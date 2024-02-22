use age::armor::{ArmoredReader, Format};
use age::cli_common::read_identities;
use age::{Identity, Recipient};
use clap::{Parser, Subcommand};
use digest::Digest;
use dirs::cache_dir;
use edit::{edit_file, get_editor};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use toor::project::find_project_root;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[clap(long)]
    identity: Vec<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        plaintext: PathBuf,
        ciphertext: PathBuf,
    },

    /// Decrypt a file
    Decrypt {
        ciphertext: PathBuf,
        plaintext: PathBuf,
    },

    /// Edit the plaintext of a file
    Edit { ciphertext: PathBuf },

    /// Re-encrypt a file to all configured recipients
    Rekey { ciphertext: PathBuf },

    /// Regenerate a cache file for the current project
    ///
    /// Needed when adding new files to the project or changing the recipients.
    Cache,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArcanumFile {
    dest: PathBuf,
    source: PathBuf,
    directory_permissions: String,
    make_directory: bool,
    group: String,
    owner: String,
    permissions: String,
    recipients: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArcanumConfig {
    files: HashMap<String, ArcanumFile>,
    admin_recipients: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CacheFile {
    nixos: Option<HashMap<String, ArcanumConfig>>,
    dev_shells: Option<HashMap<String, HashMap<String, ArcanumConfig>>>,
    home_manager: Option<HashMap<String, HashMap<String, ArcanumConfig>>>,
    flake: Option<ArcanumConfig>,
}

impl CacheFile {
    fn recipients_for_file(&self, source: &Path) -> Vec<Box<dyn Recipient + Send>> {
        let mut recipients: BTreeSet<String> = BTreeSet::new();
        let flake = self.flake.as_ref().unwrap();
        for (_, file) in &flake.files {
            if source == file.source {
                recipients.extend(file.recipients.clone());
                recipients.extend(flake.admin_recipients.clone());
            }
        }

        for (_, config) in self.nixos.as_ref().unwrap() {
            for (_, file) in &config.files {
                if source == file.source {
                    recipients.extend(file.recipients.clone());
                    recipients.extend(config.admin_recipients.clone());
                }
            }
        }

        for (_, config) in self.home_manager.as_ref().unwrap() {
            for (_, system) in config {
                for (_, file) in &system.files {
                    if source == file.source {
                        recipients.extend(file.recipients.clone());
                        recipients.extend(system.admin_recipients.clone());
                    }
                }
            }
        }

        for (_, config) in self.dev_shells.as_ref().unwrap() {
            for (_, system) in config {
                for (_, file) in &system.files {
                    if source == file.source {
                        recipients.extend(file.recipients.clone());
                        recipients.extend(system.admin_recipients.clone());
                    }
                }
            }
        }

        if !recipients.is_empty() {
            eprintln!("Recipients for {}:", source.display());
            for recipient in &recipients {
                eprintln!(" - {}", recipient);
            }
        }

        let mut boxed_recipients: Vec<Box<dyn Recipient + Send>> = vec![];
        for r in &recipients {
            if r.starts_with("age1") {
                boxed_recipients.push(Box::new(age::x25519::Recipient::from_str(r).unwrap()))
            } else {
                boxed_recipients.push(Box::new(age::ssh::Recipient::from_str(r).unwrap()))
            }
        }
        boxed_recipients
    }
}

fn main() {
    let cwd = std::env::current_dir().unwrap();
    let project_root = find_project_root(cwd);
    if project_root.is_none() {
        panic!("Could not find project root, are you in a project?");
    }
    let project_root = project_root.unwrap();

    let cli = Cli::parse();

    let cache_file_path = cache_file_path(&project_root);
    eprintln!("Using cache file at {:?}", cache_file_path);
    let cache: CacheFile = load_cache_file(&project_root, &cache_file_path);

    let identities = identity_files(&cli);

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::Encrypt {
            plaintext,
            ciphertext,
        } => {
            let data = if plaintext.display().to_string() == "-" {
                let mut buffer = String::new();
                std::io::stdin().read_to_string(&mut buffer).unwrap();
                buffer.into_bytes()
            } else if plaintext.exists() {
                std::fs::read(plaintext).unwrap()
            } else {
                eprintln!("plaintext does not exist at {:?}, aborting", plaintext);
                return;
            };
            let recipients = cache.recipients_for_file(ciphertext);
            if recipients.is_empty() {
                eprintln!("No recipients found for {:?}", ciphertext);
                return;
            }
            let ciphertext_data = ciphertext_from_plaintext_buffer(&data, recipients);
            std::fs::write(ciphertext, ciphertext_data).unwrap();
            eprintln!("Wrote ciphertext to {:?}", ciphertext);
        }
        Commands::Decrypt {
            ciphertext,
            plaintext,
        } => {
            if plaintext.display().to_string() == "-" {
                let plaintext_data = plaintext_from_ciphertext_source(ciphertext, identities);
                std::io::stdout().write_all(&plaintext_data).unwrap();
            } else {
                let plaintext_data = plaintext_from_ciphertext_source(ciphertext, identities);
                if plaintext_data.is_empty() {
                    eprintln!("plaintext is empty, not writing to {:?}", plaintext);
                    return;
                }
                std::fs::write(plaintext, plaintext_data).unwrap();
                eprintln!("Wrote plaintext to {:?}", plaintext);
            }
        }
        Commands::Rekey { ciphertext } => {
            let plaintext_data = plaintext_from_ciphertext_source(ciphertext, identities);
            let recipients = cache.recipients_for_file(ciphertext);
            let ciphertext_data = ciphertext_from_plaintext_buffer(&plaintext_data, recipients);
            std::fs::write(ciphertext, ciphertext_data).unwrap();
            eprintln!("Rekeyed ciphertext at {:?}", ciphertext);
        }
        Commands::Edit { ciphertext } => {
            let recipients = cache.recipients_for_file(ciphertext);
            if recipients.is_empty() {
                eprintln!("No recipients found, unable to edit.");
                std::process::exit(1);
            }

            let original_plaintext_data = plaintext_from_ciphertext_source(ciphertext, identities.clone());
            let file_stem = PathBuf::from(ciphertext.file_stem().unwrap());
            let extension = file_stem.extension().unwrap().to_str().unwrap();
            let t = temp_file::TempFile::with_suffix(format!(".{}", extension)).unwrap();
            std::fs::write(t.path(), &original_plaintext_data).unwrap();
            eprintln!(
                "Opening plaintext in editor: {}",
                get_editor().unwrap().display()
            );
            edit_file(&t.path()).unwrap();
            let plaintext_data = std::fs::read(t.path()).unwrap();
            if plaintext_data.is_empty() {
                eprintln!("edited plaintext is empty, not writing to {:?}", ciphertext);
                return;
            }
            if plaintext_data == original_plaintext_data {
                eprintln!("Plaintext is unchanged, not writing to {:?}", ciphertext);
                eprintln!(
                    "If you want to re-encrypt the files to new recipents, use the 'rekey' command."
                );
                return;
            }
            let ciphertext_data = ciphertext_from_plaintext_buffer(&plaintext_data, recipients);
            let ciphertext_temp = temp_file::with_contents(&ciphertext_data);

            // Verify we can decrypt the new ciphertext
            plaintext_from_ciphertext_source(ciphertext_temp.path(), identities);

            std::fs::write(ciphertext, ciphertext_data).unwrap();
            eprintln!("Wrote ciphertext to {:?}", ciphertext);
        }
        Commands::Cache => {
            generate_cache_file(&project_root, &cache_file_path);
        }
    }
}

fn cache_file_path(project_root: &Path) -> PathBuf {
    let mut hasher = Sha3_256::new();
    hasher.update(project_root.to_string_lossy().as_bytes());
    let hash = hasher.finalize();
    let hash = format!("{:x}", hash)[..8].to_string();
    let cache_file_name = format!("arcanum-{}.json", hash);
    let dir = cache_dir().unwrap();
    if !dir.exists() {
        std::fs::create_dir_all(&dir).unwrap();
    }
    let cache_path = dir.join(cache_file_name);
    cache_path
}

fn identity_files(cli: &Cli) -> Vec<String> {
    let mut identities = vec![];
    for identity in &cli.identity {
        if identity.exists() {
            identities.push(identity.clone().display().to_string());
        }
    }
    let default_identities = vec![
        dirs::home_dir().unwrap().join(".ssh/id_ed25519"),
        dirs::home_dir().unwrap().join(".ssh/id_rsa"),
    ];
    for identity in default_identities {
        if identity.exists() {
            identities.push(identity.display().to_string());
        }
    }
    identities
}

fn load_cache_file(project_root: &Path, cache: &Path) -> CacheFile {
    if cache.exists() {
        let data = std::fs::read_to_string(cache).unwrap();
        let cache_file: CacheFile = serde_json::from_str(&data).unwrap();
        cache_file
    } else {
        generate_cache_file(project_root, cache)
    }
}

fn generate_cache_file(project_root: &Path, cache: &Path) -> CacheFile {
    let result = Command::new("nix")
        .arg("eval")
        .arg("--json")
        .arg(".#lib.arcanum")
        .current_dir(project_root)
        .output()
        .unwrap();
    if !result.status.success() {
        eprintln!("nix eval failed");
        eprintln!("stdout: {}", String::from_utf8_lossy(&result.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&result.stderr));
        std::process::exit(1);
    }
    let data = String::from_utf8(result.stdout).unwrap();
    let cache_file: CacheFile = serde_json::from_str(&data).unwrap();
    std::fs::write(cache, data).unwrap();

    cache_file
}

fn plaintext_from_ciphertext_source(source: &Path, identities: Vec<String>) -> Vec<u8> {
    let contents = if source.exists() {
        let encrypted = std::fs::read(source).unwrap();
        let armor_reader = ArmoredReader::new(&encrypted[..]);
        let decryptor = match age::Decryptor::new(armor_reader).unwrap() {
            age::Decryptor::Recipients(d) => d,
            _ => unreachable!(),
        };

        let mut decrypted = vec![];
        let identity = read_identities(identities, Some(30)).unwrap();
        let identity_refs: Vec<&dyn Identity> = identity.iter().map(|i| i.as_ref()).collect();
        let reader = decryptor.decrypt(identity_refs.into_iter());
        if reader.is_err() {
            eprintln!("You do not have an identity able to decrypt this file. Exiting.");
            std::process::exit(1);
        }
        let mut reader = reader.unwrap();
        reader.read_to_end(&mut decrypted).unwrap();

        decrypted
    } else {
        eprintln!("ciphertext does not exist: {:?}", source);
        vec![]
    };
    contents
}

fn ciphertext_from_plaintext_buffer(
    plaintext: &[u8],
    recipients: Vec<Box<dyn Recipient + Send>>,
) -> Vec<u8> {
    let encryptor = age::Encryptor::with_recipients(recipients).unwrap();
    let mut encrypted = vec![];
    let mut armored_writer =
        age::armor::ArmoredWriter::wrap_output(&mut encrypted, Format::AsciiArmor).unwrap();
    let mut writer = encryptor.wrap_output(&mut armored_writer).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    armored_writer.finish().unwrap();
    encrypted
}
