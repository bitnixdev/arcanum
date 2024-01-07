use age::armor::{ArmoredReader, Format};
use age::cli_common::read_identities;
use age::{Identity, Recipient};
use clap::{Parser, Subcommand};
use edit::{edit_file, get_editor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toor::project::find_project_root;
use tracing::info;
use whoami::{hostname, username};

#[derive(clap::ValueEnum, Clone, Debug)]
#[clap(rename_all = "kebab_case")]
enum Context {
    DevShell,
    NixOs,
    HomeManager,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[clap(long, value_enum)]
    context: Context,

    #[command(subcommand)]
    command: Commands,

    #[clap(long, default_value = ".chips/arcanum.json")]
    cache_file: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        source: PathBuf,
        from: Option<PathBuf>,
    },
    Decrypt {
        source: PathBuf,
        to: Option<PathBuf>,
    },
    Edit {
        source: PathBuf,
    },
    Rekey {
        source: Option<PathBuf>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
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
struct CacheFile {
    dev_shells: HashMap<String, HashMap<String, HashMap<String, ArcanumFile>>>,
    // flakes: HashMap<String, ArcanumFile>,
    // home_manager: HashMap<String, HashMap<String, HashMap<String, ArcanumFile>>>,
    // nixos: HashMap<String, HashMap<String, HashMap<String, ArcanumFile>>>,
    // nixos_admin_recipients: Vec<String>,
}

fn main() {
    tracing_subscriber::fmt::init();

    let cwd = std::env::current_dir().unwrap();
    let project_root = find_project_root(cwd);
    if project_root.is_none() {
        panic!("Could not find project root, are you in a project?");
    }
    let project_root = project_root.unwrap();

    info!("project_root: {:?}", project_root);

    let cli = Cli::parse();

    let file = Path::new(&cli.cache_file);
    if !file.exists() {
        panic!("Cache file does not exist: {:?}", file);
    }
    let data = std::fs::read_to_string(file).unwrap();
    let cache: CacheFile = serde_json::from_str(&data).unwrap();

    let files = match &cli.context {
        Context::DevShell => dev_shell_files(cache),
        Context::HomeManager => dev_shell_files(cache),
        Context::NixOs => dev_shell_files(cache),
    };
    let files = files.unwrap();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::Encrypt { source, from } => {
            let (_, matching_config) = files
                .iter()
                .find(|(_, file)| *source == file.source)
                .unwrap();
            let plaintext = match from {
                Some(from) => {
                    if from.display().to_string() == "-" {
                        info!("reading from stdin");
                        let mut buffer = String::new();
                        std::io::stdin().read_to_string(&mut buffer).unwrap();
                        buffer.into_bytes()
                    } else if from.exists() {
                        std::fs::read(from).unwrap()
                    } else {
                        info!("from does not exist: {:?}", from);
                        vec![]
                    }
                }
                None => {
                    let dest = &matching_config.dest;
                    if dest.exists() {
                        std::fs::read(dest).unwrap()
                    } else {
                        info!("dest does not exist: {:?}", dest);
                        vec![]
                    }
                }
            };
            let recipients = recipients_for_file(matching_config);
            let encrypted = ciphertext_from_plaintext_buffer(&plaintext, recipients);
            std::fs::write(source, encrypted).unwrap();
        }
        Commands::Decrypt { source, to } => {
            let dest = match to {
                Some(to) => to,
                None => {
                    let (_, matching_config) = files
                        .iter()
                        .find(|(_, file)| *source == file.source)
                        .unwrap();
                    &matching_config.dest
                }
            };
            let plaintext = plaintext_from_ciphertext_source(source);
            if plaintext.is_empty() {
                info!("plaintext is empty, not writing to {:?}", dest);
                return;
            }
            std::fs::write(dest, plaintext).unwrap();
            info!("Wrote plaintext to {:?}", dest);
        }
        Commands::Rekey { source } => {
            info!("'Rekey' was used, source is: {:?}", source);
            let target_files = match source {
                Some(source) => {
                    let (_, matching_config) = files
                        .iter()
                        .find(|(_, file)| *source == file.source)
                        .unwrap();
                    vec![matching_config]
                }
                None => files.values().collect(),
            };
            for matching_config in target_files {
                let plaintext = plaintext_from_ciphertext_source(&matching_config.source);
                let recipients = recipients_for_file(matching_config);
                let encrypted = ciphertext_from_plaintext_buffer(&plaintext, recipients);
                std::fs::write(&matching_config.source, encrypted).unwrap();
                info!("Rekeyed ciphertext at {:?}", matching_config.source);
            }
        }
        Commands::Edit { source } => {
            let (_, matching_config) = files
                .iter()
                .find(|(_, file)| *source == file.source)
                .unwrap();
            let contents = plaintext_from_ciphertext_source(source);
            let t = temp_file::with_contents(&contents);
            info!(
                "Opening plaintext in editor: {}",
                get_editor().unwrap().display()
            );
            edit_file(&t.path()).unwrap();
            let plaintext = std::fs::read(t.path()).unwrap();
            if plaintext.is_empty() {
                info!("edited plaintext is empty, not writing to {:?}", source);
                return;
            }
            if plaintext == contents {
                info!("edited plaintext is unchanged, not writing to {:?}", source);
                info!(
                    "If you want to re-encrypt the files to new recipents, use the 'rekey' command"
                );
                return;
            }
            let recipients = recipients_for_file(matching_config);

            let encrypted = ciphertext_from_plaintext_buffer(&plaintext, recipients);
            std::fs::write(source, encrypted).unwrap();
            info!("Wrote ciphertext to {:?}", source);
        }
    }
}

fn recipients_for_file(matching_config: &ArcanumFile) -> Vec<Box<dyn Recipient + Send>> {
    let mut recipients: Vec<Box<dyn Recipient + Send>> = vec![];
    for r in &matching_config.recipients {
        if r.starts_with("age1") {
            recipients.push(Box::new(age::x25519::Recipient::from_str(r).unwrap()))
        } else {
            recipients.push(Box::new(age::ssh::Recipient::from_str(r).unwrap()))
        }
    }
    recipients
}

fn plaintext_from_ciphertext_source(source: &PathBuf) -> Vec<u8> {
    let contents = if source.exists() {
        let encrypted = std::fs::read(source).unwrap();
        let armor_reader = ArmoredReader::new(&encrypted[..]);
        let decryptor = match age::Decryptor::new(armor_reader).unwrap() {
            age::Decryptor::Recipients(d) => d,
            _ => unreachable!(),
        };

        let mut decrypted = vec![];
        let home_directory = dirs::home_dir().unwrap();
        let identity = read_identities(
            vec![
                // TODO: check if these files exist before adding them
                home_directory.join(".ssh/id_ed25519").display().to_string(),
                // home_directory.join(".ssh/id_rsa").display().to_string(),
            ],
            Some(30),
        )
        .unwrap();
        let identity_refs: Vec<&dyn Identity> = identity.iter().map(|i| i.as_ref()).collect();
        let mut reader = decryptor.decrypt(identity_refs.into_iter()).unwrap();
        reader.read_to_end(&mut decrypted).unwrap();

        decrypted
    } else {
        info!("source does not exist: {:?}", source);
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

fn nixos_arch_platform() -> String {
    let arch = std::env::consts::ARCH;
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        platform => platform,
    };
    format!("{}-{}", arch, platform)
}

fn dev_shell_files(mut cache_file: CacheFile) -> Option<HashMap<String, ArcanumFile>> {
    let system_config = cache_file.dev_shells.remove(&nixos_arch_platform());
    match system_config {
        Some(mut system_config) => {
            let user_host = format!("{}-{}", username(), hostname());
            let user_host_config = system_config.remove(&user_host);
            match user_host_config {
                Some(user_host_config) => Some(user_host_config),
                None => system_config.remove("default"),
            }
        }
        None => None,
    }
}
