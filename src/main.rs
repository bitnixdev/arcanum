use age::armor::{ArmoredReader, Format};
use age::cli_common::{StdinGuard, read_identities};
use age::{Identity, Recipient};
use clap::{Parser, Subcommand, ValueEnum};
use dirs::cache_dir;
use edit::{edit_file, get_editor};
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::Instant;
use toor::config::Config;
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

    /// Decrypt a file to stdout for textconv (no cache lookup)
    Textconv { ciphertext: PathBuf },

    /// Edit the plaintext of a file
    Edit { ciphertext: PathBuf },

    /// Re-encrypt a file to all configured recipients, or all files if none specified
    Rekey { ciphertext: Option<PathBuf> },

    /// Resolve merge conflicts in an encrypted file
    Merge { ciphertext: PathBuf },

    /// Show plaintext diffs for changed encrypted files
    Diff {
        /// Version-control backend to query
        #[arg(long, value_enum, default_value = "auto")]
        vcs: VcsArg,

        /// Compare current files with this jj revset or git ref
        #[arg(long, value_name = "REV")]
        from: Option<String>,

        /// Encrypted files or directories to include
        #[arg(value_name = "FILE")]
        files: Vec<PathBuf>,
    },

    /// List configured files and their recipients
    List,

    /// Regenerate a cache file for the current project
    ///
    /// Needed when adding new files to the project or changing the recipients.
    Cache,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum VcsArg {
    Auto,
    Jj,
    Git,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Vcs {
    Jj,
    Git,
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

#[derive(Debug, Deserialize)]
struct EditFile {
    dest: PathBuf,
    source: PathBuf,
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
    darwin: Option<HashMap<String, ArcanumConfig>>,
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

        if let Some(darwin_configs) = &self.darwin {
            for (_, config) in darwin_configs {
                for (_, file) in &config.files {
                    if source == file.source {
                        recipients.extend(file.recipients.clone());
                        recipients.extend(config.admin_recipients.clone());
                    }
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

fn update_edited_plaintext(
    project_root: &Path,
    ciphertext: &Path,
    plaintext: &[u8],
) -> Result<Vec<PathBuf>, String> {
    let Some(files) = std::env::var_os("ARCANUM_EDIT_FILES") else {
        return Ok(Vec::new());
    };
    let files: Vec<EditFile> = serde_json::from_slice(files.as_encoded_bytes())
        .map_err(|e| format!("Invalid ARCANUM_EDIT_FILES: {}", e))?;
    update_edited_plaintext_files(project_root, ciphertext, plaintext, files)
}

fn update_edited_plaintext_files(
    project_root: &Path,
    ciphertext: &Path,
    plaintext: &[u8],
    files: Vec<EditFile>,
) -> Result<Vec<PathBuf>, String> {
    let ciphertext = absolute_path(project_root, ciphertext);
    let mut updated = Vec::new();

    for file in files {
        if absolute_path(project_root, &file.source) != ciphertext {
            continue;
        }
        if let Some(parent) = file.dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {:?}: {}", parent, e))?;
        }
        std::fs::write(&file.dest, plaintext)
            .map_err(|e| format!("Failed to update {:?}: {}", file.dest, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file.dest, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Failed to restrict {:?}: {}", file.dest, e))?;
        }
        updated.push(file.dest);
    }

    updated.sort();
    updated.dedup();
    Ok(updated)
}

fn absolute_path(project_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        project_root.join(path)
    }
}

/// Best-effort removal of plaintext temp files when arcanum is killed while an
/// editor still has one open. `Drop` covers the normal path; this covers the
/// signals a terminal or a supervisor can send us.
#[cfg(unix)]
mod signal_cleanup {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;
    use std::sync::Once;
    use std::sync::atomic::{AtomicPtr, Ordering};

    /// More slots than any one command needs; merge uses the most, at three.
    const SLOTS: usize = 8;

    /// Paths are kept as leaked C strings so the handler only has to call
    /// `unlink(2)`, which is async-signal-safe. The strings are never freed:
    /// reclaiming one could race a handler that already read the pointer.
    static PATHS: [AtomicPtr<libc::c_char>; SLOTS] =
        [const { AtomicPtr::new(ptr::null_mut()) }; SLOTS];

    static INSTALL: Once = Once::new();

    const CAUGHT: [libc::c_int; 4] = [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM];

    extern "C" fn handler(sig: libc::c_int) {
        for slot in &PATHS {
            let path = slot.swap(ptr::null_mut(), Ordering::AcqRel);
            if !path.is_null() {
                unsafe { libc::unlink(path) };
            }
        }
        // Die the way we were asked to, so the exit status is not a lie.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }

    fn install() {
        INSTALL.call_once(|| {
            let handler = handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
            for sig in CAUGHT {
                unsafe { libc::signal(sig, handler) };
            }
        });
    }

    /// Registers `path` for removal on signal, returning the slot it claimed.
    pub fn register(path: &Path) -> Option<usize> {
        install();
        let raw = CString::new(path.as_os_str().as_bytes()).ok()?.into_raw();
        for (index, slot) in PATHS.iter().enumerate() {
            if slot
                .compare_exchange(ptr::null_mut(), raw, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(index);
            }
        }
        // Out of slots. The file is still removed on drop.
        unsafe { drop(CString::from_raw(raw)) };
        None
    }

    /// Releases a slot after the file is gone, so a later signal cannot unlink
    /// a path that something else has since reused.
    pub fn unregister(slot: usize) {
        PATHS[slot].store(ptr::null_mut(), Ordering::Release);
    }
}

/// A temp file holding decrypted plaintext, named after the encrypted file with
/// its `.age` suffix stripped so editors pick the right syntax mode:
/// `secrets/github-actions.toml.age` becomes `github-actions.<id>.toml`.
///
/// The file is removed on drop and, on unix, when arcanum is killed by a
/// catchable signal while the editor is still running.
struct PlaintextTempFile {
    file: temp_file::TempFile,
    #[cfg(unix)]
    slot: Option<usize>,
}

impl PlaintextTempFile {
    /// `label` is inserted before the random id, e.g. `Some("ours")` yields
    /// `github-actions.ours.<id>.toml`.
    fn new(ciphertext: &Path, label: Option<&str>) -> Result<Self, String> {
        let (stem, extension) = plaintext_name_parts(ciphertext);
        let prefix = match label {
            Some(label) => format!("{}.{}.", stem, label),
            None => format!("{}.", stem),
        };
        let file = temp_file::TempFileBuilder::new()
            .prefix(prefix)
            .suffix(format!(".{}", extension))
            .build()
            .map_err(|e| format!("Failed to create temp file: {}", e))?;

        // Created empty, so this lands before any plaintext is written.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Failed to restrict {:?}: {}", file.path(), e))?;
        }

        #[cfg(unix)]
        let slot = signal_cleanup::register(file.path());

        Ok(Self {
            file,
            #[cfg(unix)]
            slot,
        })
    }

    fn path(&self) -> &Path {
        self.file.path()
    }
}

impl Drop for PlaintextTempFile {
    fn drop(&mut self) {
        // Remove before releasing the slot, so a signal arriving in between
        // still finds a live registration. `temp_file`'s own drop then no-ops.
        let _ = std::fs::remove_file(self.file.path());
        #[cfg(unix)]
        if let Some(slot) = self.slot {
            signal_cleanup::unregister(slot);
        }
    }
}

/// Splits an encrypted path into the stem and extension to use for its
/// plaintext temp file: `github-actions.toml.age` -> `("github-actions", "toml")`.
fn plaintext_name_parts(ciphertext: &Path) -> (String, String) {
    let inner = if ciphertext.extension().is_some_and(|ext| ext == "age") {
        ciphertext.file_stem()
    } else {
        ciphertext.file_name()
    };
    let inner = Path::new(inner.unwrap_or_else(|| std::ffi::OsStr::new("")));

    let stem = inner
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("arcanum");
    let extension = inner
        .extension()
        .and_then(|ext| ext.to_str())
        .filter(|ext| !ext.is_empty())
        .unwrap_or("txt");

    (stem.to_string(), extension.to_string())
}

fn main() {
    env_logger::init();
    let cwd = std::env::current_dir().unwrap();
    let config = Config { root_pattern: None };
    let project_root = find_project_root(cwd.clone(), config);
    if project_root.is_none() {
        panic!("Could not find project root, are you in a project?");
    }
    let project_root = project_root.unwrap();

    let cli = Cli::parse();

    let identities = identity_files(&cli);

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::Encrypt {
            plaintext,
            ciphertext,
        } => {
            let cache: CacheFile = load_cache_file(&project_root);
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
            if let Some(parent) = ciphertext.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
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
        Commands::Textconv { ciphertext } => {
            let plaintext_data = plaintext_from_ciphertext_source(ciphertext, identities);
            std::io::stdout().write_all(&plaintext_data).unwrap();
        }
        Commands::Rekey { ciphertext } => {
            let cache: CacheFile = load_cache_file(&project_root);
            if let Some(ciphertext_path) = ciphertext {
                // Rekey single file
                let plaintext_data = plaintext_from_ciphertext_source(ciphertext_path, identities);
                let recipients = cache.recipients_for_file(ciphertext_path);
                let ciphertext_data = ciphertext_from_plaintext_buffer(&plaintext_data, recipients);
                std::fs::write(ciphertext_path, ciphertext_data).unwrap();
                eprintln!("Rekeyed ciphertext at {:?}", ciphertext_path);
            } else {
                // Rekey all files
                let mut files_to_rekey = Vec::new();

                // Collect all files from flake config
                if let Some(flake_config) = &cache.flake {
                    for (_, file) in &flake_config.files {
                        if file.source.exists() {
                            files_to_rekey.push(file.source.clone());
                        }
                    }
                }

                // Collect all files from nixos configs
                if let Some(nixos_configs) = &cache.nixos {
                    for (_, config) in nixos_configs {
                        for (_, file) in &config.files {
                            if file.source.exists() {
                                files_to_rekey.push(file.source.clone());
                            }
                        }
                    }
                }

                // Collect all files from darwin configs
                if let Some(darwin_configs) = &cache.darwin {
                    for (_, config) in darwin_configs {
                        for (_, file) in &config.files {
                            if file.source.exists() {
                                files_to_rekey.push(file.source.clone());
                            }
                        }
                    }
                }

                // Collect all files from home_manager configs
                if let Some(home_manager_configs) = &cache.home_manager {
                    for (_, config) in home_manager_configs {
                        for (_, system) in config {
                            for (_, file) in &system.files {
                                if file.source.exists() {
                                    files_to_rekey.push(file.source.clone());
                                }
                            }
                        }
                    }
                }

                // Collect all files from dev_shells configs
                if let Some(dev_shells_configs) = &cache.dev_shells {
                    for (_, config) in dev_shells_configs {
                        for (_, system) in config {
                            for (_, file) in &system.files {
                                if file.source.exists() {
                                    files_to_rekey.push(file.source.clone());
                                }
                            }
                        }
                    }
                }

                // Remove duplicates and sort
                files_to_rekey.sort();
                files_to_rekey.dedup();

                if files_to_rekey.is_empty() {
                    eprintln!("No files found to rekey");
                    return;
                }

                eprintln!("Rekeying {} files...", files_to_rekey.len());

                for file_path in files_to_rekey {
                    eprintln!("Rekeying {:?}", file_path);
                    let plaintext_data =
                        plaintext_from_ciphertext_source(&file_path, identities.clone());
                    let recipients = cache.recipients_for_file(&file_path);
                    if recipients.is_empty() {
                        eprintln!("No recipients found for {:?}, skipping", file_path);
                        continue;
                    }
                    let ciphertext_data =
                        ciphertext_from_plaintext_buffer(&plaintext_data, recipients);
                    std::fs::write(&file_path, ciphertext_data).unwrap();
                    eprintln!("Rekeyed ciphertext at {:?}", file_path);
                }
            }
        }
        Commands::Edit { ciphertext } => {
            let cache: CacheFile = load_cache_file(&project_root);
            let recipients = cache.recipients_for_file(ciphertext);
            if recipients.is_empty() {
                eprintln!("No recipients found, unable to edit.");
                std::process::exit(1);
            }

            let ciphertext_path = absolute_path(&project_root, ciphertext);
            let original_plaintext_data =
                plaintext_from_ciphertext_source(&ciphertext_path, identities.clone());
            let t = match PlaintextTempFile::new(&ciphertext_path, None) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            };
            std::fs::write(t.path(), &original_plaintext_data).unwrap();
            eprintln!(
                "Opening plaintext in editor: {}",
                get_editor().unwrap().display()
            );
            edit_file(&t.path()).unwrap();
            let plaintext_data = std::fs::read(t.path()).unwrap();
            if plaintext_data.is_empty() {
                eprintln!(
                    "edited plaintext is empty, not writing to {:?}",
                    ciphertext_path
                );
                return;
            }
            if plaintext_data == original_plaintext_data {
                eprintln!(
                    "Plaintext is unchanged, not writing to {:?}",
                    ciphertext_path
                );
                eprintln!(
                    "If you want to re-encrypt the files to new recipents, use the 'rekey' command."
                );
                return;
            }
            let ciphertext_data = ciphertext_from_plaintext_buffer(&plaintext_data, recipients);
            let ciphertext_temp = temp_file::with_contents(&ciphertext_data);

            // Verify we can decrypt the new ciphertext
            plaintext_from_ciphertext_source(ciphertext_temp.path(), identities);

            if let Some(parent) = ciphertext_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&ciphertext_path, ciphertext_data).unwrap();
            eprintln!("Wrote ciphertext to {:?}", ciphertext_path);
            match update_edited_plaintext(&project_root, &ciphertext_path, &plaintext_data) {
                Ok(destinations) => {
                    for destination in destinations {
                        eprintln!("Updated decrypted file at {:?}", destination);
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Merge { ciphertext } => {
            let cache: CacheFile = load_cache_file(&project_root);
            let recipients = cache.recipients_for_file(ciphertext);
            if recipients.is_empty() {
                eprintln!("No recipients found for {:?}", ciphertext);
                return;
            }

            // Check if file has merge conflicts
            let file_content = match std::fs::read_to_string(ciphertext) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("Failed to read file {:?}: {}", ciphertext, e);
                    return;
                }
            };

            if !file_content.contains("<<<<<<< ") || !file_content.contains(">>>>>>> ") {
                eprintln!(
                    "File {:?} does not appear to have merge conflicts",
                    ciphertext
                );
                return;
            }

            eprintln!("Resolving merge conflicts in {:?}", ciphertext);

            // Extract the conflicting versions using git show
            let relative_path = if ciphertext.is_absolute() {
                match ciphertext.strip_prefix(&project_root) {
                    Ok(path) => path,
                    Err(_) => {
                        eprintln!(
                            "File {:?} is not within project root {:?}",
                            ciphertext, project_root
                        );
                        return;
                    }
                }
            } else {
                // Already a relative path
                ciphertext.as_path()
            };

            // Check if we're in the middle of a merge or rebase
            let merge_head_exists = project_root.join(".git/MERGE_HEAD").exists();
            let rebase_apply_exists = project_root.join(".git/rebase-apply").exists();
            let rebase_merge_exists = project_root.join(".git/rebase-merge").exists();

            let in_merge = merge_head_exists;
            let in_rebase = rebase_apply_exists || rebase_merge_exists;

            if !in_merge && !in_rebase {
                eprintln!("Not currently in a merge or rebase state.");
                eprintln!("This command should be run during an active merge or rebase conflict.");
                return;
            }

            let conflict_type = if in_merge { "merge" } else { "rebase" };
            eprintln!("Detected {} conflict", conflict_type);

            // Get the conflicting versions based on conflict type
            let (ours_output, theirs_output) = if in_merge {
                // For merge conflicts
                let ours = Command::new("git")
                    .current_dir(&project_root)
                    .args(&["show", &format!("HEAD:{}", relative_path.display())])
                    .output();
                let theirs = Command::new("git")
                    .current_dir(&project_root)
                    .args(&["show", &format!("MERGE_HEAD:{}", relative_path.display())])
                    .output();
                (ours, theirs)
            } else {
                // For rebase conflicts - use git index stages
                let ours = Command::new("git")
                    .current_dir(&project_root)
                    .args(&["show", &format!(":2:{}", relative_path.display())])
                    .output();
                let theirs = Command::new("git")
                    .current_dir(&project_root)
                    .args(&["show", &format!(":3:{}", relative_path.display())])
                    .output();
                (ours, theirs)
            };

            // Also try alternative approaches if the above fail
            let ours_alt_output = if ours_output.as_ref().map_or(true, |o| !o.status.success()) {
                if in_merge {
                    Some(
                        Command::new("git")
                            .current_dir(&project_root)
                            .args(&["show", &format!("HEAD~1:{}", relative_path.display())])
                            .output(),
                    )
                } else {
                    // For rebase, try getting the base version
                    Some(
                        Command::new("git")
                            .current_dir(&project_root)
                            .args(&["show", &format!("HEAD:{}", relative_path.display())])
                            .output(),
                    )
                }
            } else {
                None
            };

            let theirs_alt_output = if theirs_output.as_ref().map_or(true, |o| !o.status.success())
            {
                if in_merge {
                    // Try getting from the merge commit's second parent
                    Some(
                        Command::new("git")
                            .current_dir(&project_root)
                            .args(&[
                                "show",
                                &format!("$(cat .git/MERGE_HEAD):{}", relative_path.display()),
                            ])
                            .output(),
                    )
                } else {
                    // For rebase, try getting from the original commit being applied
                    let orig_commit_path = if rebase_apply_exists {
                        project_root.join(".git/rebase-apply/original-commit")
                    } else {
                        project_root.join(".git/rebase-merge/stopped-sha")
                    };

                    if orig_commit_path.exists() {
                        if let Ok(commit_hash) = std::fs::read_to_string(&orig_commit_path) {
                            let commit_hash = commit_hash.trim();
                            Some(
                                Command::new("git")
                                    .current_dir(&project_root)
                                    .args(&[
                                        "show",
                                        &format!("{}:{}", commit_hash, relative_path.display()),
                                    ])
                                    .output(),
                            )
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            } else {
                None
            };

            // Try to get clean versions, with fallbacks
            let ours_ciphertext = match ours_output {
                Ok(output) if output.status.success() => {
                    eprintln!("Successfully extracted ours version using git show");
                    output.stdout
                }
                _ => {
                    if let Some(Ok(alt_output)) = ours_alt_output {
                        if alt_output.status.success() {
                            eprintln!(
                                "Successfully extracted ours version using alternative method"
                            );
                            alt_output.stdout
                        } else {
                            eprintln!("Failed to extract ours version:");
                            if let Ok(ours) = ours_output {
                                let ref_name = if in_merge { "HEAD" } else { ":2" };
                                eprintln!(
                                    "  git show {}:{} failed: {}",
                                    ref_name,
                                    relative_path.display(),
                                    ours.status
                                );
                                eprintln!("  stderr: {}", String::from_utf8_lossy(&ours.stderr));
                            }
                            eprintln!("  Alternative method also failed: {}", alt_output.status);
                            eprintln!("  stderr: {}", String::from_utf8_lossy(&alt_output.stderr));
                            return;
                        }
                    } else {
                        eprintln!("Failed to extract ours version and no alternative available");
                        return;
                    }
                }
            };

            let theirs_ciphertext = match theirs_output {
                Ok(output) if output.status.success() => {
                    eprintln!("Successfully extracted theirs version using git show");
                    output.stdout
                }
                _ => {
                    if let Some(Ok(alt_output)) = theirs_alt_output {
                        if alt_output.status.success() {
                            eprintln!(
                                "Successfully extracted theirs version using alternative method"
                            );
                            alt_output.stdout
                        } else {
                            eprintln!("Failed to extract theirs version:");
                            if let Ok(theirs) = theirs_output {
                                let ref_name = if in_merge { "MERGE_HEAD" } else { ":3" };
                                eprintln!(
                                    "  git show {}:{} failed: {}",
                                    ref_name,
                                    relative_path.display(),
                                    theirs.status
                                );
                                eprintln!("  stderr: {}", String::from_utf8_lossy(&theirs.stderr));
                            }
                            eprintln!("  Alternative method also failed: {}", alt_output.status);
                            eprintln!("  stderr: {}", String::from_utf8_lossy(&alt_output.stderr));
                            return;
                        }
                    } else {
                        eprintln!("Failed to extract theirs version and no alternative available");
                        return;
                    }
                }
            };

            // Create temporary files for the conflicting versions
            let ours_temp = temp_file::empty();
            let theirs_temp = temp_file::empty();

            if let Err(e) = std::fs::write(ours_temp.path(), &ours_ciphertext) {
                eprintln!("Failed to write ours temp file: {}", e);
                return;
            }

            if let Err(e) = std::fs::write(theirs_temp.path(), &theirs_ciphertext) {
                eprintln!("Failed to write theirs temp file: {}", e);
                return;
            }

            eprintln!("Decrypting both versions...");
            eprintln!("Ours version size: {} bytes", ours_ciphertext.len());
            eprintln!("Theirs version size: {} bytes", theirs_ciphertext.len());

            // Decrypt both versions
            let ours_plaintext =
                plaintext_from_ciphertext_source(ours_temp.path(), identities.clone());
            let theirs_plaintext =
                plaintext_from_ciphertext_source(theirs_temp.path(), identities.clone());

            if ours_plaintext.is_empty() || theirs_plaintext.is_empty() {
                eprintln!("Failed to decrypt one or both conflicting versions");
                return;
            }

            // Create temporary files for the decrypted versions
            let plain_temp = |label: &str| match PlaintextTempFile::new(ciphertext, Some(label)) {
                Ok(temp) => Some(temp),
                Err(e) => {
                    eprintln!("{}", e);
                    None
                }
            };
            let (Some(ours_plain_temp), Some(theirs_plain_temp), Some(merged_temp)) = (
                plain_temp("ours"),
                plain_temp("theirs"),
                plain_temp("merged"),
            ) else {
                return;
            };

            std::fs::write(ours_plain_temp.path(), &ours_plaintext).unwrap();
            std::fs::write(theirs_plain_temp.path(), &theirs_plaintext).unwrap();

            eprintln!("Attempting automatic merge of plaintext versions...");

            // Try to merge using git merge-file
            let merge_result = Command::new("git")
                .args(&[
                    "merge-file",
                    "-p",
                    ours_plain_temp.path().to_str().unwrap(),
                    ours_plain_temp.path().to_str().unwrap(), // base - using ours as base
                    theirs_plain_temp.path().to_str().unwrap(),
                ])
                .output();

            match merge_result {
                Ok(output) if output.status.success() => {
                    // Successful automatic merge
                    eprintln!("Automatic merge successful!");
                    std::fs::write(merged_temp.path(), &output.stdout).unwrap();
                }
                _ => {
                    // Merge failed, need manual resolution
                    eprintln!("Automatic merge failed. Opening editor for manual resolution...");
                    eprintln!("Ours version: {:?}", ours_plain_temp.path());
                    eprintln!("Theirs version: {:?}", theirs_plain_temp.path());

                    // Create a file with conflict markers for manual editing
                    let mut conflict_content = String::new();
                    let ours_label = if in_merge {
                        "HEAD (ours)"
                    } else {
                        "Current (ours)"
                    };
                    let theirs_label = if in_merge {
                        "MERGE_HEAD (theirs)"
                    } else {
                        "Incoming (theirs)"
                    };

                    conflict_content.push_str(&format!("<<<<<<< {}\n", ours_label));
                    conflict_content.push_str(&String::from_utf8_lossy(&ours_plaintext));
                    if !ours_plaintext.ends_with(b"\n") {
                        conflict_content.push('\n');
                    }
                    conflict_content.push_str("=======\n");
                    conflict_content.push_str(&String::from_utf8_lossy(&theirs_plaintext));
                    if !theirs_plaintext.ends_with(b"\n") {
                        conflict_content.push('\n');
                    }
                    conflict_content.push_str(&format!(">>>>>>> {}\n", theirs_label));

                    std::fs::write(merged_temp.path(), conflict_content).unwrap();

                    eprintln!(
                        "Opening merged file in editor: {}",
                        get_editor().unwrap().display()
                    );
                    edit_file(merged_temp.path()).unwrap();
                }
            }

            let merged_plaintext = std::fs::read(merged_temp.path()).unwrap();

            if merged_plaintext.is_empty() {
                eprintln!("Merged plaintext is empty, not writing to {:?}", ciphertext);
                return;
            }

            // Check if there are still conflict markers
            let merged_content = String::from_utf8_lossy(&merged_plaintext);
            if merged_content.contains("<<<<<<< ") || merged_content.contains(">>>>>>> ") {
                eprintln!("Warning: Conflict markers still present in merged content");
                eprintln!("Please resolve all conflicts before proceeding");
                return;
            }

            // Show diff information
            eprintln!("\n=== MERGE SUMMARY ===");

            // Show diff between ours and theirs
            eprintln!("Differences between conflicting versions:");
            let diff_result = Command::new("diff")
                .args(&[
                    "-u",
                    ours_plain_temp.path().to_str().unwrap(),
                    theirs_plain_temp.path().to_str().unwrap(),
                ])
                .output();

            match diff_result {
                Ok(output) => {
                    let diff_output = String::from_utf8_lossy(&output.stdout);
                    if !diff_output.trim().is_empty() {
                        // Replace temp file paths with meaningful labels in diff output
                        let diff_labeled = diff_output
                            .replace(
                                ours_plain_temp.path().to_str().unwrap(),
                                &format!("{} (ours)", conflict_type),
                            )
                            .replace(
                                theirs_plain_temp.path().to_str().unwrap(),
                                &format!("{} (theirs)", conflict_type),
                            );
                        eprintln!("{}", diff_labeled);
                    } else {
                        eprintln!("No differences found between versions");
                    }
                }
                Err(_) => {
                    // Fallback: show simple line counts
                    let ours_lines = String::from_utf8_lossy(&ours_plaintext).lines().count();
                    let theirs_lines = String::from_utf8_lossy(&theirs_plaintext).lines().count();
                    let merged_lines = merged_content.lines().count();
                    eprintln!("Ours version: {} lines", ours_lines);
                    eprintln!("Theirs version: {} lines", theirs_lines);
                    eprintln!("Merged result: {} lines", merged_lines);
                }
            }

            // Show a summary of the final merged content
            let merged_lines = merged_content.lines().count();
            let merged_chars = merged_content.len();
            eprintln!(
                "\nFinal merged result: {} lines, {} characters",
                merged_lines, merged_chars
            );

            // Show first few lines of merged content as preview
            let preview_lines: Vec<&str> = merged_content.lines().take(5).collect();
            if !preview_lines.is_empty() {
                eprintln!(
                    "Preview of merged content (first {} lines):",
                    preview_lines.len()
                );
                for (i, line) in preview_lines.iter().enumerate() {
                    eprintln!("  {}: {}", i + 1, line);
                }
                if merged_lines > 5 {
                    eprintln!("  ... ({} more lines)", merged_lines - 5);
                }
            }
            // Show how the final result compares to each original version
            eprintln!("Changes from ours version to final result:");
            let ours_to_final_diff = Command::new("diff")
                .args(&[
                    "-u",
                    ours_plain_temp.path().to_str().unwrap(),
                    merged_temp.path().to_str().unwrap(),
                ])
                .output();

            match ours_to_final_diff {
                Ok(output) if !output.stdout.is_empty() => {
                    let diff_output = String::from_utf8_lossy(&output.stdout);
                    let diff_labeled = diff_output
                        .replace(
                            ours_plain_temp.path().to_str().unwrap(),
                            &format!("{} (ours)", conflict_type),
                        )
                        .replace(merged_temp.path().to_str().unwrap(), "final result");
                    eprintln!("{}", diff_labeled);
                }
                _ => eprintln!("No changes from ours version"),
            }

            eprintln!("Changes from theirs version to final result:");
            let theirs_to_final_diff = Command::new("diff")
                .args(&[
                    "-u",
                    theirs_plain_temp.path().to_str().unwrap(),
                    merged_temp.path().to_str().unwrap(),
                ])
                .output();

            match theirs_to_final_diff {
                Ok(output) if !output.stdout.is_empty() => {
                    let diff_output = String::from_utf8_lossy(&output.stdout);
                    let diff_labeled = diff_output
                        .replace(
                            theirs_plain_temp.path().to_str().unwrap(),
                            &format!("{} (theirs)", conflict_type),
                        )
                        .replace(merged_temp.path().to_str().unwrap(), "final result");
                    eprintln!("{}", diff_labeled);
                }
                _ => eprintln!("No changes from theirs version"),
            }

            eprintln!("====================\n");

            // Encrypt the merged result
            let merged_ciphertext = ciphertext_from_plaintext_buffer(&merged_plaintext, recipients);
            std::fs::write(ciphertext, merged_ciphertext).unwrap();
            eprintln!(
                "Successfully resolved merge conflicts and wrote to {:?}",
                ciphertext
            );
        }
        Commands::Diff { vcs, from, files } => {
            if let Err(e) = show_secret_diff(
                &project_root,
                &cwd,
                identities,
                *vcs,
                from.as_deref(),
                files,
            ) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        Commands::List => {
            let cache: CacheFile = load_cache_file(&project_root);
            let mut files: BTreeMap<PathBuf, BTreeSet<(char, String)>> = BTreeMap::new();

            if let Some(flake_config) = &cache.flake {
                for (_, file) in &flake_config.files {
                    let entry = files.entry(file.source.clone()).or_default();
                    for r in &flake_config.admin_recipients {
                        entry.insert(('F', r.clone()));
                    }
                    for r in &file.recipients {
                        entry.insert(('R', r.clone()));
                    }
                }
            }

            if let Some(nixos_configs) = &cache.nixos {
                for (_, config) in nixos_configs {
                    for (_, file) in &config.files {
                        let entry = files.entry(file.source.clone()).or_default();
                        for r in &config.admin_recipients {
                            entry.insert(('N', r.clone()));
                        }
                        for r in &file.recipients {
                            entry.insert(('R', r.clone()));
                        }
                    }
                }
            }

            if let Some(darwin_configs) = &cache.darwin {
                for (_, config) in darwin_configs {
                    for (_, file) in &config.files {
                        let entry = files.entry(file.source.clone()).or_default();
                        for r in &config.admin_recipients {
                            entry.insert(('M', r.clone()));
                        }
                        for r in &file.recipients {
                            entry.insert(('R', r.clone()));
                        }
                    }
                }
            }

            if let Some(hm_configs) = &cache.home_manager {
                for (_, config) in hm_configs {
                    for (_, system) in config {
                        for (_, file) in &system.files {
                            let entry = files.entry(file.source.clone()).or_default();
                            for r in &system.admin_recipients {
                                entry.insert(('H', r.clone()));
                            }
                            for r in &file.recipients {
                                entry.insert(('R', r.clone()));
                            }
                        }
                    }
                }
            }

            if let Some(ds_configs) = &cache.dev_shells {
                for (_, config) in ds_configs {
                    for (_, system) in config {
                        for (_, file) in &system.files {
                            let entry = files.entry(file.source.clone()).or_default();
                            for r in &system.admin_recipients {
                                entry.insert(('D', r.clone()));
                            }
                            for r in &file.recipients {
                                entry.insert(('R', r.clone()));
                            }
                        }
                    }
                }
            }

            if files.is_empty() {
                eprintln!("No files configured.");
                return;
            }

            println!(
                "Legend: F=Flake, N=NixOS, M=macOS/Darwin, H=Home Manager, D=Dev Shell, R=File Recipient"
            );
            println!();
            for (path, recipients) in &files {
                println!("{}", path.display());
                for (kind, recipient) in recipients {
                    println!("  {} {}", kind, recipient);
                }
                println!();
            }
        }
        Commands::Cache => {
            if let Some(fingerprint) = get_flake_fingerprint(&project_root) {
                let cache_path = cache_file_path_for_fingerprint(&fingerprint);
                generate_cache_file(&project_root, &cache_path);
            } else {
                eprintln!("could not determine flake fingerprint, evaluating without caching");
                generate_cache_file_uncached(&project_root);
            }
        }
    }
}

fn show_secret_diff(
    project_root: &Path,
    cwd: &Path,
    identities: Vec<String>,
    vcs_arg: VcsArg,
    from: Option<&str>,
    files: &[PathBuf],
) -> Result<(), String> {
    let vcs = resolve_vcs(project_root, vcs_arg)?;
    let file_args = project_relative_files(files, cwd, project_root)?;
    let changed_paths = changed_paths(vcs, project_root, from, &file_args)?;
    let explicit_files = !file_args.is_empty();
    let base_rev = from.unwrap_or(default_base_rev(vcs));
    let mut saw_encrypted_file = false;
    let mut printed_diff = false;

    if changed_paths.is_empty() {
        eprintln!("No changed files found.");
        return Ok(());
    }

    for path in changed_paths {
        let old_ciphertext = read_base_file(vcs, project_root, base_rev, &path)?;
        let new_ciphertext = read_current_file(vcs, project_root, &path)?;
        let old_is_age = old_ciphertext
            .as_deref()
            .is_some_and(looks_like_age_ciphertext);
        let new_is_age = new_ciphertext
            .as_deref()
            .is_some_and(looks_like_age_ciphertext);

        if !old_is_age && !new_is_age {
            if explicit_files {
                eprintln!("Skipping {}: not an age ciphertext", path.display());
            }
            continue;
        }

        saw_encrypted_file = true;

        let old_plaintext = if old_is_age {
            let ciphertext = old_ciphertext.as_deref().unwrap();
            decrypt_ciphertext_buffer(ciphertext, &identities).map_err(|e| {
                format!(
                    "Failed to decrypt {} at {}: {}",
                    path.display(),
                    base_rev,
                    e
                )
            })?
        } else {
            Vec::new()
        };

        let new_plaintext = if new_is_age {
            let ciphertext = new_ciphertext.as_deref().unwrap();
            decrypt_ciphertext_buffer(ciphertext, &identities)
                .map_err(|e| format!("Failed to decrypt current {}: {}", path.display(), e))?
        } else {
            Vec::new()
        };

        if old_plaintext == new_plaintext {
            continue;
        }

        let old_label = if old_is_age {
            format!("a/{} ({})", path.display(), base_rev)
        } else {
            "/dev/null".to_string()
        };
        let new_label = if new_is_age {
            format!("b/{} (current)", path.display())
        } else {
            "/dev/null".to_string()
        };

        if print_plaintext_diff(&old_label, &old_plaintext, &new_label, &new_plaintext)? {
            printed_diff = true;
        }
    }

    if !saw_encrypted_file {
        eprintln!("No changed encrypted files found.");
    } else if !printed_diff {
        eprintln!("No plaintext changes in changed encrypted files.");
    }

    Ok(())
}

fn resolve_vcs(project_root: &Path, vcs_arg: VcsArg) -> Result<Vcs, String> {
    match vcs_arg {
        VcsArg::Auto => {
            if command_succeeds(project_root, "jj", &["root"]) {
                Ok(Vcs::Jj)
            } else if command_succeeds(project_root, "git", &["rev-parse", "--show-toplevel"]) {
                Ok(Vcs::Git)
            } else {
                Err("Could not find a jj or git repository.".to_string())
            }
        }
        VcsArg::Jj => {
            if command_succeeds(project_root, "jj", &["root"]) {
                Ok(Vcs::Jj)
            } else {
                Err("Could not find a jj repository.".to_string())
            }
        }
        VcsArg::Git => {
            if command_succeeds(project_root, "git", &["rev-parse", "--show-toplevel"]) {
                Ok(Vcs::Git)
            } else {
                Err("Could not find a git repository.".to_string())
            }
        }
    }
}

fn command_succeeds(project_root: &Path, program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .current_dir(project_root)
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn default_base_rev(vcs: Vcs) -> &'static str {
    match vcs {
        Vcs::Jj => "@-",
        Vcs::Git => "HEAD",
    }
}

fn project_relative_files(
    files: &[PathBuf],
    cwd: &Path,
    project_root: &Path,
) -> Result<Vec<PathBuf>, String> {
    let mut relative_files = Vec::new();
    let normalized_project_root = normalize_path(project_root);
    for file in files {
        let absolute = if file.is_absolute() {
            file.clone()
        } else {
            cwd.join(file)
        };
        let absolute = normalize_path(&absolute);
        let relative = absolute
            .strip_prefix(&normalized_project_root)
            .map_err(|_| {
                format!(
                    "{} is not inside project root {}",
                    file.display(),
                    project_root.display()
                )
            })?;
        relative_files.push(relative.to_path_buf());
    }
    Ok(relative_files)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn changed_paths(
    vcs: Vcs,
    project_root: &Path,
    from: Option<&str>,
    files: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
    let output = match vcs {
        Vcs::Jj => {
            let mut command = Command::new("jj");
            command
                .current_dir(project_root)
                .arg("diff")
                .arg("--name-only")
                .arg("--from")
                .arg(from.unwrap_or(default_base_rev(vcs)))
                .arg("--to")
                .arg("@");
            if !files.is_empty() {
                command.arg("--");
                for file in files {
                    command.arg(file);
                }
            }
            command
                .output()
                .map_err(|e| format!("Failed to run jj diff: {}", e))?
        }
        Vcs::Git => {
            let mut command = Command::new("git");
            command
                .current_dir(project_root)
                .arg("diff")
                .arg("--name-only")
                .arg(from.unwrap_or(default_base_rev(vcs)))
                .arg("--");
            for file in files {
                command.arg(file);
            }
            command
                .output()
                .map_err(|e| format!("Failed to run git diff: {}", e))?
        }
    };

    if !output.status.success() {
        return Err(format!(
            "{} diff failed:\n{}",
            vcs_name(vcs),
            command_output_error(&output)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut paths = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn vcs_name(vcs: Vcs) -> &'static str {
    match vcs {
        Vcs::Jj => "jj",
        Vcs::Git => "git",
    }
}

fn command_output_error(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        return stderr.trim().to_string();
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn read_base_file(
    vcs: Vcs,
    project_root: &Path,
    base_rev: &str,
    path: &Path,
) -> Result<Option<Vec<u8>>, String> {
    match vcs {
        Vcs::Jj => read_jj_file(project_root, base_rev, path),
        Vcs::Git => read_git_revision_file(project_root, base_rev, path),
    }
}

fn read_current_file(
    vcs: Vcs,
    project_root: &Path,
    path: &Path,
) -> Result<Option<Vec<u8>>, String> {
    match vcs {
        Vcs::Jj => read_jj_file(project_root, "@", path),
        Vcs::Git => match std::fs::read(project_root.join(path)) {
            Ok(contents) => Ok(Some(contents)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Failed to read {}: {}", path.display(), e)),
        },
    }
}

fn read_jj_file(
    project_root: &Path,
    revision: &str,
    path: &Path,
) -> Result<Option<Vec<u8>>, String> {
    let output = Command::new("jj")
        .current_dir(project_root)
        .arg("file")
        .arg("show")
        .arg("--revision")
        .arg(revision)
        .arg(path)
        .output()
        .map_err(|e| format!("Failed to run jj file show: {}", e))?;

    if output.status.success() {
        Ok(Some(output.stdout))
    } else {
        Ok(None)
    }
}

fn read_git_revision_file(
    project_root: &Path,
    revision: &str,
    path: &Path,
) -> Result<Option<Vec<u8>>, String> {
    let revision_path = format!("{}:{}", revision, path.display());
    let output = Command::new("git")
        .current_dir(project_root)
        .arg("show")
        .arg("--no-ext-diff")
        .arg(revision_path)
        .output()
        .map_err(|e| format!("Failed to run git show: {}", e))?;

    if output.status.success() {
        Ok(Some(output.stdout))
    } else {
        Ok(None)
    }
}

fn looks_like_age_ciphertext(contents: &[u8]) -> bool {
    let first_non_whitespace = contents
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(contents.len());
    let trimmed = &contents[first_non_whitespace..];
    trimmed.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
        || trimmed.starts_with(b"age-encryption.org/v1")
}

fn decrypt_ciphertext_buffer(contents: &[u8], identities: &[String]) -> Result<Vec<u8>, String> {
    let armor_reader = ArmoredReader::new(contents);
    let decryptor =
        age::Decryptor::new(armor_reader).map_err(|e| format!("Invalid age ciphertext: {}", e))?;

    let mut decrypted = vec![];
    let mut stdin_guard = StdinGuard::new(true);
    let identity = read_identities(identities.to_vec(), Some(30), &mut stdin_guard)
        .map_err(|e| format!("Failed to read identities: {}", e))?;
    let identity_refs: Vec<&dyn Identity> = identity.iter().map(|i| i.as_ref()).collect();
    let mut reader = decryptor
        .decrypt(identity_refs.into_iter())
        .map_err(|_| "You do not have an identity able to decrypt this file.".to_string())?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| format!("Failed to decrypt ciphertext: {}", e))?;

    Ok(decrypted)
}

fn print_plaintext_diff(
    old_label: &str,
    old_plaintext: &[u8],
    new_label: &str,
    new_plaintext: &[u8],
) -> Result<bool, String> {
    let old_temp = temp_file::empty();
    let new_temp = temp_file::empty();
    std::fs::write(old_temp.path(), old_plaintext)
        .map_err(|e| format!("Failed to write diff input: {}", e))?;
    std::fs::write(new_temp.path(), new_plaintext)
        .map_err(|e| format!("Failed to write diff input: {}", e))?;

    let output = Command::new("diff")
        .arg("-u")
        .arg("--label")
        .arg(old_label)
        .arg("--label")
        .arg(new_label)
        .arg(old_temp.path())
        .arg(new_temp.path())
        .output()
        .map_err(|e| format!("Failed to run diff: {}", e))?;

    if !output.status.success() && output.status.code() != Some(1) {
        return Err(format!("diff failed:\n{}", command_output_error(&output)));
    }

    if output.stdout.is_empty() {
        return Ok(false);
    }

    std::io::stdout()
        .write_all(&output.stdout)
        .map_err(|e| format!("Failed to write diff output: {}", e))?;
    Ok(true)
}

fn cache_dir_path() -> PathBuf {
    let dir = cache_dir().unwrap().join("arcanum");
    if !dir.exists() {
        std::fs::create_dir_all(&dir).unwrap();
    }
    dir
}

fn cache_file_path_for_fingerprint(fingerprint: &str) -> PathBuf {
    cache_dir_path().join(format!("{}.json", fingerprint))
}

fn cleanup_old_cache_files() {
    let dir = cache_dir_path();
    let max_age = std::time::Duration::from_secs(7 * 24 * 60 * 60);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!("failed to read cache directory for cleanup: {}", e);
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match metadata.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if let Ok(age) = modified.elapsed() {
            if age > max_age {
                debug!("removing old cache file: {:?}", path);
                let _ = std::fs::remove_file(&path);
            }
        }
    }
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

fn get_flake_fingerprint(project_root: &Path) -> Option<String> {
    debug!("running: nix flake metadata --json");
    let start = Instant::now();
    let result = Command::new("nix")
        .args(["flake", "metadata", "--json"])
        .current_dir(project_root)
        .output();
    let elapsed = start.elapsed();
    debug!("nix flake metadata completed in {:.2?}", elapsed);

    match result {
        Ok(output) if output.status.success() => {
            let json_str = String::from_utf8_lossy(&output.stdout);
            let metadata: serde_json::Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    debug!("failed to parse flake metadata JSON: {}", e);
                    return None;
                }
            };
            let fingerprint = metadata
                .get("fingerprint")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            debug!("flake fingerprint: {:?}", fingerprint);
            fingerprint
        }
        Ok(output) => {
            debug!(
                "nix flake metadata failed (exit {}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            None
        }
        Err(e) => {
            debug!("nix flake metadata failed to execute: {}", e);
            None
        }
    }
}

fn load_cache_file(project_root: &Path) -> CacheFile {
    if let Some(fingerprint) = get_flake_fingerprint(project_root) {
        let cache_path = cache_file_path_for_fingerprint(&fingerprint);
        if cache_path.exists() {
            let data = std::fs::read_to_string(&cache_path).unwrap();
            if let Ok(cache_file) = serde_json::from_str::<CacheFile>(&data) {
                debug!("cache hit (fingerprint: {})", fingerprint);
                return cache_file;
            }
            debug!("cache file corrupt, regenerating");
        } else {
            debug!("no cache for fingerprint {}, generating", fingerprint);
        }
        generate_cache_file(project_root, &cache_path)
    } else {
        debug!("could not determine flake fingerprint, evaluating without caching");
        generate_cache_file_uncached(project_root)
    }
}

fn generate_cache_file(project_root: &Path, cache: &Path) -> CacheFile {
    let cache_file = generate_cache_file_uncached(project_root);
    let data = serde_json::to_string(&cache_file).unwrap();
    std::fs::write(cache, data).unwrap();
    cleanup_old_cache_files();
    cache_file
}

fn generate_cache_file_uncached(project_root: &Path) -> CacheFile {
    debug!("running: nix eval --json .#lib.arcanum");
    let start = Instant::now();
    let result = Command::new("nix")
        .arg("eval")
        .arg("--json")
        .arg(".#lib.arcanum")
        .current_dir(project_root)
        .output()
        .unwrap();
    let elapsed = start.elapsed();
    debug!("nix eval completed in {:.2?}", elapsed);

    if !result.status.success() {
        eprintln!("nix eval failed");
        eprintln!("stdout: {}", String::from_utf8_lossy(&result.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&result.stderr));
        std::process::exit(1);
    }
    let data = String::from_utf8(result.stdout).unwrap();
    serde_json::from_str(&data).unwrap()
}

fn plaintext_from_ciphertext_source(source: &Path, identities: Vec<String>) -> Vec<u8> {
    let contents = if source.exists() {
        let encrypted = std::fs::read(source).unwrap();
        let armor_reader = ArmoredReader::new(&encrypted[..]);
        let decryptor = age::Decryptor::new(armor_reader).unwrap();

        let mut decrypted = vec![];
        let mut stdin_guard = StdinGuard::new(true);
        let identity = read_identities(identities, Some(30), &mut stdin_guard).unwrap();
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
    let recipient_refs: Vec<&dyn Recipient> = recipients
        .iter()
        .map(|r| {
            let boxed_ref: &(dyn Recipient + Send) = r.as_ref();
            boxed_ref as &dyn Recipient
        })
        .collect();
    let encryptor = age::Encryptor::with_recipients(recipient_refs.iter().copied()).unwrap();
    let mut encrypted = vec![];
    let mut armored_writer =
        age::armor::ArmoredWriter::wrap_output(&mut encrypted, Format::AsciiArmor).unwrap();
    let mut writer = encryptor.wrap_output(&mut armored_writer).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    armored_writer.finish().unwrap();
    encrypted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_name_parts_strips_the_age_suffix() {
        assert_eq!(
            plaintext_name_parts(Path::new("secrets/github-actions.toml.age")),
            ("github-actions".to_string(), "toml".to_string())
        );
    }

    #[test]
    fn plaintext_name_parts_falls_back_when_there_is_no_inner_extension() {
        assert_eq!(
            plaintext_name_parts(Path::new("secrets/project.age")),
            ("project".to_string(), "txt".to_string())
        );
    }

    #[test]
    fn plaintext_name_parts_handles_paths_that_are_not_age_files() {
        assert_eq!(
            plaintext_name_parts(Path::new("secrets/project.env")),
            ("project".to_string(), "env".to_string())
        );
    }

    #[test]
    fn relative_paths_are_resolved_from_the_project_root() {
        assert_eq!(
            absolute_path(
                Path::new("/project"),
                Path::new("secrets/github-actions.toml.age")
            ),
            PathBuf::from("/project/secrets/github-actions.toml.age")
        );
    }

    #[test]
    fn absolute_paths_are_not_changed() {
        assert_eq!(
            absolute_path(
                Path::new("/project"),
                Path::new("/elsewhere/github-actions.toml.age")
            ),
            PathBuf::from("/elsewhere/github-actions.toml.age")
        );
    }

    #[test]
    fn edited_plaintext_updates_only_the_matching_destination() {
        let matching = temp_file::empty();
        let other = temp_file::empty();
        std::fs::write(matching.path(), b"old matching value").unwrap();
        std::fs::write(other.path(), b"old other value").unwrap();
        let files = vec![
            EditFile {
                source: PathBuf::from("secrets/project.env.age"),
                dest: matching.path().to_path_buf(),
            },
            EditFile {
                source: PathBuf::from("secrets/other.env.age"),
                dest: other.path().to_path_buf(),
            },
        ];

        let updated = update_edited_plaintext_files(
            Path::new("/project"),
            Path::new("secrets/project.env.age"),
            b"new matching value",
            files,
        )
        .unwrap();

        assert_eq!(updated, vec![matching.path().to_path_buf()]);
        assert_eq!(
            std::fs::read(matching.path()).unwrap(),
            b"new matching value"
        );
        assert_eq!(std::fs::read(other.path()).unwrap(), b"old other value");
    }

    #[cfg(unix)]
    #[test]
    fn updated_plaintext_is_only_readable_by_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let destination = temp_file::empty();
        let files = vec![EditFile {
            source: PathBuf::from("secrets/project.env.age"),
            dest: destination.path().to_path_buf(),
        }];

        update_edited_plaintext_files(
            Path::new("/project"),
            Path::new("secrets/project.env.age"),
            b"plaintext",
            files,
        )
        .unwrap();

        let mode = std::fs::metadata(destination.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{:o}", mode);
    }

    #[test]
    fn plaintext_temp_file_is_named_after_the_ciphertext() {
        let temp = PlaintextTempFile::new(Path::new("secrets/github-actions.toml.age"), None)
            .expect("temp file");
        let name = temp
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(name.starts_with("github-actions."), "{}", name);
        assert!(name.ends_with(".toml"), "{}", name);
        assert!(temp.path().exists());
    }

    #[test]
    fn plaintext_temp_file_includes_the_label() {
        let temp = PlaintextTempFile::new(Path::new("secrets/project.env.age"), Some("ours"))
            .expect("temp file");
        let name = temp
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(name.starts_with("project.ours."), "{}", name);
        assert!(name.ends_with(".env"), "{}", name);
    }

    #[cfg(unix)]
    #[test]
    fn plaintext_temp_file_is_only_readable_by_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let temp =
            PlaintextTempFile::new(Path::new("secrets/project.env.age"), None).expect("temp file");
        let mode = std::fs::metadata(temp.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{:o}", mode);
    }

    #[test]
    fn plaintext_temp_file_is_removed_on_drop() {
        let path = {
            let temp = PlaintextTempFile::new(Path::new("secrets/project.env.age"), None)
                .expect("temp file");
            std::fs::write(temp.path(), b"plaintext").unwrap();
            temp.path().to_path_buf()
        };
        assert!(!path.exists(), "{:?} was left behind", path);
    }

    /// Re-runs itself in a child process that gets killed mid-"edit", which is
    /// the only way to observe the signal handler without killing the harness.
    #[cfg(unix)]
    #[test]
    fn plaintext_temp_file_is_removed_when_killed_by_a_signal() {
        const REPORT_TO: &str = "ARCANUM_TEST_SIGNAL_REPORT_TO";

        if let Ok(report_to) = std::env::var(REPORT_TO) {
            let temp = PlaintextTempFile::new(Path::new("secrets/project.env.age"), None)
                .expect("temp file");
            std::fs::write(temp.path(), b"plaintext").unwrap();
            std::fs::write(&report_to, temp.path().as_os_str().as_encoded_bytes()).unwrap();
            unsafe { libc::raise(libc::SIGTERM) };
            unreachable!("SIGTERM should have terminated the child");
        }

        let report_to = temp_file::empty();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "--quiet",
                "tests::plaintext_temp_file_is_removed_when_killed_by_a_signal",
            ])
            .env(REPORT_TO, report_to.path())
            .status()
            .expect("re-run test binary");

        assert_eq!(
            status.code(),
            None,
            "child should have died from the signal, not exited"
        );

        let reported = std::fs::read(report_to.path()).unwrap();
        assert!(!reported.is_empty(), "child never reported its temp file");
        let leaked = PathBuf::from(String::from_utf8(reported).unwrap());
        assert!(!leaked.exists(), "{:?} survived the signal", leaked);
    }
}
