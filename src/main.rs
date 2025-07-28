use age::armor::{ArmoredReader, Format};
use age::cli_common::{StdinGuard, read_identities};
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

    /// Edit the plaintext of a file
    Edit { ciphertext: PathBuf },

    /// Re-encrypt a file to all configured recipients, or all files if none specified
    Rekey { ciphertext: Option<PathBuf> },

    /// Resolve merge conflicts in an encrypted file
    Merge { ciphertext: PathBuf },

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
    let config = Config { root_pattern: None };
    let project_root = find_project_root(cwd, config);
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
            let recipients = cache.recipients_for_file(ciphertext);
            if recipients.is_empty() {
                eprintln!("No recipients found, unable to edit.");
                std::process::exit(1);
            }

            let original_plaintext_data =
                plaintext_from_ciphertext_source(ciphertext, identities.clone());
            let extension = ciphertext
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("txt");
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
        Commands::Merge { ciphertext } => {
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
            let extension = ciphertext
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("txt");

            let ours_plain_temp =
                temp_file::TempFile::with_suffix(format!(".ours.{}", extension)).unwrap();
            let theirs_plain_temp =
                temp_file::TempFile::with_suffix(format!(".theirs.{}", extension)).unwrap();
            let merged_temp =
                temp_file::TempFile::with_suffix(format!(".merged.{}", extension)).unwrap();

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
