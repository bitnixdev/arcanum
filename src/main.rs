use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::info;
use whoami::{username, hostname};
use toor::project::find_project_root;

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
    Encrypt {  name: Option<String> },
    Decrypt { name: Option<String> },
    Edit { name: Option<String> },
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
    flakes: HashMap<String, ArcanumFile>,
    home_manager: HashMap<String, HashMap<String, HashMap<String, ArcanumFile>>>,
    nixos: HashMap<String, HashMap<String, HashMap<String, ArcanumFile>>>,
    nixos_admin_recipients: Vec<String>,
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

    let cache = match cli.cache_file {
        Some(file) => {
            let file = Path::new(&file);
            if !file.exists() {
                panic!("Cache file does not exist: {:?}", file);
            }
            let data = std::fs::read_to_string(file).unwrap();
            let cache: CacheFile = serde_json::from_str(&data).unwrap();
            info!("cache: {:?}", cache);
            cache
        }
        None => None
    };

    let files = match &cli.context {
        Context::DevShell => {
            let dev_shell_path = dev_shell_path();
            info!("dev_shell_path: {}", dev_shell_path);
            let json_data = read_nix(project_root, dev_shell_path);
            let files: HashMap<String, ArcanumFile> = serde_json::from_str(&json_data).unwrap();
            info!("files: {:?}", files);
            files
        }
        Context::HomeManager => {
            let home_manager_path = home_manager_path();
            info!("home_manager_path: {}", home_manager_path);
            unreachable!("HomeManager is not yet supported");
        }
        Context::NixOs => {
            unreachable!("NixOs is not yet supported");
        }
        _ => panic!("Unsupported context: {:?}", cli.context)
    };


    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::Encrypt { name } => {
            println!("'Encrypt' was used, name is: {:?}", name)
        }
        Commands::Decrypt { name } => {
            println!("'Decrypt' was used, name is: {:?}", name)
        }
        Commands::Edit { name } => {
            println!("'Edit' was used, name is: {:?}", name)
        }
    }
}

fn read_cache() -> CacheFile {

}

fn dev_shell_path() -> String {
    let username = username();
    let hostname = hostname();
    let hostname = hostname.split('.').next().unwrap();
    let arch = std::env::consts::ARCH;
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        platform => platform,
    };

    format!(".#lib.arcanum.devShells.{}-{}.{}-{}", arch, platform, username, hostname)
}
fn home_manager_path() -> String {
    let username = username();
    let arch = std::env::consts::ARCH;
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        platform => platform,
    };

    format!(".#lib.arcanum.homeConfigurations.{}-{}.{}", arch, platform, username)
}

// .#lib.arcanum.devShells.aarch64-darwin.jasonrm-elon
fn read_nix(cwd: PathBuf, path: String) -> String {
    let output = Command::new("nix")
        .current_dir(cwd)
        .arg("eval")
        .arg("--json")
        .arg(path)
        .output()
        .expect("failed to execute process");

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        exit(1);
    }
    stdout.to_string()
}