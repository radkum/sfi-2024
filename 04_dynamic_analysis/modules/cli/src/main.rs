use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};
use std::{env, ffi::OsString};

use signatures::sig_set::{heuristic_set::HeurSet, sha_set::ShaSet, SigSet};
use signatures::sig_set::dynamic_set::DynSet;

#[derive(clap::Args)]
pub struct CompileRaw {
    /// Malware dir
    #[clap(short, long)]
    dir: String,
    /// Out path of sigset. Extenstion should be "sset"
    #[clap(short, long)]
    out_path: String,
}

#[derive(clap::Args)]
pub struct Compile {
    /// Create Set from sha signatures
    #[clap(short)]
    sha_set: bool,
    /// Create Set from heuristic signatures
    #[clap(short = 'i')]
    heuristic_set: bool,
    /// Create Set from dynamic signatures
    #[clap(short = 'd')]
    dynamic_set: bool,
    /// Signature directory
    #[clap(long)]
    dir: String,
    /// Output name/path of sigset. Extenstion should be "sset"
    #[clap(short, long)]
    out_path: String,
}

#[derive(clap::Args)]
pub struct Unpack {
    /// Path to sset
    #[clap(short, long)]
    sha_set: String,
    /// Directory where sigs should be unpack
    #[clap(short, long)]
    out_dir: String,
}

#[derive(Subcommand)]
pub enum SignatureCommand {
    CompileRaw(CompileRaw),
    Compile(Compile),
    Unpack(Unpack),
    //List(List), - todo in future
}

#[derive(Subcommand)]
enum Commands {
    /// Build malware signature set
    #[command(subcommand)]
    Signature(SignatureCommand),
    /// Evaluate a suspected file
    Evaluate {
        /// Path to sha signature set. Optional
        #[clap(short)]
        sha_sig_path: Option<String>,
        /// Path to heur signature set. Optional
        #[clap(short = 'i')]
        heur_sig_path: Option<String>,
        /// Path to scan. Dir or file
        #[clap(value_name = "PATH")]
        file_path: String,
    },
    /// Sandbox a suspected file
    Sandbox {
        /// Path to dynamic signature set. Optional
        #[clap(short = 'd')]
        dyn_sig_path: String,
        /// Path to scan. Dir or file
        #[clap(value_name = "PATH")]
        file_path: String,
    },
}

#[derive(Parser)]
#[command(author, about)]
pub struct Cli {
    /// Increase log message verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    log_level: u8,
    #[arg(short = 'V', long)]
    /// Print version information
    version: bool,
    #[command(subcommand)]
    commands: Commands,
}

pub fn main() -> anyhow::Result<()> {
    let mut args = env::args_os().collect::<Vec<_>>();
    if args.len() == 1 {
        args.push(OsString::from("--help"));
    }
    let args = Cli::parse_from(args);

    let log_level = match args.log_level {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::new().filter_level(log_level).init();

    match args.commands {
        Commands::Signature(signature_command) => match signature_command {
            SignatureCommand::Compile(args) => {
                let (set_type, magic) = get_magic_for_sigset(&args);

                let ser = match set_type {
                    SetType::Sha => {
                        let set = ShaSet::from_signatures(args.dir.as_str())?;
                        set.to_sig_set()
                    },
                    SetType::Heur => {
                        let set = HeurSet::from_signatures(args.dir.as_str())?;
                        set.to_sig_set()
                    },
                    SetType::Dyn => {
                        let set = DynSet::from_signatures(args.dir.as_str())?;
                        set.to_sig_set()
                    },
                };

                match ser.serialize(&args.out_path, magic) {
                    Ok(number) => println!("SUCCESS to compile set. Count: {number}"),
                    Err(e) => log::error!("Failed to compile sigs. Err: {e}"),
                }
            },
            SignatureCommand::Unpack(args) => {
                let sha_set = signatures::deserialize_sha_set_from_path(args.sha_set.as_str())?;
                if std::path::Path::new(&args.out_dir).exists() {
                    let md = std::fs::metadata(&args.out_dir)?;
                    if md.is_file() {
                        let info = format!("{} is a file!", &args.out_dir);
                        let mut cmd = Cli::command();
                        cmd.error(ErrorKind::ArgumentConflict, info).exit();
                    }

                    let _ = std::fs::remove_dir(&args.out_dir);
                }

                let res = std::fs::create_dir(&args.out_dir);
                if let Err(e) = res {
                    log::warn!("Failed to create dir: {}. Err: {e}", &args.out_dir);
                } else {
                    match sha_set.unpack_to_dir(&args.out_dir) {
                        Ok(number) => println!("SUCCESS to unpack shaset. Count: {number}"),
                        Err(e) => log::error!("Failed to create dir: {}. Err: {e}", &args.out_dir),
                    }
                }
            },
            SignatureCommand::CompileRaw(args) => {
                let sha_set = ShaSet::from_dir(args.dir.as_str())?;
                let ser = sha_set.to_sig_set();
                ser.serialize(&args.out_path, ShaSet::SET_MAGIC_U32)?;
            },
        },
        Commands::Evaluate {
            sha_sig_path,
            heur_sig_path,
            file_path,
        } => {
            if sha_sig_path.is_none() && heur_sig_path.is_none() {
                //something wrong
                log::warn!("You need specify at least one set");
                return Ok(());
            } else {
                scanner::scan_path(file_path.as_str(), sha_sig_path, heur_sig_path)?
            }
        },
        Commands::Sandbox {
            dyn_sig_path,
            file_path,
        } => {
            let v = sandbox::sandbox_path(file_path.as_str())?;
            scanner::scan_api_calls(v, dyn_sig_path)?
        },
    }

    Ok(())
}
pub type Magic = u32;
enum SetType {
    Sha,
    Heur,
    Dyn,
}

fn get_magic_for_sigset(args: &Compile) -> (SetType, Magic) {
    match (args.sha_set, args.heuristic_set, args.dynamic_set) {
        (true, false, false) => (SetType::Sha, ShaSet::SET_MAGIC_U32),
        (false, true, false) => (SetType::Heur, HeurSet::SET_MAGIC_U32),
        (false, false, true) => (SetType::Dyn, DynSet::SET_MAGIC_U32),
        _ => {
            let mut cmd = Cli::command();
            cmd.error(
                ErrorKind::ArgumentConflict,
                "You can choose only one version of signatures",
            )
            .exit();
        },
    }
}
