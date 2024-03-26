mod detection;

use clap::{Parser, Subcommand};
use std::{env, ffi::OsString};

use signatures::sig_set::{bedet_set::BedetSet, SigSet};

#[derive(clap::Args)]
pub struct Compile {
    /// Signature directory
    #[clap(long)]
    dir: String,
    /// Output name/path of sigset. Extenstion should be "bset"
    #[clap(short, long)]
    out_path: String,
}

#[derive(Subcommand)]
pub enum SignatureCommand {
    Compile(Compile),
    //Unpack(Unpack),
    //List(),
}

#[derive(Subcommand)]
enum Commands {
    /// Build malware signature set
    #[command(subcommand)]
    Signature(SignatureCommand),
    /// Evaluate a suspected file
    StartDetection {
        /// Path to sha signature set
        #[clap(short)]
        bedet_sig_path: String,
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
                let set = BedetSet::from_signatures(args.dir.as_str())?;
                let ser = set.to_set_serializer();

                match ser.serialize_bedet_set(&args.out_path) {
                    Ok(number) => println!("SUCCESS to compile set. Count: {number}"),
                    Err(e) => log::error!("Failed to compile sigs. Err: {e}"),
                }
            },
        },
        Commands::StartDetection { bedet_sig_path } => {
            detection::start_detection(bedet_sig_path).unwrap()
        },
    }

    Ok(())
}
