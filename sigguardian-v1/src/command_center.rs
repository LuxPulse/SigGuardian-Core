use clap::{Parser, Subcommand};
use crate::remote_control::RemoteControl;
use crate::signature_builder::BuilderArgs;
use crate::system::format_system_info;

#[derive(Parser)]
#[clap(name = "SigGuardian-X Command Center")]
#[clap(version = "1.0")]
#[clap(about = "Ultimate sovereign defense system", long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Build a new environment signature
    Build {
        #[clap(flatten)]
        args: BuilderArgs,
    },
    
    /// Verify current environment
    Verify,
    
    /// Control remote devices
    Control {
        #[clap(subcommand)]
        action: ControlActions,
    },
    
    /// System diagnostics
    Diagnose,
}

#[derive(Subcommand)]
pub enum ControlActions {
    /// Get system info from remote device
    Info {
        /// IP address of target device
        ip: String,
    },
    
    /// Initiate purge on remote device
    Purge {
        /// IP address of target device
        ip: String,
    },
    
    /// Shutdown remote application
    Shutdown {
        /// IP address of target device
        ip: String,
    },
}

pub fn execute_command() {
    let cli = Cli::parse();
    
    match &cli.command {
        Commands::Build { args } => {
            if let Err(e) = crate::signature_builder::build_signature(args.clone(), crate::constants::ENCRYPTION_KEY) {
                eprintln!("❌ Build failed: {}", e);
                std::process::exit(1);
            }
            println!("✅ Signature created successfully");
        }
        Commands::Verify => {
            match crate::execute_guardian_protection("sig.guard") {
                Ok(_) => println!("✅ Environment verified successfully"),
                Err(e) => {
                    eprintln!("❌ Verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Control { action } => {
            match action {
                ControlActions::Info { ip } => {
                    match RemoteControl::send_command(ip, "SYSINFO") {
                        Ok(info) => println!("{}", info),
                        Err(e) => eprintln!("❌ Command failed: {}", e),
                    }
                }
                ControlActions::Purge { ip } => {
                    match RemoteControl::send_command(ip, "PURGE_NOW") {
                        Ok(_) => println!("✅ Purge command sent successfully"),
                        Err(e) => eprintln!("❌ Command failed: {}", e),
                    }
                }
                ControlActions::Shutdown { ip } => {
                    match RemoteControl::send_command(ip, "SHUTDOWN") {
                        Ok(_) => println!("✅ Shutdown command sent successfully"),
                        Err(e) => eprintln!("❌ Command failed: {}", e),
                    }
                }
            }
        }
        Commands::Diagnose => {
            let info = crate::system::get_system_info();
            println!("{}", format_system_info(&info));
        }
    }
}