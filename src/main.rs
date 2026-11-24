use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod hardening;
mod error;
mod audit;
mod compliance;

use hardening::SecurityManager;
use error::SecurityError;

#[derive(Parser)]
#[command(name = "sigmaos-security")]
#[command(about = "SigmaOS security hardening system")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply security hardening
    Harden {
        /// Hardening profile
        #[arg(short, long, default_value = "standard")]
        profile: String,
        /// Dry run
        #[arg(short, long)]
        dry_run: bool,
        /// Force apply
        #[arg(short, long)]
        force: bool,
    },
    /// Audit security configuration
    Audit {
        /// Audit type
        #[arg(short, long, default_value = "all")]
        audit_type: String,
        /// Output format
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Check compliance
    Compliance {
        /// Compliance standard
        #[arg(short, long)]
        standard: String,
        /// Generate report
        #[arg(short, long)]
        report: bool,
    },
    /// Show security status
    Status {
        /// Show detailed status
        #[arg(short, long)]
        detailed: bool,
    },
    /// Configure security settings
    Config {
        /// Set hardening profile
        #[arg(short, long)]
        profile: Option<String>,
        /// Enable SELinux
        #[arg(short, long)]
        selinux: Option<bool>,
        /// Enable AppArmor
        #[arg(short, long)]
        apparmor: Option<bool>,
        /// Enable firewall
        #[arg(short, long)]
        firewall: Option<bool>,
    },
}

fn main() -> Result<(), SecurityError> {
    env_logger::init();
    
    let cli = Cli::parse();
    let security_manager = SecurityManager::new()?;
    
    match cli.command {
        Commands::Harden { profile, dry_run, force } => {
            if dry_run {
                let changes = security_manager.get_hardening_changes(&profile)?;
                println!("Dry run - {} changes would be applied:", changes.len());
                for change in changes {
                    println!("  {}: {}", change.component, change.action);
                }
            } else {
                security_manager.apply_hardening(&profile, force)?;
                println!("Security hardening applied successfully");
            }
        }
        Commands::Audit { audit_type, format } => {
            let audit_result = security_manager.run_audit(&audit_type)?;
            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&audit_result)?),
                "text" => {
                    println!("Security Audit Results:");
                    println!("  Status: {}", audit_result.status);
                    println!("  Issues found: {}", audit_result.issues.len());
                    for issue in audit_result.issues {
                        println!("    - {}: {}", issue.severity, issue.description);
                    }
                }
                _ => println!("Unknown format: {}", format),
            }
        }
        Commands::Compliance { standard, report } => {
            let compliance_result = security_manager.check_compliance(&standard)?;
            if report {
                let report_path = security_manager.generate_compliance_report(&compliance_result)?;
                println!("Compliance report generated at {}", report_path.display());
            } else {
                println!("Compliance check for {}:", standard);
                println!("  Status: {}", compliance_result.status);
                println!("  Score: {}/100", compliance_result.score);
            }
        }
        Commands::Status { detailed } => {
            let status = security_manager.get_status()?;
            println!("Security status:");
            println!("  Hardening profile: {}", status.profile);
            println!("  SELinux: {}", status.selinux_enabled);
            println!("  AppArmor: {}", status.apparmor_enabled);
            println!("  Firewall: {}", status.firewall_enabled);
            println!("  Encryption: {}", status.encryption_enabled);
            println!("  Last audit: {}", status.last_audit);
            
            if detailed {
                println!("\nSecurity components:");
                for component in status.components {
                    println!("  {}: {}", component.name, component.status);
                }
            }
        }
        Commands::Config { profile, selinux, apparmor, firewall } => {
            security_manager.update_config(profile, selinux, apparmor, firewall)?;
            println!("Security configuration updated");
        }
    }
    
    Ok(())
}
