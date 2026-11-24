use crate::error::SecurityError;
use crate::audit::SecurityAudit;
use crate::compliance::ComplianceChecker;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use std::process::Command;

pub struct SecurityManager {
    config_path: PathBuf,
    audit: SecurityAudit,
    compliance: ComplianceChecker,
}

impl SecurityManager {
    pub fn new() -> Result<Self, SecurityError> {
        let config_dir = directories::config_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join("sigmaos");
        
        fs::create_dir_all(&config_dir)?;
        
        Ok(Self {
            config_path: config_dir.join("security.toml"),
            audit: SecurityAudit::new()?,
            compliance: ComplianceChecker::new()?,
        })
    }
    
    pub fn apply_hardening(&self, profile: &str, force: bool) -> Result<(), SecurityError> {
        let changes = self.get_hardening_changes(profile)?;
        
        if changes.is_empty() {
            log::info!("No hardening changes needed");
            return Ok(());
        }
        
        if !force {
            // Show changes and ask for confirmation
            println!("The following changes will be applied:");
            for change in &changes {
                println!("  {}: {}", change.component, change.action);
            }
            println!("\nUse --force to apply changes without confirmation");
            return Ok(());
        }
        
        // Apply changes
        for change in changes {
            self.apply_change(&change)?;
        }
        
        // Update configuration
        self.update_profile(profile)?;
        
        log::info!("Security hardening applied successfully");
        Ok(())
    }
    
    pub fn get_hardening_changes(&self, profile: &str) -> Result<Vec<HardeningChange>, SecurityError> {
        let mut changes = Vec::new();
        
        match profile {
            "minimal" => {
                // Minimal hardening
                changes.push(HardeningChange {
                    component: "firewall".to_string(),
                    action: "enable".to_string(),
                    description: "Enable basic firewall".to_string(),
                });
            }
            "standard" => {
                // Standard hardening
                changes.push(HardeningChange {
                    component: "selinux".to_string(),
                    action: "enable".to_string(),
                    description: "Enable SELinux".to_string(),
                });
                changes.push(HardeningChange {
                    component: "firewall".to_string(),
                    action: "enable".to_string(),
                    description: "Enable firewall".to_string(),
                });
                changes.push(HardeningChange {
                    component: "audit".to_string(),
                    action: "enable".to_string(),
                    description: "Enable audit logging".to_string(),
                });
            }
            "strict" => {
                // Strict hardening
                changes.push(HardeningChange {
                    component: "selinux".to_string(),
                    action: "enable".to_string(),
                    description: "Enable SELinux in enforcing mode".to_string(),
                });
                changes.push(HardeningChange {
                    component: "apparmor".to_string(),
                    action: "enable".to_string(),
                    description: "Enable AppArmor".to_string(),
                });
                changes.push(HardeningChange {
                    component: "firewall".to_string(),
                    action: "enable".to_string(),
                    description: "Enable strict firewall".to_string(),
                });
                changes.push(HardeningChange {
                    component: "encryption".to_string(),
                    action: "enable".to_string(),
                    description: "Enable disk encryption".to_string(),
                });
                changes.push(HardeningChange {
                    component: "audit".to_string(),
                    action: "enable".to_string(),
                    description: "Enable comprehensive audit logging".to_string(),
                });
            }
            _ => {
                return Err(SecurityError::InvalidProfile(profile.to_string()));
            }
        }
        
        Ok(changes)
    }
    
    pub fn run_audit(&self, audit_type: &str) -> Result<AuditResult, SecurityError> {
        self.audit.run_audit(audit_type)
    }
    
    pub fn check_compliance(&self, standard: &str) -> Result<ComplianceResult, SecurityError> {
        self.compliance.check_compliance(standard)
    }
    
    pub fn get_status(&self) -> Result<SecurityStatus, SecurityError> {
        let config = self.load_config()?;
        
        Ok(SecurityStatus {
            profile: config.profile,
            selinux_enabled: self.is_selinux_enabled()?,
            apparmor_enabled: self.is_apparmor_enabled()?,
            firewall_enabled: self.is_firewall_enabled()?,
            encryption_enabled: self.is_encryption_enabled()?,
            last_audit: self.get_last_audit_time()?,
            components: self.get_component_status()?,
        })
    }
    
    pub fn update_config(&self, profile: Option<String>, selinux: Option<bool>, apparmor: Option<bool>, firewall: Option<bool>) -> Result<(), SecurityError> {
        let mut config = self.load_config()?;
        
        if let Some(profile) = profile {
            config.profile = profile;
        }
        
        if let Some(selinux) = selinux {
            config.selinux = selinux;
        }
        
        if let Some(apparmor) = apparmor {
            config.apparmor = apparmor;
        }
        
        if let Some(firewall) = firewall {
            config.firewall = firewall;
        }
        
        self.save_config(&config)?;
        Ok(())
    }
    
    pub fn generate_compliance_report(&self, result: &ComplianceResult) -> Result<PathBuf, SecurityError> {
        let report_path = directories::data_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .join("sigmaos")
            .join("compliance-report.html");
        
        let report_content = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>SigmaOS Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .status {{ font-size: 24px; font-weight: bold; }}
        .score {{ font-size: 18px; color: #666; }}
        .issues {{ margin-top: 20px; }}
        .issue {{ padding: 10px; margin: 5px 0; border-left: 4px solid #ccc; }}
        .high {{ border-left-color: #d9534f; }}
        .medium {{ border-left-color: #f0ad4e; }}
        .low {{ border-left-color: #5bc0de; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SigmaOS Compliance Report</h1>
        <div class="status">Status: {}</div>
        <div class="score">Score: {}/100</div>
    </div>
    <div class="issues">
        <h2>Issues Found</h2>
        {}
    </div>
</body>
</html>"#,
            result.status,
            result.score,
            result.issues.iter().map(|issue| {
                format!(
                    r#"<div class="issue {}">
                        <strong>{}</strong>: {}
                        <br><small>Recommendation: {}</small>
                    </div>"#,
                    issue.severity.to_lowercase(),
                    issue.severity,
                    issue.description,
                    issue.recommendation
                )
            }).collect::<Vec<_>>().join("\n")
        );
        
        fs::write(&report_path, report_content)?;
        Ok(report_path)
    }
    
    fn load_config(&self) -> Result<SecurityConfig, SecurityError> {
        if self.config_path.exists() {
            let content = fs::read_to_string(&self.config_path)?;
            toml::from_str(&content).map_err(|e| SecurityError::Config(e.to_string()))
        } else {
            Ok(SecurityConfig::default())
        }
    }
    
    fn save_config(&self, config: &SecurityConfig) -> Result<(), SecurityError> {
        let content = toml::to_string_pretty(config)?;
        fs::write(&self.config_path, content)?;
        Ok(())
    }
    
    fn apply_change(&self, change: &HardeningChange) -> Result<(), SecurityError> {
        match change.component.as_str() {
            "selinux" => self.enable_selinux()?,
            "apparmor" => self.enable_apparmor()?,
            "firewall" => self.enable_firewall()?,
            "audit" => self.enable_audit()?,
            "encryption" => self.enable_encryption()?,
            _ => log::warn!("Unknown component: {}", change.component),
        }
        Ok(())
    }
    
    fn enable_selinux(&self) -> Result<(), SecurityError> {
        // Enable SELinux
        let status = Command::new("sudo")
            .arg("setenforce")
            .arg("1")
            .status()?;
        
        if !status.success() {
            return Err(SecurityError::HardeningFailed("Failed to enable SELinux".to_string()));
        }
        
        Ok(())
    }
    
    fn enable_apparmor(&self) -> Result<(), SecurityError> {
        // Enable AppArmor
        let status = Command::new("sudo")
            .arg("systemctl")
            .arg("enable")
            .arg("apparmor")
            .status()?;
        
        if !status.success() {
            return Err(SecurityError::HardeningFailed("Failed to enable AppArmor".to_string()));
        }
        
        Ok(())
    }
    
    fn enable_firewall(&self) -> Result<(), SecurityError> {
        // Enable firewall
        let status = Command::new("sudo")
            .arg("systemctl")
            .arg("enable")
            .arg("firewalld")
            .status()?;
        
        if !status.success() {
            return Err(SecurityError::HardeningFailed("Failed to enable firewall".to_string()));
        }
        
        Ok(())
    }
    
    fn enable_audit(&self) -> Result<(), SecurityError> {
        // Enable audit logging
        let status = Command::new("sudo")
            .arg("systemctl")
            .arg("enable")
            .arg("auditd")
            .status()?;
        
        if !status.success() {
            return Err(SecurityError::HardeningFailed("Failed to enable audit logging".to_string()));
        }
        
        Ok(())
    }
    
    fn enable_encryption(&self) -> Result<(), SecurityError> {
        // Enable disk encryption
        // TODO: Implement disk encryption
        Ok(())
    }
    
    fn is_selinux_enabled(&self) -> Result<bool, SecurityError> {
        let status = Command::new("getenforce")
            .output()?;
        
        Ok(status.stdout.contains(&b'1') || status.stdout.contains(&b'E'))
    }
    
    fn is_apparmor_enabled(&self) -> Result<bool, SecurityError> {
        let status = Command::new("systemctl")
            .arg("is-active")
            .arg("apparmor")
            .output()?;
        
        Ok(status.stdout.contains(&b'active'))
    }
    
    fn is_firewall_enabled(&self) -> Result<bool, SecurityError> {
        let status = Command::new("systemctl")
            .arg("is-active")
            .arg("firewalld")
            .output()?;
        
        Ok(status.stdout.contains(&b'active'))
    }
    
    fn is_encryption_enabled(&self) -> Result<bool, SecurityError> {
        // Check if disk encryption is enabled
        // TODO: Implement encryption check
        Ok(false)
    }
    
    fn get_last_audit_time(&self) -> Result<String, SecurityError> {
        // Get last audit time
        // TODO: Implement audit time retrieval
        Ok("Never".to_string())
    }
    
    fn get_component_status(&self) -> Result<Vec<ComponentStatus>, SecurityError> {
        Ok(vec![
            ComponentStatus {
                name: "SELinux".to_string(),
                status: if self.is_selinux_enabled()? { "Enabled".to_string() } else { "Disabled".to_string() },
            },
            ComponentStatus {
                name: "AppArmor".to_string(),
                status: if self.is_apparmor_enabled()? { "Enabled".to_string() } else { "Disabled".to_string() },
            },
            ComponentStatus {
                name: "Firewall".to_string(),
                status: if self.is_firewall_enabled()? { "Enabled".to_string() } else { "Disabled".to_string() },
            },
            ComponentStatus {
                name: "Encryption".to_string(),
                status: if self.is_encryption_enabled()? { "Enabled".to_string() } else { "Disabled".to_string() },
            },
        ])
    }
    
    fn update_profile(&self, profile: &str) -> Result<(), SecurityError> {
        let mut config = self.load_config()?;
        config.profile = profile.to_string();
        self.save_config(&config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningChange {
    pub component: String,
    pub action: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub profile: String,
    pub selinux: bool,
    pub apparmor: bool,
    pub firewall: bool,
    pub encryption: bool,
    pub audit: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            profile: "standard".to_string(),
            selinux: true,
            apparmor: false,
            firewall: true,
            encryption: false,
            audit: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityStatus {
    pub profile: String,
    pub selinux_enabled: bool,
    pub apparmor_enabled: bool,
    pub firewall_enabled: bool,
    pub encryption_enabled: bool,
    pub last_audit: String,
    pub components: Vec<ComponentStatus>,
}

#[derive(Debug, Clone)]
pub struct ComponentStatus {
    pub name: String,
    pub status: String,
}
