use crate::error::SecurityError;
use serde::{Deserialize, Serialize};
use std::process::Command;

pub struct SecurityAudit;

impl SecurityAudit {
    pub fn new() -> Result<Self, SecurityError> {
        Ok(Self)
    }
    
    pub fn run_audit(&self, audit_type: &str) -> Result<AuditResult, SecurityError> {
        let mut issues = Vec::new();
        let mut status = "Pass".to_string();
        
        match audit_type {
            "all" | "system" => {
                self.audit_system(&mut issues)?;
            }
            "network" => {
                self.audit_network(&mut issues)?;
            }
            "filesystem" => {
                self.audit_filesystem(&mut issues)?;
            }
            "authentication" => {
                self.audit_authentication(&mut issues)?;
            }
            "encryption" => {
                self.audit_encryption(&mut issues)?;
            }
            _ => {
                return Err(SecurityError::AuditFailed(format!("Unknown audit type: {}", audit_type)));
            }
        }
        
        if !issues.is_empty() {
            status = "Fail".to_string();
        }
        
        Ok(AuditResult {
            audit_type: audit_type.to_string(),
            status,
            issues,
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }
    
    fn audit_system(&self, issues: &mut Vec<AuditIssue>) -> Result<(), SecurityError> {
        // Check SELinux status
        let selinux_status = Command::new("getenforce").output()?;
        if !selinux_status.stdout.contains(&b'1') && !selinux_status.stdout.contains(&b'E') {
            issues.push(AuditIssue {
                severity: "High".to_string(),
                description: "SELinux is not enabled".to_string(),
                recommendation: "Enable SELinux for mandatory access control".to_string(),
            });
        }
        
        // Check firewall status
        let firewall_status = Command::new("systemctl").arg("is-active").arg("firewalld").output()?;
        if !firewall_status.stdout.contains(&b'active') {
            issues.push(AuditIssue {
                severity: "High".to_string(),
                description: "Firewall is not active".to_string(),
                recommendation: "Enable firewall for network protection".to_string(),
            });
        }
        
        // Check audit logging
        let audit_status = Command::new("systemctl").arg("is-active").arg("auditd").output()?;
        if !audit_status.stdout.contains(&b'active') {
            issues.push(AuditIssue {
                severity: "Medium".to_string(),
                description: "Audit logging is not active".to_string(),
                recommendation: "Enable audit logging for security monitoring".to_string(),
            });
        }
        
        Ok(())
    }
    
    fn audit_network(&self, issues: &mut Vec<AuditIssue>) -> Result<(), SecurityError> {
        // Check for open ports
        let ports_output = Command::new("ss").arg("-tlnp").output()?;
        let ports = String::from_utf8_lossy(&ports_output.stdout);
        
        // Check for suspicious ports
        let suspicious_ports = ["23", "21", "25", "110", "143"];
        for port in suspicious_ports {
            if ports.contains(port) {
                issues.push(AuditIssue {
                    severity: "Medium".to_string(),
                    description: format!("Port {} is open", port),
                    recommendation: format!("Consider closing port {} if not needed", port),
                });
            }
        }
        
        Ok(())
    }
    
    fn audit_filesystem(&self, issues: &mut Vec<AuditIssue>) -> Result<(), SecurityError> {
        // Check file permissions
        let sensitive_files = ["/etc/shadow", "/etc/passwd", "/etc/sudoers"];
        
        for file in sensitive_files {
            let status = Command::new("stat").arg("-c").arg("%a").arg(file).output()?;
            if status.status.success() {
                let perms = String::from_utf8_lossy(&status.stdout).trim().to_string();
                if perms != "600" && perms != "644" {
                    issues.push(AuditIssue {
                        severity: "Medium".to_string(),
                        description: format!("Incorrect permissions on {}: {}", file, perms),
                        recommendation: format!("Set correct permissions on {}", file),
                    });
                }
            }
        }
        
        Ok(())
    }
    
    fn audit_authentication(&self, issues: &mut Vec<AuditIssue>) -> Result<(), SecurityError> {
        // Check password policy
        let pam_output = Command::new("cat").arg("/etc/pam.d/system-auth").output()?;
        let pam_config = String::from_utf8_lossy(&pam_output.stdout);
        
        if !pam_config.contains("pam_pwquality.so") {
            issues.push(AuditIssue {
                severity: "Medium".to_string(),
                description: "Password quality module not configured".to_string(),
                recommendation: "Configure password quality requirements".to_string(),
            });
        }
        
        Ok(())
    }
    
    fn audit_encryption(&self, issues: &mut Vec<AuditIssue>) -> Result<(), SecurityError> {
        // Check disk encryption
        let cryptsetup_output = Command::new("lsblk").arg("-o").arg("NAME,TYPE,FSTYPE").output()?;
        let block_devices = String::from_utf8_lossy(&cryptsetup_output.stdout);
        
        if !block_devices.contains("crypt") {
            issues.push(AuditIssue {
                severity: "Low".to_string(),
                description: "Disk encryption not detected".to_string(),
                recommendation: "Consider enabling disk encryption for sensitive data".to_string(),
            });
        }
        
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub audit_type: String,
    pub status: String,
    pub issues: Vec<AuditIssue>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditIssue {
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}
