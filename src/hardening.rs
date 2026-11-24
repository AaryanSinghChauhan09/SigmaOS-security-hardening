use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningConfig {
    pub enable_apparmor: bool,
    pub enable_selinux: bool,
    pub enable_firewall: bool,
    pub enable_audit: bool,
    pub enable_fde: bool,
    pub enable_secure_boot: bool,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            enable_apparmor: true,
            enable_selinux: false,
            enable_firewall: true,
            enable_audit: true,
            enable_fde: false,
            enable_secure_boot: false,
        }
    }
}

pub struct SecurityHardener {
    config: HardeningConfig,
}

impl SecurityHardener {
    pub fn new(config: HardeningConfig) -> Self {
        Self { config }
    }
    
    pub fn apply_hardening(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.enable_apparmor {
            self.enable_apparmor()?;
        }
        
        if self.config.enable_selinux {
            self.enable_selinux()?;
        }
        
        if self.config.enable_firewall {
            self.configure_firewall()?;
        }
        
        if self.config.enable_audit {
            self.enable_audit()?;
        }
        
        if self.config.enable_fde {
            self.enable_full_disk_encryption()?;
        }
        
        if self.config.enable_secure_boot {
            self.enable_secure_boot()?;
        }
        
        Ok(())
    }
    
    fn enable_apparmor(&self) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("systemctl")
            .args(["enable", "apparmor"])
            .status()?;
        
        if !status.success() {
            return Err("Failed to enable AppArmor".into());
        }
        
        println!("AppArmor enabled");
        Ok(())
    }
    
    fn enable_selinux(&self) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("systemctl")
            .args(["enable", "selinux"])
            .status()?;
        
        if !status.success() {
            return Err("Failed to enable SELinux".into());
        }
        
        println!("SELinux enabled");
        Ok(())
    }
    
    fn configure_firewall(&self) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("ufw")
            .args(["enable"])
            .status()?;
        
        if !status.success() {
            return Err("Failed to enable firewall".into());
        }
        
        println!("Firewall enabled");
        Ok(())
    }
    
    fn enable_audit(&self) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("auditd")
            .status()?;
        
        if !status.success() {
            return Err("Failed to enable audit".into());
        }
        
        println!("Audit enabled");
        Ok(())
    }
    
    fn enable_full_disk_encryption(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Full disk encryption configuration would go here");
        Ok(())
    }
    
    fn enable_secure_boot(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Secure boot configuration would go here");
        Ok(())
    }
}
