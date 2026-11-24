use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub timestamp: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub compliance_issues: Vec<ComplianceIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub severity: String,
    pub description: String,
    pub component: String,
    pub fix_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceIssue {
    pub standard: String,
    pub issue: String,
    pub severity: String,
}

pub struct SecurityAuditor;

impl SecurityAuditor {
    pub fn audit(&self) -> Result<AuditReport, Box<dyn std::error::Error>> {
        let vulnerabilities = self.scan_vulnerabilities()?;
        let compliance_issues = self.check_compliance()?;
        
        Ok(AuditReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            vulnerabilities,
            compliance_issues,
        })
    }
    
    fn scan_vulnerabilities(&self) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        let mut vulnerabilities = Vec::new();
        
        let output = Command::new("cve-check")
            .args(["--machine", "--format", "json"])
            .output()?;
        
        if output.status.success() {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            
            if let Some(pvds) = result["items"].as_array() {
                for pvd in pvds {
                    if let Some(name) = pvd["name"].as_str() {
                        vulnerabilities.push(Vulnerability {
                            severity: "Medium".to_string(),
                            description: format!("Vulnerability in {}", name),
                            component: name.to_string(),
                            fix_available: true,
                        });
                    }
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    fn check_compliance(&self) -> Result<Vec<ComplianceIssue>, Box<dyn std::error::Error>> {
        let mut issues = Vec::new();
        
        let output = Command::new("lynis")
            .arg("audit")
            .output()?;
        
        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout);
            
            if result.contains("Warning") {
                issues.push(ComplianceIssue {
                    standard: "CIS".to_string(),
                    issue: "Security configuration issues found".to_string(),
                    severity: "Medium".to_string(),
                });
            }
        }
        
        Ok(issues)
    }
}
