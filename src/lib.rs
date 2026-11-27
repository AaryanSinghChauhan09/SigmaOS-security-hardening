#![forbid(unsafe_code)]

pub mod audit;
pub mod compliance;
pub mod error;
pub mod hardening;

pub use audit::{AuditReport, SecurityAuditor};
pub use compliance::{ComplianceChecker, ComplianceStandard};
pub use error::SecurityError;
pub use hardening::{HardeningConfig, SecurityHardener};

#[cfg(test)]
mod tests {
    use super::*;
    use compliance::ComplianceStatus;

    #[test]
    fn hardening_config_defaults_are_secure() {
        let c = HardeningConfig::default();
        assert!(c.enable_apparmor);
        assert!(c.enable_firewall);
        assert!(c.enable_audit);
        // FDE/secure-boot default off (require hardware/setup)
        assert!(!c.enable_fde);
        assert!(!c.enable_secure_boot);
    }

    #[test]
    fn hardening_config_serde_roundtrip() {
        let c = HardeningConfig {
            enable_apparmor: false,
            enable_selinux: true,
            enable_firewall: false,
            enable_audit: true,
            enable_fde: true,
            enable_secure_boot: true,
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: HardeningConfig = serde_json::from_str(&j).unwrap();
        assert!(back.enable_selinux);
        assert!(back.enable_fde);
        assert!(!back.enable_apparmor);
    }

    #[test]
    fn cis_benchmark_shape() {
        let cis = ComplianceChecker.check_cis_benchmark();
        assert_eq!(cis.name, "CIS Benchmark");
        assert_eq!(cis.requirements.len(), 3);
        assert!(cis
            .requirements
            .iter()
            .all(|r| r.status == ComplianceStatus::Unknown));
        assert!(cis.requirements.iter().any(|r| r.id == "CIS-1.1"));
    }

    #[test]
    fn stig_shape() {
        let stig = ComplianceChecker.check_stig();
        assert_eq!(stig.name, "STIG");
        assert_eq!(stig.requirements.len(), 2);
    }

    #[test]
    fn audit_report_serde_roundtrip() {
        let r = AuditReport {
            timestamp: "2026-01-01T00:00:00Z".into(),
            vulnerabilities: vec![audit::Vulnerability {
                severity: "High".into(),
                description: "d".into(),
                component: "c".into(),
                fix_available: true,
            }],
            compliance_issues: vec![],
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: AuditReport = serde_json::from_str(&j).unwrap();
        assert_eq!(back.vulnerabilities.len(), 1);
        assert_eq!(back.vulnerabilities[0].severity, "High");
    }
}
