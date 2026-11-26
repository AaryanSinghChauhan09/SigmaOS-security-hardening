use sigmaos_security_hardening::{
    ComplianceChecker, HardeningConfig, SecurityAuditor, SecurityHardener,
};

fn main() {
    env_logger::init();

    println!("SigmaOS Security Hardening");

    let hardening_config = HardeningConfig::default();
    let hardener = SecurityHardener::new(hardening_config.clone());

    println!("\n=== Applying Security Hardening ===");
    if let Err(e) = hardener.apply_hardening() {
        eprintln!("Failed to apply hardening: {}", e);
    } else {
        println!("Security hardening applied successfully");
    }

    println!("\n=== Running Security Audit ===");
    let auditor = SecurityAuditor;
    match auditor.audit() {
        Ok(report) => {
            println!("Audit report generated:");
            println!("  Vulnerabilities found: {}", report.vulnerabilities.len());
            println!("  Compliance issues: {}", report.compliance_issues.len());
        }
        Err(e) => eprintln!("Failed to run audit: {}", e),
    }

    println!("\n=== Checking Compliance ===");
    let checker = ComplianceChecker;
    let cis = checker.check_cis_benchmark();
    println!("CIS Benchmark: {} requirements", cis.requirements.len());

    let stig = checker.check_stig();
    println!("STIG: {} requirements", stig.requirements.len());

    println!("\nSecurity hardening complete");
}
