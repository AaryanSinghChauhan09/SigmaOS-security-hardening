use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("TOML error: {0}")]
    Toml(#[from] toml::ser::Error),
    
    #[error("TOML error: {0}")]
    TomlDe(#[from] toml::de::Error),
    
    #[error("Security error: {0}")]
    Security(String),
    
    #[error("Invalid profile: {0}")]
    InvalidProfile(String),
    
    #[error("Hardening failed: {0}")]
    HardeningFailed(String),
    
    #[error("Audit failed: {0}")]
    AuditFailed(String),
    
    #[error("Compliance check failed: {0}")]
    ComplianceFailed(String),
    
    #[error("Config error: {0}")]
    Config(String),
}
