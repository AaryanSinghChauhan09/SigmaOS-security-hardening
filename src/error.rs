use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Command error: {0}")]
    Command(String),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Hardening error: {0}")]
    Hardening(String),
    
    #[error("Audit error: {0}")]
    Audit(String),
    
    #[error("Compliance error: {0}")]
    Compliance(String),
}
