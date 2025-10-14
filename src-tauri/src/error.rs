use thiserror::Error;

#[derive(Debug, Error)]
pub enum VpnError {
    #[error("Invalid config format: {0}")]
    InvalidConfig(String),
    
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Already connected")]
    AlreadyConnected,
    
    #[error("Not connected")]
    NotConnected,
}

pub type VpnResult<T> = Result<T, VpnError>;
