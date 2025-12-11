use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_yaml::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

// Define error codes for external consumption (e.g. exit codes or log tags)
impl AppError {
    pub fn code(&self) -> &'static str {
        match self {
            AppError::DatabaseError(_) => "E001",
            AppError::ConfigError(_) => "E002",
            AppError::IoError(_) => "E003",
            AppError::SerializationError(_) => "E004",
            AppError::Unknown(_) => "E999",
        }
    }
}
