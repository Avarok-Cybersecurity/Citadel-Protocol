/// An error type for this crate
pub enum ConfigError {
    Generic(String),
    IoError(String)
}

impl ToString for ConfigError {
    fn to_string(&self) -> String {
        match self {
            ConfigError::Generic(err) => {
                err.to_string()
            },

            ConfigError::IoError(err) => {
                err.to_string()
            }
        }
    }
}



