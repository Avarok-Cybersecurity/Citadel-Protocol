pub enum Error {
    Default(String),
    Internal(&'static str)
}

impl ToString for Error {
    fn to_string(&self) -> String {
        match self {
            Error::Default(val) => val.to_string(),
            Error::Internal(val) => val.to_string()
        }
    }
}

impl AsRef<str> for Error {
    fn as_ref(&self) -> &str {
        match self {
            Error::Default(val) => val.as_ref(),
            Error::Internal(val) => val.as_ref()
        }
    }
}