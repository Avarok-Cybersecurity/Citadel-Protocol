#[derive(Debug)]
pub enum ConsoleError {
    Generic(String),
    Default(&'static str)
}

impl ConsoleError {
    pub fn into_string(self) -> String {
        match self {
            ConsoleError::Generic(err) => err,
            ConsoleError::Default(err) => err.to_string()
        }
    }
}

impl<T: ToString> From<T> for ConsoleError {
    fn from(val: T) -> Self {
        ConsoleError::Generic(val.to_string())
    }
}