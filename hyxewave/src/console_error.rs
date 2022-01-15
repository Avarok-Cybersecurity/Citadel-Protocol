use std::error::Error;

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

impl<E: Error> From<E> for ConsoleError {
    fn from(err: E) -> Self {
        ConsoleError::Generic(err.to_string())
    }
}