use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RextioRuntimeError {
    message: String,
}

impl RextioRuntimeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for RextioRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(&self.message)
    }
}

impl Error for RextioRuntimeError {}

#[cfg(test)]
mod tests {
    use super::RextioRuntimeError;

    #[test]
    fn stores_actionable_message() {
        let error = RextioRuntimeError::new("index out of bounds");

        assert_eq!(error.message(), "index out of bounds");
        assert_eq!(error.to_string(), "index out of bounds");
    }
}
