use std::{error::Error, fmt::Display};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier {
    namespace: String,
    value: String,
}

impl Identifier {
    pub fn minecraft<T: AsRef<str>>(value: T) -> Self {
        Self {
            namespace: "minecraft".to_string(),
            value: value.as_ref().to_string(),
        }
    }
}

impl Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierParseError {
    InvalidNamespace,
    InvalidValue,
}

impl Display for IdentifierParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to parse identifier due to {}",
            match self {
                Self::InvalidNamespace => "invalid namespace",
                Self::InvalidValue => "invalid value",
            }
        )
    }
}

impl Error for IdentifierParseError {}

impl TryFrom<&str> for Identifier {
    type Error = IdentifierParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (namespace, value) = value.split_once(':').unwrap_or(("minecraft", value));

        if !namespace.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_'
        }) {
            return Err(IdentifierParseError::InvalidNamespace);
        }

        if !value.chars().all(|c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || c == '.'
                || c == '-'
                || c == '_'
                || c == '/'
        }) {
            return Err(IdentifierParseError::InvalidValue);
        }

        Ok(Self {
            namespace: namespace.to_string(),
            value: value.to_string(),
        })
    }
}
