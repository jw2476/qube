use std::{error::Error, fmt::Display};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier {
    namespace: String,
    value: String,
}

impl Identifier {
    /// Get the namespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use qube_proto::Identifier;
    /// let brand = Identifier::try_from("minecraft:brand").unwrap();
    /// assert_eq!(brand.namespace(), "minecraft");
    /// ```
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get the value.
    ///
    /// # Examples
    ///
    /// ```
    /// use qube_proto::Identifier;
    /// let brand = Identifier::try_from("minecraft:brand").unwrap();
    /// assert_eq!(brand.value(), "brand");
    /// ```
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn minecraft<T: AsRef<str>>(value: T) -> Result<Self, IdentifierParseError> {
        Self::try_from(format!("minecraft:{}", value.as_ref()).as_str())
    }
}

impl Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.value)
    }
}

impl PartialEq<(&str, &str)> for Identifier {
    fn eq(&self, other: &(&str, &str)) -> bool {
        self.namespace() == other.0 && self.value() == other.1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierParseError {
    InvalidNamespace,
    InvalidValue,
    EmptyNamespace,
    EmptyValue,
}

impl Display for IdentifierParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to parse identifier due to {}",
            match self {
                Self::InvalidNamespace => "invalid namespace",
                Self::InvalidValue => "invalid value",
                Self::EmptyNamespace => "empty namespace",
                Self::EmptyValue => "empty value",
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

        if namespace.is_empty() {
            return Err(IdentifierParseError::EmptyNamespace);
        }

        if value.is_empty() {
            return Err(IdentifierParseError::EmptyValue);
        }

        Ok(Self {
            namespace: namespace.to_string(),
            value: value.to_string(),
        })
    }
}
