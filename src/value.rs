use std::collections::BTreeMap;

use crate::error::{Result, SecurityError};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    Real(f64),
    String(String),
    Data(Vec<u8>),
    Date(f64),
    Url(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl Value {
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    pub const fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    pub fn dictionary<const N: usize>(entries: [(&str, Self); N]) -> Self {
        Self::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(values) => values.get(key),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            Self::Unsigned(value) => i64::try_from(*value).ok(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            Self::Integer(value) => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Real(value) => Some(*value),
            Self::Integer(value) => Some(*value as f64),
            Self::Unsigned(value) => Some(*value as f64),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Self::Data(value) => Some(value),
            _ => None,
        }
    }

    pub const fn as_date(&self) -> Option<f64> {
        match self {
            Self::Date(value) => Some(*value),
            _ => None,
        }
    }

    pub(crate) fn into_strings(self, operation: &'static str) -> Result<Vec<String>> {
        let Self::Array(values) = self else {
            return Err(SecurityError::UnexpectedType {
                operation,
                expected: "string array",
            });
        };
        values
            .into_iter()
            .map(|value| match value {
                Self::String(value) => Ok(value),
                _ => Err(SecurityError::UnexpectedType {
                    operation,
                    expected: "string",
                }),
            })
            .collect()
    }
}
