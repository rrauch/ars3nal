use crate::JsonError;
use crate::confidential::{Confidential, SecretExt};
use crate::json::JsonSource;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Copy, Clone, PartialEq, Hash, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeyType {
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "EC")]
    Ec,
    #[serde(rename = "OKP")]
    Okp,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rsa => "RSA",
            Self::Ec => "EC",
            Self::Okp => "OKP",
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    kty: KeyType,
    #[serde(flatten)]
    fields: HashMap<String, Confidential<String>>,
}

impl Jwk {
    pub fn key_type(&self) -> KeyType {
        self.kty
    }

    pub fn contains(&self, field: impl AsRef<str>) -> bool {
        self.fields.contains_key(field.as_ref())
    }

    pub fn get(&self, field: impl AsRef<str>) -> Option<&Confidential<String>> {
        self.fields.get(field.as_ref())
    }

    pub fn from_json<J: JsonSource>(json: J) -> Result<Self, JsonError> {
        serde_json::from_value(json.try_into_json()?)
    }

    pub(crate) fn to_json_str(&self) -> Result<Confidential<String>, JsonError> {
        serde_json::to_string_pretty(self).map(|s| s.confidential())
    }
}

impl Zeroize for Jwk {
    fn zeroize(&mut self) {
        self.fields.drain().for_each(|(_, mut v)| v.zeroize());
    }
}

impl Drop for Jwk {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Jwk {}
