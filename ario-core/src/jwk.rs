use crate::JsonError;
use crate::json::JsonSource;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: KeyType,
    #[serde(flatten)]
    pub fields: HashMap<String, Zeroizing<String>>,
}

impl Jwk {
    pub fn from_json<J: JsonSource>(json: J) -> Result<Self, JsonError> {
        serde_json::from_value(json.try_into_json()?)
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
