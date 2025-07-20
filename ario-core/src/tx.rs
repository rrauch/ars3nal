use crate::blob::{BlobName, TypedBlob};
use crate::serde::{de_empty_string_as_none, ser_none_as_empty_string};
use crate::{Address, id};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::fmt::{Debug};

const MAX_TX_DATA_LEN: usize = 1024 * 1024 * 12;

pub struct TxKind;
pub type TxId = id::Typed256B64Id<TxKind>;

#[derive(Debug, Clone, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Format {
    V1 = 1,
    V2 = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
// todo: Vec<u8>? or String?
pub struct Tag {
    pub name: String,
    pub value: String,
}

// This follows the definition found here:
// https://docs.arweave.org/developers/arweave-node-server/http-api#field-definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxData {
    pub format: Format,
    pub id: TxId,
    pub last_tx: TxId,
    pub owner: String, // todo: rsa public key
    pub tags: Vec<Tag>,
    #[serde(
        deserialize_with = "de_empty_string_as_none",
        serialize_with = "ser_none_as_empty_string"
    )]
    pub target: Option<Address<()>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>, // todo: numerical string (winstons)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_root: Option<String>, // todo: Merkle Root
    pub data_size: String, // todo: numerical string (size in bytes)
    #[serde(
        deserialize_with = "de_empty_string_as_none",
        serialize_with = "ser_none_as_empty_string"
    )]
    pub data: Option<TxPayload>,
    pub reward: Option<String>, // todo: numerical string (winstons)
    pub signature: String,      // todo: rsa signature
}

pub type TxPayload = TypedBlob<TxKind, MAX_TX_DATA_LEN>;
impl BlobName for TxKind {
    const NAME: &'static str = "tx_payload";
}
