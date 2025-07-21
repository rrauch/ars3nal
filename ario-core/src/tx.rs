use crate::blob::{BlobName, TypedBlob};
use crate::money::{TypedMoney, Winston};
use crate::serde::{empty_string_none, string_number};
use crate::stringify::Stringify;
use crate::valid::Valid;
use crate::{Address, id};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

const MAX_TX_DATA_LEN: usize = 1024 * 1024 * 12;

pub struct TxKind;
pub type TxId = id::Typed256B64Id<TxKind>;

pub struct TxAnchorKind;
pub type TxAnchor = id::Typed384B64Id<TxAnchorKind>;

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum LastTx {
    V1(TxId),
    V2(TxAnchor),
}

#[derive(Error, Debug)]
pub enum LastTxError<E1, E2> {
    #[error("last_tx length is invalid, expected either 64 or 43 characters, but found {0}")]
    InvalidLength(usize),
    #[error(transparent)]
    V1Error(E1),
    #[error(transparent)]
    V2Error(E2),
}

impl Stringify<Self> for LastTx {
    type Error =
        LastTxError<<TxId as Stringify<TxId>>::Error, <TxAnchor as Stringify<TxAnchor>>::Error>;

    fn to_str(input: &Self) -> impl Into<Cow<str>> {
        match input {
            Self::V1(tx_id) => TxId::to_str(tx_id).into(),
            Self::V2(tx_anchor) => TxAnchor::to_str(tx_anchor).into(),
        }
    }

    fn try_from_str<S: AsRef<str>>(input: S) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let input = input.as_ref();
        match input.len() {
            64 => Ok(Self::V2(
                TxAnchor::try_from_str(input).map_err(LastTxError::V2Error)?,
            )),
            43 => Ok(Self::V1(
                TxId::try_from_str(input).map_err(LastTxError::V1Error)?,
            )),
            invalid => Err(LastTxError::InvalidLength(invalid)),
        }
    }
}

impl Display for LastTx {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(Self::to_str(self).into().as_ref())
    }
}

impl FromStr for LastTx {
    type Err =
        LastTxError<<TxId as Stringify<TxId>>::Error, <TxAnchor as Stringify<TxAnchor>>::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_str(s)
    }
}

impl Serialize for LastTx {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        crate::serde::stringify::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for LastTx {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        crate::serde::stringify::deserialize(deserializer)
    }
}

#[derive(Debug, Clone, Serialize_repr, Deserialize_repr, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Format {
    V1 = 1,
    V2 = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
// todo: Vec<u8>? or String?
pub struct Tag {
    pub name: String,
    pub value: String,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    TxDataError(#[from] TxDataError),
}

#[derive(Error, Debug)]
pub enum TxDataError {
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error("Incorrect last_tx variant found")]
    IncorrectLastTxVariant,
}

// This follows the definition found here:
// https://docs.arweave.org/developers/arweave-node-server/http-api#field-definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxData {
    pub format: Format,
    pub id: TxId,
    pub last_tx: LastTx,
    pub owner: String, // todo: rsa public key
    pub tags: Vec<Tag>,
    #[serde(with = "empty_string_none")]
    pub target: Option<Address<()>>,
    #[serde(default)]
    #[serde(with = "empty_string_none")]
    pub quantity: Option<Quantity>,
    pub data_tree: Vec<String>, // todo
    #[serde(default)]
    #[serde(with = "empty_string_none")]
    pub data_root: Option<String>, // todo: Merkle Root
    #[serde(with = "string_number")]
    pub data_size: u64,
    #[serde(with = "empty_string_none")]
    pub data: Option<Payload>,
    #[serde(with = "empty_string_none")]
    pub reward: Option<Reward>,
    pub signature: String, // todo: rsa signature
}

impl TxData {
    pub(crate) fn try_from_json_slice(bytes: &[u8]) -> Result<Self, TxDataError> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

impl Valid for TxData {
    type Error = TxDataError;

    fn validate(&self) -> Result<(), Self::Error> {
        match (&self.format, &self.last_tx) {
            (Format::V1, LastTx::V1(_)) => {}
            (Format::V2, LastTx::V2(_)) => {}
            _ => {
                return Err(TxDataError::IncorrectLastTxVariant);
            }
        }
        Ok(())
    }
}

pub type Payload = TypedBlob<TxKind, MAX_TX_DATA_LEN>;
impl BlobName for TxKind {
    const NAME: &'static str = "tx_payload";
}

pub struct TxQuantityKind;
pub type Quantity = TypedMoney<TxQuantityKind, Winston>;

pub struct TxRewardKind;
pub type Reward = TypedMoney<TxRewardKind, Winston>;

#[cfg(test)]
mod tests {
    use crate::money::{CurrencyExt, Winston};
    use crate::tx::{Format, TxData};
    use crate::valid::Valid;

    static TX_V1: &'static [u8] = include_bytes!("../testdata/tx_v1.json");
    static TX_V2: &'static [u8] = include_bytes!("../testdata/tx_v2.json");

    #[test]
    fn tx_data_ok_v1() -> anyhow::Result<()> {
        let tx_data = TxData::try_from_json_slice(TX_V1)?;
        tx_data.validate()?;
        assert_eq!(&tx_data.format, &Format::V1);
        assert_eq!(
            tx_data.id.to_string(),
            "BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ"
        );
        assert_eq!(
            tx_data.last_tx.to_string(),
            "jUcuEDZQy2fC6T3fHnGfYsw0D0Zl4NfuaXfwBOLiQtA"
        );
        /*assert_eq!(
            &tx_data.owner,
            "_qa4arkdjK2X9SjechexnWzTtbOKcPkBPhrDDej6lI8"
        );*/
        assert_eq!(&tx_data.tags, &vec![]);
        assert!(tx_data.target.is_none());
        assert_eq!(
            tx_data.quantity.as_ref().unwrap().as_ref(),
            &Winston::zero()
        );
        //todo: data root
        assert_eq!(tx_data.data_size, 1033478);
        assert_eq!(tx_data.data.as_ref().unwrap().len(), 1033478);
        //todo: verify data value
        assert_eq!(
            tx_data.reward.as_ref().unwrap().as_ref(),
            &Winston::from_str("124145681682")?,
        );
        //todo: signature
        Ok(())
    }

    #[test]
    fn tx_data_ok_v2() -> anyhow::Result<()> {
        let tx_data = TxData::try_from_json_slice(TX_V2)?;
        tx_data.validate()?;
        assert_eq!(&tx_data.format, &Format::V2);
        assert_eq!(
            tx_data.id.to_string(),
            "bXGqzNQNmHTeL54cUQ6wPo-MO0thLP44FeAoM93kEwk"
        );
        assert_eq!(
            tx_data.last_tx.to_string(),
            "gVhey9KN6Fjc3nZbSOqLPRyDjjw6O5-sLSWPLZ_S7LoX5XOrFRja8A_wuj22OpHj"
        );
        /*assert_eq!(
            &tx_data.owner,
            "OK_m2Tk41N94KZLl5WQSx_-iNWbvcp8EMfrYsel_QeQ"
        );*/
        //assert_eq!(&tx_data.tags, &vec![]); //todo: tags
        assert!(tx_data.target.is_none());
        assert_eq!(
            tx_data.quantity.as_ref().unwrap().as_ref(),
            &Winston::zero()
        );
        //todo: data root
        assert_eq!(tx_data.data_size, 128355);
        assert!(tx_data.data.is_none());
        assert_eq!(
            tx_data.reward.as_ref().unwrap().as_ref(),
            &Winston::from_str("557240107")?,
        );
        //todo: signature
        Ok(())
    }
}
