use crate::blob::{BlobName, TypedBlob};
use crate::hash::{HasherExt, Sha256Hasher};
use crate::money::{Money, TypedMoney, Winston};
use crate::serde::{empty_string_none, string_number};
use crate::stringify::Stringify;
use crate::typed::FromInner;
use crate::valid::Valid;
use crate::wallet::Wallet;
use crate::{Address, hash, id, signature};
use derive_where::derive_where;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::LazyLock;
use thiserror::Error;

const MAX_TX_DATA_LEN: usize = 1024 * 1024 * 12;

static ZERO_QUANTITY: LazyLock<Quantity> = LazyLock::new(|| Quantity::zero());
static ZERO_REWARD: LazyLock<Reward> = LazyLock::new(|| Reward::zero());

pub struct TxKind;

pub type TxId = hash::TypedDigest<TxSignature, Sha256Hasher, 32>;
pub type TxSignature = signature::TypedSignature<TxKind, (), 512>;

impl TxSignature {
    fn empty() -> Self {
        Self::from_inner(signature::Signature::empty())
    }

    pub fn digest(&self) -> TxId {
        TxId::from_inner(Sha256Hasher::digest(self.as_slice()))
    }
}

pub struct TxAnchorKind;
pub type TxAnchor = id::Typed384B64Id<TxAnchorKind>;

#[derive(Debug, Clone, PartialEq)]
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
    #[error("Incorrect data length found: expected '{expected}' but found '{actual}'")]
    IncorrectDataLen { actual: u64, expected: u64 },
    #[error("quantity cannot be negative")]
    NegativeQuantity,
    #[error("reward cannot be negative")]
    NegativeReward,
    #[error("quantity is missing but mandatory for this tx")]
    MissingQuantity,
    #[error("target is missing but mandatory for this tx")]
    MissingTarget,
    #[error("tx id does not match the signature")]
    IdSignatureMismatch,
}

// This follows the definition found here:
// https://docs.arweave.org/developers/arweave-node-server/http-api#field-definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TxData {
    format: Format,
    id: TxId,
    last_tx: LastTx,
    owner: String, // todo: rsa public key
    tags: Vec<Tag>,
    #[serde(with = "empty_string_none")]
    target: Option<Address<()>>,
    #[serde(default)]
    #[serde(with = "empty_string_none")]
    quantity: Option<Quantity>,
    data_tree: Vec<String>, // todo
    #[serde(default)]
    #[serde(with = "empty_string_none")]
    data_root: Option<String>, // todo: Merkle Root
    #[serde(with = "string_number")]
    data_size: u64,
    #[serde(with = "empty_string_none")]
    data: Option<EmbeddedData>,
    #[serde(with = "empty_string_none")]
    reward: Option<Reward>,
    signature: TxSignature,
}

impl TxData {
    pub(crate) fn try_from_json_slice(bytes: &[u8]) -> Result<Self, TxDataError> {
        let tx_data: TxData = serde_json::from_slice(bytes)?;
        tx_data.validate()?;
        Ok(tx_data)
    }

    pub fn is_transfer(&self) -> bool {
        self.target.is_some() && self.quantity.is_some()
    }

    pub fn has_data(&self) -> bool {
        if let Some(data) = self.data.as_ref() {
            if !data.is_empty() {
                return true;
            }
        }
        self.has_external_payload()
    }

    pub fn has_external_payload(&self) -> bool {
        match self.format {
            Format::V1 => {
                // todo: double-check if V1 tx support external payloads or not
                false
            }
            Format::V2 => {
                // this is according do the docs at
                // https://docs.arweave.org/developers/arweave-node-server/http-api#field-definitions
                if self.data_size > 0
                    && self
                        .data_root
                        .as_ref()
                        .map(|e| !e.is_empty())
                        .unwrap_or(false)
                {
                    true
                } else {
                    false
                }
            }
        }
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
        if let Format::V1 = self.format {
            // the docs at  https://docs.arweave.org/developers/arweave-node-server/http-api#field-definitions
            // mention to use `data_size` only with V2 transactions, but actual transactions seem to use
            // data_size to indicate the actual length of the internal payload after deserialization.
            let data_len = self.data.as_ref().map(|d| d.len() as u64).unwrap_or(0);
            if data_len != self.data_size {
                return Err(TxDataError::IncorrectDataLen {
                    actual: data_len,
                    expected: self.data_size,
                });
            }
        }
        let mut positive_quantity = false;
        if let Some(quantity) = &self.quantity {
            if quantity < ZERO_QUANTITY.deref() {
                return Err(TxDataError::NegativeQuantity);
            }
            if quantity != ZERO_QUANTITY.deref() {
                if self.target.is_none() {
                    return Err(TxDataError::MissingTarget);
                }
                positive_quantity = true;
            }
        }

        if let Some(reward) = &self.reward {
            if reward < ZERO_REWARD.deref() {
                return Err(TxDataError::NegativeReward);
            }
        }

        if self.target.is_some() {
            if !positive_quantity {
                return Err(TxDataError::MissingQuantity);
            }
        }

        let expected_tx_id = self.signature.digest();
        if expected_tx_id != self.id {
            return Err(TxDataError::IdSignatureMismatch);
        }

        Ok(())
    }
}

pub type EmbeddedData = TypedBlob<TxKind, MAX_TX_DATA_LEN>;
impl BlobName for TxKind {
    const NAME: &'static str = "tx_embedded_data";
}

pub struct TxQuantityKind;
pub type Quantity = TypedMoney<TxQuantityKind, Winston>;

impl Quantity {
    pub(crate) fn from<I: Into<Money<Winston>>>(money: I) -> Self {
        Self::from_inner(money.into())
    }
}

pub struct TxRewardKind;
pub type Reward = TypedMoney<TxRewardKind, Winston>;

impl Reward {
    pub(crate) fn from<I: Into<Money<Winston>>>(money: I) -> Self {
        Self::from_inner(money.into())
    }
}

pub struct Signed;
pub struct Unsigned;

pub type V1Tx<S> = TxImpl<S, V1>;
pub type V2Tx<S> = TxImpl<S, V2>;

#[derive(Error, Debug)]
pub enum TxError {
    #[error(transparent)]
    DataError(#[from] TxDataError),
    #[error(transparent)]
    SigningError(#[from] SigningError),
}

#[derive_where(Debug, Clone)]
pub enum Tx<S> {
    V1(V1Tx<S>),
    V2(V2Tx<S>),
}

impl<S> Tx<S> {
    pub fn id(&self) -> &TxId {
        match self {
            Self::V1(v1) => v1.id(),
            Self::V2(v2) => v2.id(),
        }
    }

    pub fn tags(&self) -> &Vec<Tag> {
        match self {
            Self::V1(v1) => v1.tags(),
            Self::V2(v2) => v2.tags(),
        }
    }

    pub fn quantity(&self) -> Option<&Quantity> {
        match self {
            Self::V1(v1) => v1.quantity(),
            Self::V2(v2) => v2.quantity(),
        }
    }

    pub fn reward(&self) -> Option<&Reward> {
        match self {
            Self::V1(v1) => v1.reward(),
            Self::V2(v2) => v2.reward(),
        }
    }
}

impl SignedTx {
    pub fn try_from_json_slice(bytes: &[u8]) -> Result<Self, TxError> {
        let tx_data = TxData::try_from_json_slice(bytes)?;
        // todo: verify signature here?
        Ok(match tx_data.format {
            Format::V1 => Self::V1(TxImpl::new(tx_data)),
            Format::V2 => Self::V2(TxImpl::new(tx_data)),
        })
    }

    pub fn try_make_mut(self) -> Result<UnsignedTx, (Self, EditError)> {
        match self {
            Self::V1(v1) => Err((v1.into(), EditError::V1Unsupported)),
            Self::V2(v2) => Ok(v2.make_unsigned().into()),
        }
    }
}

impl UnsignedTx {
    pub(crate) fn sign(self, wallet: &Wallet) -> Result<SignedTx, (Self, SigningError)> {
        match self {
            Self::V1(v1) => Err((v1.into(), SigningError::V1Unsupported)),
            Self::V2(v2) => Ok(v2
                .sign(wallet)
                .map_err(|(inner, e)| (inner.into(), e))?
                .into()),
        }
    }

    pub fn tags_mut(&mut self) -> &mut Vec<Tag> {
        match self {
            Self::V1(v1) => v1.tags_mut(),
            Self::V2(v2) => v2.tags_mut(),
        }
    }

    pub fn quantity_mut(&mut self) -> &mut Option<Quantity> {
        match self {
            Self::V1(v1) => v1.quantity_mut(),
            Self::V2(v2) => v2.quantity_mut(),
        }
    }

    pub fn reward_mut(&mut self) -> &mut Option<Reward> {
        match self {
            Self::V1(v1) => v1.reward_mut(),
            Self::V2(v2) => v2.reward_mut(),
        }
    }
}

impl<S> From<TxImpl<S, V1>> for Tx<S> {
    fn from(value: TxImpl<S, V1>) -> Self {
        Self::V1(value)
    }
}

impl<S> From<TxImpl<S, V2>> for Tx<S> {
    fn from(value: TxImpl<S, V2>) -> Self {
        Self::V2(value)
    }
}

pub type SignedTx = Tx<Signed>;
pub type UnsignedTx = Tx<Unsigned>;

pub struct V1;
pub struct V2;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Signing V1 type transactions is not supported")]
    V1Unsupported,
}

#[derive(Error, Debug)]
pub enum EditError {
    #[error("Editing V1 type transactions is not supported")]
    V1Unsupported,
}

#[derive_where(Clone, Debug)]
#[repr(transparent)]
pub struct TxImpl<S, V>(TxData, PhantomData<(S, V)>);

impl<S, V> TxImpl<S, V> {
    fn new(inner: TxData) -> Self {
        Self(inner, PhantomData)
    }

    pub fn id(&self) -> &TxId {
        &self.0.id
    }

    pub fn tags(&self) -> &Vec<Tag> {
        &self.0.tags
    }

    pub fn quantity(&self) -> Option<&Quantity> {
        self.0.quantity.as_ref()
    }

    pub fn reward(&self) -> Option<&Reward> {
        self.0.reward.as_ref()
    }
}

impl<V> TxImpl<Unsigned, V> {
    pub fn tags_mut(&mut self) -> &mut Vec<Tag> {
        self.0.tags.as_mut()
    }

    pub fn quantity_mut(&mut self) -> &mut Option<Quantity> {
        &mut self.0.quantity
    }

    pub fn reward_mut(&mut self) -> &mut Option<Reward> {
        &mut self.0.reward
    }
}

impl<S> TxImpl<S, V1> {
    pub fn last_tx(&self) -> &TxId {
        if let LastTx::V1(tx_id) = &self.0.last_tx {
            tx_id
        } else {
            unreachable!()
        }
    }
}

impl<S> TxImpl<S, V2> {
    pub fn last_tx(&self) -> &TxAnchor {
        if let LastTx::V2(tx_anchor) = &self.0.last_tx {
            tx_anchor
        } else {
            unreachable!()
        }
    }
}

impl TxImpl<Unsigned, V2> {
    fn sign(self, _wallet: &Wallet) -> Result<TxImpl<Signed, V2>, (Self, SigningError)> {
        // tx signing happens here
        todo!()
    }

    pub fn set_last_tx(&mut self, anchor: TxAnchor) {
        self.0.last_tx = LastTx::V2(anchor);
    }
}

impl TxImpl<Signed, V2> {
    fn make_unsigned(self) -> TxImpl<Unsigned, V2> {
        let mut data = self.0;
        data.signature = TxSignature::empty();
        TxImpl(data, PhantomData)
    }
}

#[cfg(test)]
mod tests {
    use crate::money::{CurrencyExt, Winston};
    use crate::tx::{Format, Quantity, Reward, SignedTx, TxData, ZERO_QUANTITY};
    use std::ops::Deref;

    static TX_V1: &'static [u8] = include_bytes!("../testdata/tx_v1.json");
    static TX_V2: &'static [u8] = include_bytes!("../testdata/tx_v2.json");
    static TX_V2_2: &'static [u8] = include_bytes!("../testdata/tx_v2_2.json");

    #[test]
    fn tx_data_ok_v1() -> anyhow::Result<()> {
        let tx_data = TxData::try_from_json_slice(TX_V1)?;
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
        assert_eq!(tx_data.quantity.as_ref().unwrap(), ZERO_QUANTITY.deref(),);
        //todo: data root
        assert_eq!(tx_data.data_size, 1033478);
        assert_eq!(tx_data.data.as_ref().unwrap().len(), 1033478);
        //todo: verify data value
        assert_eq!(
            tx_data.reward.as_ref().unwrap(),
            &Reward::from(Winston::from_str("124145681682")?),
        );
        assert!(tx_data.has_data());
        assert!(!tx_data.has_external_payload());
        assert!(!tx_data.is_transfer());
        //todo: signature
        Ok(())
    }

    #[test]
    fn tx_data_ok_v2() -> anyhow::Result<()> {
        let tx_data = TxData::try_from_json_slice(TX_V2)?;
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
        assert_eq!(
            tx_data.signature.to_string(),
            "mJnhtXrtXMklRiPigOty7Q06ce8E9kdsRH4ww4IVVJ_YkYYfFGQXWoU-WZRsixvsEwjThUd6S8lvGetbzVszaGTplM7qxC4leUIn8gwj7cinvp3ABXzxsb9jPAwR5ytkzHuxJuSkwyUkVNXudamh5hG6d1OdXcBumcy9Sv66s29zCA7D6ptB1_d2DYxqIlXUpGH3EwVXNAoZXnmOicrlFKUPmZ-jOUXhNYmrHi3SwuJXVCAcDc7GXdN6Dbrt11iVvgp6Ag0h5fhCOZcUR2bhO0JK9QCP-xMic_97EY6JnGTp6GhOwZloIItkqEV9ZgPS787EvzOZOBH6Zk-bxk8WuWHP-0dU-LlA8DCAaTXZya01XBNA00mb5PKhaYk1ItH39ftcPXFVObrgxEU7SNdSdJnxy-eAKGIZYrTcN4mIuaRrC-CQyYSFPOee1MKlde4oKaE8NBtZsBvf3au9lnA-IYtQoHIhw5fo5kaLksp79ahpCC4Gc6ijrXeTvlgJnYaQ8q237YCeSwIUKHWMXHEAgjrPNaWyIVpn3mdbjbSRbpVKxxt7xNSkw4yz-8RPqI8bMMGpwS9CJKnRkcIeuAH6id2rgW57wPPMM6iHx2KxYF9AZx-4B4m7cO0TwUsaIL5DFYVdXYZXYC3fh3yG9uMSoH24oNgVlzuZG-NyyTT13oQ"
        );
        assert!(tx_data.target.is_none());
        assert_eq!(tx_data.quantity.as_ref().unwrap(), ZERO_QUANTITY.deref(),);
        //todo: data root
        assert_eq!(tx_data.data_size, 128355);
        assert!(tx_data.data.is_none());
        assert_eq!(
            tx_data.reward.as_ref().unwrap(),
            &Reward::from(Winston::from_str("557240107")?),
        );
        assert!(!tx_data.is_transfer());
        assert!(tx_data.has_data());
        assert!(tx_data.has_external_payload());
        //todo: signature
        Ok(())
    }

    #[test]
    fn tx_data_ok_transfer() -> anyhow::Result<()> {
        let tx_data = TxData::try_from_json_slice(TX_V2_2)?;
        assert_eq!(&tx_data.format, &Format::V2);
        assert_eq!(
            tx_data.id.to_string(),
            "oo6wzsvLtpGmOInBvyJ3ORjbhVelFEZKTOAy6wtjZtQ"
        );
        assert_eq!(
            tx_data.last_tx.to_string(),
            "mxi51DabflJu7YNcJSIm54cWjXDu69MAknQFuujhzDp7lEI7MT5zCufHlyhpq5lm"
        );
        assert_eq!(
            tx_data.quantity.as_ref(),
            Some(&Quantity::from(Winston::from_str("2199990000000000")?))
        );
        assert_eq!(
            tx_data.target.as_ref().unwrap().to_string(),
            "fGPsv2_-ueOvwFQF5zvYCRmawBGgc9FiDOXkbfurQtI"
        );
        assert!(tx_data.is_transfer());
        assert!(!tx_data.has_data());
        assert_eq!(
            tx_data.reward.as_ref(),
            Some(&Reward::from(Winston::from_str("6727794")?))
        );
        Ok(())
    }

    #[test]
    fn tx_v1_ok() -> anyhow::Result<()> {
        let tx = SignedTx::try_from_json_slice(TX_V1)?;
        assert_eq!(
            tx.id().to_string(),
            "BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ"
        );
        Ok(())
    }

    #[test]
    fn tx_v2_ok() -> anyhow::Result<()> {
        let tx = SignedTx::try_from_json_slice(TX_V2)?;
        assert_eq!(
            tx.id().to_string(),
            "bXGqzNQNmHTeL54cUQ6wPo-MO0thLP44FeAoM93kEwk"
        );
        Ok(())
    }

    #[test]
    fn tx_v2_mut_ok() -> anyhow::Result<()> {
        let mut tx = SignedTx::try_from_json_slice(TX_V2)?
            .try_make_mut()
            .unwrap();

        tx.quantity_mut()
            .replace(Quantity::from(Winston::from_str("100001")?));

        assert_eq!(
            tx.quantity().unwrap(),
            &Quantity::from(Winston::from_str("100001")?),
        );

        tx.reward_mut()
            .replace(Reward::from(Winston::from_str("20001")?));

        assert_eq!(
            tx.reward().unwrap(),
            &Reward::from(Winston::from_str("20001")?),
        );

        Ok(())
    }

    #[test]
    fn tx_v2_mut_err() -> anyhow::Result<()> {
        assert!(
            SignedTx::try_from_json_slice(TX_V1)?
                .try_make_mut()
                .is_err()
        );
        Ok(())
    }
}
