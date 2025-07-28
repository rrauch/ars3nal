mod raw;
mod v1;

use crate::JsonError;
use crate::base64::ToBase64;
use crate::blob::{AsBlob, Blob, TypedBlob};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, HasherExt, TypedDigest};
use crate::crypto::hash::{Sha256, Sha384};
use crate::crypto::rsa::{Rsa4096, RsaPss, RsaPublicKey};
use crate::crypto::signature::{Signature, TypedSignature};
use crate::money::{Money, TypedMoney, Winston};
use crate::tx::raw::RawTag;
use crate::typed::{FromInner, Typed};
use crate::wallet::{
    Wallet, WalletAddress, WalletKind, WalletPKey, WalletPublicKey, WalletSecretKey,
};
use derive_where::derive_where;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::sync::LazyLock;
use thiserror::Error;

const MAX_TX_DATA_LEN: usize = 1024 * 1024 * 12;

static ZERO_QUANTITY: LazyLock<Quantity> = LazyLock::new(|| Quantity::zero());
static ZERO_REWARD: LazyLock<Reward> = LazyLock::new(|| Reward::zero());

pub struct TxKind;

pub type TxId = TypedDigest<TxSignature, Sha256>;

impl Display for TxId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64().as_str())
    }
}

pub type TxSignature = TypedSignature<TxHash, WalletKind, RsaPss<Rsa4096>>;
pub type TxHash = TypedDigest<TxKind, Sha384>;

impl TxSignature {
    pub fn digest(&self) -> TxId {
        TxId::from_inner(Sha256::digest(self.as_blob()))
    }
}

pub struct TxAnchorKind;
pub type TxAnchor = Typed<TxAnchorKind, [u8; 48]>;

impl Display for TxAnchor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_base64().as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LastTx {
    V1(TxId),
    V2(TxAnchor),
}

impl<'a> TryFrom<Blob<'a>> for LastTx {
    type Error =
        LastTxError<<TxId as TryFrom<Blob<'a>>>::Error, <TxAnchor as TryFrom<Blob<'a>>>::Error>;

    fn try_from(value: Blob<'a>) -> Result<Self, Self::Error> {
        match value.len() {
            32 => Ok(Self::V1(
                TxId::try_from(value).map_err(LastTxError::V1Error)?,
            )),
            48 => Ok(Self::V2(
                TxAnchor::try_from(value).map_err(LastTxError::V2Error)?,
            )),
            invalid => Err(LastTxError::InvalidLength(invalid)),
        }
    }
}

impl Display for LastTx {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1(tx_id) => Display::fmt(tx_id, f),
            Self::V2(tx_anchor) => Display::fmt(tx_anchor, f),
        }
    }
}

impl DeepHashable for LastTx {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        match self {
            Self::V1(tx_id) => tx_id.deep_hash(),
            Self::V2(tx_anchor) => tx_anchor.deep_hash(),
        }
    }
}

impl Hashable for LastTx {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        match self {
            Self::V1(tx_id) => tx_id.feed(hasher),
            Self::V2(tx_anchor) => tx_anchor.feed(hasher),
        }
    }
}

impl AsRef<[u8]> for LastTx {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::V1(tx_id) => tx_id.as_slice(),
            Self::V2(tx_anchor) => tx_anchor.as_slice(),
        }
    }
}

impl AsBlob for LastTx {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::V1(tx_id) => tx_id.as_blob(),
            Self::V2(tx_anchor) => tx_anchor.as_blob(),
        }
    }
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

#[derive(Debug, Clone, Serialize_repr, Deserialize_repr, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Format {
    V1 = 1,
    V2 = 2,
}

impl Format {
    fn as_u8(&self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }
}

impl Display for Format {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_u8())
    }
}

impl DeepHashable for Format {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(match self {
            Self::V1 => b"1",
            Self::V2 => b"2",
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tag<'a> {
    pub name: TagName<'a>,
    pub value: TagValue<'a>,
}

impl<'a> From<RawTag<'a>> for Tag<'a> {
    fn from(raw: RawTag<'a>) -> Self {
        Self {
            name: TagName::from_inner(raw.name),
            value: TagValue::from_inner(raw.value),
        }
    }
}

impl DeepHashable for Tag<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::list(vec![self.name.deep_hash(), self.value.deep_hash()])
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    TxDataError(#[from] TxDataError),
}

#[derive(Error, Debug)]
pub enum TxDataError {
    #[error(transparent)]
    JsonError(#[from] JsonError),
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
    #[error("tx signature not valid")]
    SignatureError,
}

// This follows the definition found here:
// https://docs.arweave.org/developers/arweave-node-server/http-api#field-definitions
#[derive(Debug, Clone)]
pub(crate) struct TxData<'a> {
    format: Format,
    id: TxId,
    last_tx: LastTx,
    owner: WalletPKey<RsaPublicKey<Rsa4096>>,
    tags: Vec<Tag<'a>>,
    //#[serde(with = "empty_string_none")]
    target: Option<WalletAddress>,
    //#[serde(default)]
    //#[serde(with = "empty_string_none")]
    quantity: Option<Quantity>,
    data_tree: Vec<String>, // todo
    //#[serde(default)]
    //#[serde(with = "empty_string_none")]
    data_root: Option<String>, // todo: Merkle Root
    //#[serde(with = "string_number")]
    data_size: u64,
    //#[serde(with = "empty_string_none")]
    data: Option<EmbeddedData<'a>>,
    //#[serde(with = "empty_string_none")]
    reward: Option<Reward>,
    signature: TxSignature,
}

impl<'a> TxData<'a> {
    pub(crate) fn try_from_json_slice(bytes: &[u8]) -> Result<Self, TxDataError> {
        let tx_data = Self::try_from_json_slice_unvalidated(bytes)?;
        //tx_data.is_valid()?;
        Ok(tx_data)
    }

    fn try_from_json_slice_unvalidated(bytes: &[u8]) -> Result<Self, TxDataError> {
        //let tx_data: TxData = serde_json::from_slice(bytes)?;
        //Ok(tx_data)
        todo!()
    }

    pub(crate) fn verify_signature<PK: WalletPublicKey>(
        &self,
        pkey: &WalletPKey<PK>,
    ) -> Result<(), TxDataError> {
        let digest = TxHash::from_inner(self.deep_hash());
        /*Ok(pkey
        .verify_signature(digest.as_slice(), &self.signature)
        .map_err(|_e| TxDataError::SignatureError)?)*/
        todo!()
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

impl DeepHashable for TxData<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        match self.format {
            Format::V1 => {
                /*self.owner.feed_stringified(hasher);
                if let Some(target) = &self.target {
                    target.feed_stringified(hasher);
                } else {
                    hasher.update(b"");
                }
                if let Some(data) = &self.data {
                    let b64 = Base64Stringify::<UrlSafeNoPadding>::to_str(data.deref());
                    hasher.update(b64.into().as_bytes());
                    //data.feed(b64.into().as_bytes());
                } else {
                    hasher.update(b"");
                }
                if let Some(quantity) = &self.quantity {
                    quantity.feed_stringified(hasher);
                } else {
                    hasher.update(b"");
                }
                if let Some(reward) = &self.reward {
                    reward.feed_stringified(hasher);
                } else {
                    hasher.update(b"");
                }
                self.last_tx.feed_stringified(hasher);*/
                todo!()
            }
            Format::V2 => Self::list([
                self.format.deep_hash(),
                self.owner.deep_hash(),
                self.target.deep_hash(),
                self.quantity.deep_hash(),
                self.reward.deep_hash(),
                self.last_tx.deep_hash(),
                self.tags.deep_hash(),
                self.data_size.to_string().deep_hash(),
                self.data_root.deep_hash(),
            ]),
        }
    }
}

/*impl Valid for TxData {
    type Error = TxDataError;

    fn is_valid(&self) -> Result<(), Self::Error> {
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

        //self.verify_signature(&self.owner)?;

        Ok(())
    }
}*/

pub struct TagNameKind;
pub type TagName<'a> = TypedBlob<'a, TagNameKind>;

pub struct TagValueKind;
pub type TagValue<'a> = TypedBlob<'a, TagValueKind>;

pub struct EmbeddedDataKind;
pub type EmbeddedData<'a> = TypedBlob<'a, EmbeddedDataKind>;

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

pub type V1Tx<'a, S> = TxImpl<'a, S, V1>;
pub type V2Tx<'a, S> = TxImpl<'a, S, V2>;

#[derive(Error, Debug)]
pub enum TxError {
    #[error(transparent)]
    DataError(#[from] TxDataError),
    #[error(transparent)]
    SigningError(#[from] SigningError),
}

#[derive_where(Debug, Clone)]
pub enum Tx<'a, S> {
    V1(V1Tx<'a, S>),
    V2(V2Tx<'a, S>),
}

impl<'a, S> Tx<'a, S> {
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

impl<'a> SignedTx<'a> {
    pub fn try_from_json_slice(bytes: &[u8]) -> Result<Self, TxError> {
        let tx_data = TxData::try_from_json_slice(bytes)?;
        Ok(match tx_data.format {
            Format::V1 => Self::V1(TxImpl::new(tx_data)),
            Format::V2 => Self::V2(TxImpl::new(tx_data)),
        })
    }

    pub fn try_make_mut(self) -> Result<UnsignedTx<'a>, (Self, EditError)> {
        match self {
            Self::V1(v1) => Err((v1.into(), EditError::V1Unsupported)),
            Self::V2(v2) => todo!(),
        }
    }
}

impl<'a> UnsignedTx<'a> {
    pub(crate) fn sign<SK: WalletSecretKey>(
        self,
        wallet: &Wallet<SK>,
    ) -> Result<SignedTx, (Self, SigningError)> {
        match self {
            Self::V1(v1) => Err((v1.into(), SigningError::V1Unsupported)),
            Self::V2(v2) => Ok(v2
                .sign(wallet)
                .map_err(|(inner, e)| (inner.into(), e))?
                .into()),
        }
    }

    pub fn tags_mut(&'a mut self) -> &'a mut Vec<Tag<'a>> {
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

impl<'a, S> From<TxImpl<'a, S, V1>> for Tx<'a, S> {
    fn from(value: TxImpl<'a, S, V1>) -> Self {
        Self::V1(value)
    }
}

impl<'a, S> From<TxImpl<'a, S, V2>> for Tx<'a, S> {
    fn from(value: TxImpl<'a, S, V2>) -> Self {
        Self::V2(value)
    }
}

pub type SignedTx<'a> = Tx<'a, Signed>;
pub type UnsignedTx<'a> = Tx<'a, Unsigned>;

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
pub struct TxImpl<'a, S, V>(TxData<'a>, PhantomData<(S, V)>);

impl<'a, S, V> TxImpl<'a, S, V> {
    fn new(inner: TxData<'a>) -> Self {
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

impl<'a, V> TxImpl<'a, Unsigned, V> {
    pub fn tags_mut(&'a mut self) -> &'a mut Vec<Tag<'a>> {
        self.0.tags.as_mut()
    }

    pub fn quantity_mut(&mut self) -> &mut Option<Quantity> {
        &mut self.0.quantity
    }

    pub fn reward_mut(&mut self) -> &mut Option<Reward> {
        &mut self.0.reward
    }
}

impl<'a, S> TxImpl<'a, S, V1> {
    pub fn last_tx(&self) -> &TxId {
        if let LastTx::V1(tx_id) = &self.0.last_tx {
            tx_id
        } else {
            unreachable!()
        }
    }
}

impl<'a, S> TxImpl<'a, S, V2> {
    pub fn last_tx(&self) -> &TxAnchor {
        if let LastTx::V2(tx_anchor) = &self.0.last_tx {
            tx_anchor
        } else {
            unreachable!()
        }
    }
}

impl<'a> TxImpl<'a, Unsigned, V2> {
    fn sign<SK: WalletSecretKey>(
        self,
        _wallet: &Wallet<SK>,
    ) -> Result<TxImpl<Signed, V2>, (Self, SigningError)> {
        // tx signing happens here
        todo!()
    }

    pub fn set_last_tx(&mut self, anchor: TxAnchor) {
        self.0.last_tx = LastTx::V2(anchor);
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::money::{CurrencyExt, Winston};
    use crate::tx::{Format, Quantity, Reward, SignedTx, TxData, ZERO_QUANTITY};
    use std::ops::Deref;

    static TX_V1: &'static [u8] = include_bytes!("../../testdata/tx_v1.json");
    static TX_V2: &'static [u8] = include_bytes!("../../testdata/tx_v2.json");
    static TX_V2_2: &'static [u8] = include_bytes!("../../testdata/tx_v2_2.json");
    static TX_V2_3: &'static [u8] = include_bytes!("../../testdata/tx_v2_3.json");

    #[test]
    fn tx_data_ok_v1() -> anyhow::Result<()> {
        let tx_data = TxData::try_from_json_slice(TX_V1)?;
        assert_eq!(&tx_data.format, &Format::V1);
        assert_eq!(
            tx_data.id.to_base64(),
            "BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ"
        );
        assert_eq!(
            tx_data.last_tx.to_base64(),
            "jUcuEDZQy2fC6T3fHnGfYsw0D0Zl4NfuaXfwBOLiQtA"
        );
        assert_eq!(
            tx_data.owner.to_base64(),
            "posmEh5k2_h7fgj-0JwB2l2AU72u-UizJOA2m8gyYYcVjh_6N3A3DhwbLmnbIWjVWmsidgQZDDibiJhhyHsy28ARxrt5BJ3OCa1VRAk2ffhbaUaGUoIkVt6G8mnnTScN9JNPS7UYEqG_L8J48c2tQNsydbon2ImKIwCYmnMHKcpyEgXcgLDGhtGhIKtkuI-QOAu-TMqVjn5EaWsfJTW5J-ty8mswAMSxepgsUbUB3GXZfCyOAK0EGjrClZ1MLvyc8ANGQfLPjwTipMcUtX47Udy8i4C-c-vLC9oB_z5ZCDCat-5wGh2OA-lyghro2SpkxX0e-D-nbi91Pp9LORwDZIRQ5RCMDvtQx1-QD2adxn_P2zDN0hk5IWXoCnHyeoj-IdNIyCXNkDzT2A184CxjReE5XOUF7UFeOmvVwbUTMfnNBOSWeRz3U_e3MPNlc2JTIprRLC8IegyfS6NdCr90lYnuviEr0g75NE6-muJdHAd9gu2QZ1MpkX9OnsbtvCvvFje-K_p_4AR9l43CLemfdSZeHHMIzdPwKe75SFMbsuklsyc-ieq-OHrJCeL0WrkLT4Gf6rpGVkS8MjORuMOBRFrHRE7XKswzhwmV2SuzeU6ojtPNP87aNdiUGHtYCIyt7cRN5bRbrVjdCAXj2NnuWMzM6J6dme4e2R8gqNpsEok"
        );
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
            tx_data.id.to_base64(),
            "bXGqzNQNmHTeL54cUQ6wPo-MO0thLP44FeAoM93kEwk"
        );
        assert_eq!(
            tx_data.last_tx.to_base64(),
            "gVhey9KN6Fjc3nZbSOqLPRyDjjw6O5-sLSWPLZ_S7LoX5XOrFRja8A_wuj22OpHj"
        );
        assert_eq!(
            tx_data.owner.to_base64(),
            "vzDBBpa9EsQR-6un6K9hgJuCJ7wtuZjuCmGEP6bHdrOln2gYkokWNgXSu35CThS68VtlwceUxOxNLM8VjsS-by7SSq0M0GzcCEAGUjEHXB1Ni32srWQKY-uJNRgfGMTS9Xs2RGIlmZpMR2PHl3EsLTuWAYjKzl3tv0YxIdHxm3hmlWsmhqIiNCoIfEQ_chxK3nL5vdfgNkV1zhdfH-yssTY3hXNa_lpCDQLoThM1xUNrzC7DKB6fvGS52REMgHg-QAlWIvXyGsZH5qRf_Ib_lOHn2v9Wjoh7QKPpMe7VYFOQXsfzFsAAjHQIm9SmuOrN_YhK9FpsjwVo1mKEFgpN52t5yGr5Ogp2CpmCfqn0i4hmaSwHB8XL86bGdZpbWbx_TRUf8xRgQjZD7zr5EAgWc07AFVsIdd_zLOgD9cS6RQ4bGaao2it-PTF7_J2rH1vXHJrJ7_SsUy9VF_Nj0LA0PuMPPgz6QcokKboxDeRPTVkj3fCIrx1LloAKGC8LcW9-cUUheG5ZSmzxG7r5pTotXAsyM6tfT9zMLvCexrdUKuOrUPJIvAhR3q9ntx9wefCz_1f2NEHlyZHUbx2l_r8UGFQjgjB5F9wjo5ho54Q8Iqk_JDSphSOJQRO7YezJpi6UDdhfaPHQpsCRxOMpKHQAVvetMc5ADDL7hzfCPYTAMtU"
        );
        assert_eq!(
            tx_data.signature.to_base64(),
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

        assert_eq!(tx_data.tags.len(), 6);
        assert_eq!(
            tx_data.tags.get(0).unwrap().name.bytes(),
            "App-Name".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(0).unwrap().value.bytes(),
            "trackmycontainer.io".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(1).unwrap().name.bytes(),
            "Application".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(1).unwrap().value.bytes(),
            "Traxa.io".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(2).unwrap().name.bytes(),
            "Content-Type".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(2).unwrap().value.bytes(),
            "image/jpeg".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(3).unwrap().name.bytes(),
            "Modified".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(3).unwrap().value.bytes(),
            "1753107957".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(4).unwrap().name.bytes(),
            "Shipping-Container-GPS".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(4).unwrap().value.bytes(),
            "(40.7549755075, -112.0129563668)".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(5).unwrap().name.bytes(),
            "Shipping-Container-IDs".as_bytes()
        );
        assert_eq!(
            tx_data.tags.get(5).unwrap().value.bytes(),
            "SEGU4454314".as_bytes()
        );

        //todo: signature
        Ok(())
    }

    #[test]
    fn tx_data_ok_transfer() -> anyhow::Result<()> {
        let tx_data = TxData::try_from_json_slice(TX_V2_2)?;
        assert_eq!(&tx_data.format, &Format::V2);
        assert_eq!(
            tx_data.id.to_base64(),
            "oo6wzsvLtpGmOInBvyJ3ORjbhVelFEZKTOAy6wtjZtQ"
        );
        assert_eq!(
            tx_data.last_tx.to_base64(),
            "mxi51DabflJu7YNcJSIm54cWjXDu69MAknQFuujhzDp7lEI7MT5zCufHlyhpq5lm"
        );
        assert_eq!(
            tx_data.owner.to_base64(),
            "sucQ9eqnKFLIGCMi2n6b0hOVf1oL2JegiAyfPRRlTmZKvbQAZT8PELVimfdX9nVxUo7nTEXc9mPhtBJc_g4xTVKXrpe5nEYR2MMZcGIqo4rZb6ZJyAOSws-UclOKLgBP9jWUo04OOMS4_oe-gJ8ZvtKNCnpbgW11qWG7kLGb9kRTNGd-H3O5i6Cu3bCNFFNstdqAZ8yWHNXLiGU2uayWSSVp_mLNRQ9fb84GdXEJwzPVBNJgq9UgL4wcs8EvEQzIpSWF55jG1ld3Yqo5rSeReKnTDqxRqTPziYU49GvCiQA6jzzt42_-GriRU7StkBoQ1_NXQNPFcOPLCGXRVK6hrJLDYM4Pt6p_re-J68MbCJ5TYB7W0E9CpxYv1R2Y7ZsMFdlfRR52ZDuljd1-p6GLoWAXEner4cxEEVYZHF_Okq1tSFT0aVix1y646uAFObuaaSJn5xncdi-B8Xx3DUUJZ6GxSjoW-8_-68QdC0g4TzgEjY1AT-gS-V1KGm5Pi5Lk1k7xVcIcW8HF-m6DBDXoVK4WSJSRRReWeRRfmDCHQ_5wina5SVxmU1eqellOT1XIbCpI8L5BSm9RLTgeMKFbzVvuXYfNuUfQfn446VcP2zOXBSmR5zcHYkFsa18eHXlWJcOyFDu6cZwZA77LKGYoFkago-d9S5eBRGOYrV-kwhU",
        );
        assert_eq!(
            tx_data.quantity.as_ref(),
            Some(&Quantity::from(Winston::from_str("2199990000000000")?))
        );
        assert_eq!(
            tx_data.target.as_ref().unwrap().to_base64(),
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
            tx.id().to_base64(),
            "BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ"
        );
        Ok(())
    }

    #[test]
    fn tx_v2_ok() -> anyhow::Result<()> {
        let tx = SignedTx::try_from_json_slice(TX_V2)?;
        assert_eq!(
            tx.id().to_base64(),
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
    fn tx_v1_mut_err() -> anyhow::Result<()> {
        assert!(
            SignedTx::try_from_json_slice(TX_V1)?
                .try_make_mut()
                .is_err()
        );
        Ok(())
    }

    /*#[test]
    fn tx_hash_ok() -> anyhow::Result<()> {
        let tx_data = TxData::try_from_json_slice_unvalidated(TX_V2_3)?;
        let deep_digest = tx_data.deep_hash::<Sha384Hasher>();
        let deep_digest = deep_digest.as_slice();

        let expected: [u8; 48] = [
            74, 15, 74, 255, 248, 205, 47, 229, 107, 195, 69, 76, 215, 249, 34, 186, 197, 31, 178,
            163, 72, 54, 78, 179, 19, 178, 1, 132, 183, 231, 131, 213, 146, 203, 6, 99, 106, 231,
            215, 199, 181, 171, 52, 255, 205, 55, 203, 117,
        ];

        assert_eq!(deep_digest, &expected);
        Ok(())
    }*/
}
