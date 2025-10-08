use crate::base64::OptionalBase64As;
use crate::blob::Blob;
use crate::crypto::hash::HashableExt;
use crate::crypto::hash::Sha256;
use crate::json::JsonSource;
use crate::tag::{Tag, TagName, TagValue};
use crate::tx::{Format, SignatureType};
use crate::typed::FromInner;
use crate::validation::SupportsValidation;
use crate::{Authenticated, AuthenticationState, JsonError, JsonValue, Unauthenticated};
use bigdecimal::{BigDecimal, Zero};
use serde::{Deserialize, Serialize};
use serde_with::NoneAsEmptyString;
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use serde_with::{DeserializeAs, DisplayFromStr, SerializeAs};
use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::LazyLock;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Hash)]
#[repr(transparent)]
pub(super) struct RawTx<'a, Auth: AuthenticationState = Unauthenticated>(
    RawTxData<'a>,
    PhantomData<Auth>,
);

impl<'a, Auth: AuthenticationState> RawTx<'a, Auth> {
    pub(super) fn as_inner(&self) -> &RawTxData<'a> {
        &self.0
    }

    pub(super) fn to_json_string(&self) -> Result<String, JsonError> {
        self.0.to_json_string()
    }

    pub(super) fn to_json(&self) -> Result<JsonValue, JsonError> {
        self.0.to_json()
    }
}

pub(super) type UnvalidatedRawTx<'a> = RawTx<'a, Unauthenticated>;
pub(super) type ValidatedRawTx<'a> = RawTx<'a, Authenticated>;

impl<'a> From<RawTxData<'a>> for UnvalidatedRawTx<'a> {
    fn from(value: RawTxData<'a>) -> Self {
        RawTx(value, PhantomData)
    }
}

impl<'a> From<ValidatedRawTx<'a>> for RawTxData<'a> {
    fn from(value: ValidatedRawTx<'a>) -> Self {
        value.0
    }
}

impl<'a, Auth: AuthenticationState> RawTx<'a, Auth> {
    /// Ensure the raw tx data is *actually* valid when calling this function in a `Authenticated` context
    pub(super) fn danger_from_raw_tx_data(data: RawTxData<'a>) -> Self {
        Self(data, PhantomData)
    }
}

impl<'a> ValidatedRawTx<'a> {
    pub(super) fn into_inner(self) -> RawTxData<'a> {
        self.0
    }
}

impl UnvalidatedRawTx<'static> {
    pub fn from_json<J: JsonSource>(json: J) -> Result<Self, JsonError> {
        let tx_data = RawTxData::from_json(json)?;
        Ok(Self(tx_data, PhantomData))
    }
}

impl<'a> UnvalidatedRawTx<'a> {
    fn is_valid(&self) -> Result<(), <Self as SupportsValidation>::Error> {
        const VALID_ID_LENGTHS: &[usize] = &[32];
        const VALID_LAST_TX_LENGTHS: &[usize] = &[32, 48];
        const VALID_OWNER_LENGTHS: &[usize] = &[256, 512];
        const MAX_TAGS_TOTAL_LEN: usize = 2048;
        const VALID_TARGET_LENGTHS: &[usize] = &[32];
        const MAX_EMBEDDED_DATA_LEN: usize = 1024 * 1024 * 12;
        const VALID_SIG_LENGTHS: &[usize] = &[
            65,  // Secp256k1
            256, // Rsa<2048>
            512, // Rsa<4096>
        ];
        const VALID_DATA_ROOT_LENGTHS: &[usize] = &[32];

        validate_byte_len(self.0.id.bytes(), VALID_ID_LENGTHS, "id")?;
        validate_byte_len(self.0.last_tx.bytes(), VALID_LAST_TX_LENGTHS, "last_tx")?;

        if let Some(owner) = &self.0.owner {
            validate_byte_len(owner.bytes(), VALID_OWNER_LENGTHS, "owner")?;
        }

        if self.0.tags_byte_len() > MAX_TAGS_TOTAL_LEN {
            return Err(RawTxDataError::TagsMaxLenExceeded {
                max: MAX_TAGS_TOTAL_LEN,
                actual: self.0.tags_byte_len(),
            });
        }

        if let Some(target) = &self.0.target {
            validate_byte_len(target.bytes(), VALID_TARGET_LENGTHS, "target")?;
        }

        if let Some(data) = &self.0.data {
            if data.len() > MAX_EMBEDDED_DATA_LEN {
                return Err(RawTxDataError::EmbeddedDataMaxLenExceeded {
                    max: MAX_EMBEDDED_DATA_LEN,
                    actual: data.len(),
                });
            }
        }

        validate_byte_len(self.0.signature.bytes(), VALID_SIG_LENGTHS, "signature")?;

        if let Some(data_root) = &self.0.data_root {
            validate_byte_len(data_root.bytes(), VALID_DATA_ROOT_LENGTHS, "data_root")?;
        }

        let mut positive_quantity = false;
        if let Some(quantity) = &self.0.quantity {
            validate_positive_integer(quantity, "quantity")?;

            if quantity != ZERO_BD.deref() {
                if self.0.target.is_none() {
                    return Err(RawTxDataError::MissingTarget);
                }
                positive_quantity = true;
            }
        }

        validate_positive_integer(&self.0.reward, "reward")?;

        if self.0.target.is_some() {
            if !positive_quantity {
                return Err(RawTxDataError::MissingQuantity);
            }
        }

        let expected_tx_id = self.0.signature.bytes().digest::<Sha256>();
        if expected_tx_id.as_slice() != self.0.id.bytes() {
            return Err(RawTxDataError::IdSignatureMismatch);
        }

        Ok(())
    }
}

impl<'a> SupportsValidation for UnvalidatedRawTx<'a> {
    type Validated = ValidatedRawTx<'a>;
    type Error = RawTxDataError;
    type Reference<'r> = ();

    fn validate_with(
        self,
        _: &Self::Reference<'_>,
    ) -> Result<Self::Validated, (Self, Self::Error)> {
        if let Err(err) = self.is_valid() {
            return Err((self, err));
        }
        Ok(RawTx(self.0, PhantomData))
    }
}

#[derive(Error, Debug)]
pub enum RawTxError {
    #[error(transparent)]
    JsonError(#[from] JsonError),
    #[error(transparent)]
    DataError(#[from] RawTxDataError),
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Hash)]
pub(super) struct RawTag<'a> {
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub name: Blob<'a>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub value: Blob<'a>,
}

impl<'a> RawTag<'a> {
    fn byte_len(&self) -> usize {
        self.name.len() + self.value.len()
    }
}

impl<'a> From<RawTag<'a>> for Tag<'a> {
    fn from(raw: RawTag<'a>) -> Self {
        Self {
            name: TagName::from_inner(raw.name),
            value: TagValue::from_inner(raw.value),
        }
    }
}

impl<'a> From<Tag<'a>> for RawTag<'a> {
    fn from(value: Tag<'a>) -> Self {
        Self {
            name: value.name.into_inner(),
            value: value.value.into_inner(),
        }
    }
}

// This follows the definition found here:
// https://docs.arweave.org/developers/arweave-node-server/http-api#field-definitions
#[serde_as]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Hash)]
pub(super) struct RawTxData<'a> {
    pub format: Format,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub id: Blob<'a>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub last_tx: Blob<'a>,
    #[serde_as(as = "NoneIfDefault")]
    #[serde(default, skip_serializing_if = "is_none_or_default")]
    pub denomination: Option<u32>,
    #[serde_as(as = "OptionalBase64As")]
    #[serde(default)]
    pub owner: Option<Blob<'a>>,
    #[serde(default)]
    pub tags: Vec<RawTag<'a>>,
    #[serde_as(as = "OptionalBase64As")]
    #[serde(default)]
    pub target: Option<Blob<'a>>,
    #[serde_as(as = "NoneAsEmptyString")]
    #[serde(default)]
    pub quantity: Option<BigDecimal>,
    #[serde(default)]
    pub data_tree: Vec<JsonValue>,
    #[serde_as(as = "OptionalBase64As")]
    #[serde(default)]
    pub data_root: Option<Blob<'a>>,
    #[serde_as(as = "DisplayFromStr")]
    pub data_size: u64,
    #[serde_as(as = "OptionalBase64As")]
    #[serde(default)]
    pub data: Option<Blob<'a>>,
    pub reward: BigDecimal,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub signature: Blob<'a>,
    #[serde_as(as = "NoneIfDefault")]
    #[serde(default, skip_serializing_if = "is_none_or_default")]
    pub signature_type: Option<SignatureType>,
}

fn is_none_or_default<T: Default + PartialEq>(value: &Option<T>) -> bool {
    value.as_ref().map(|v| v == &(T::default())).unwrap_or(true)
}

struct NoneIfDefault;

impl<T> SerializeAs<Option<T>> for NoneIfDefault
where
    T: Default + PartialEq + Display,
{
    fn serialize_as<S>(source: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match source {
            Some(value) if value != &T::default() => Some(value.to_string()).serialize(serializer),
            _ => None::<String>.serialize(serializer),
        }
    }
}

impl<'de, T> DeserializeAs<'de, Option<T>> for NoneIfDefault
where
    T: Default + PartialEq + FromStr,
    <T as FromStr>::Err: Display,
{
    fn deserialize_as<D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?
            .map(|s| T::from_str(s.as_str()))
            .transpose()
            .map_err(serde::de::Error::custom)?;
        Ok(value.filter(|v| v != &T::default()))
    }
}

impl<'a> RawTxData<'a> {
    fn tags_byte_len(&self) -> usize {
        self.tags.iter().map(|t| t.byte_len()).sum()
    }

    fn to_json_string(&self) -> Result<String, JsonError> {
        serde_json::to_string_pretty(self)
    }

    fn to_json(&self) -> Result<JsonValue, JsonError> {
        serde_json::to_value(self)
    }
}

impl RawTxData<'static> {
    fn from_json<J: JsonSource>(json: J) -> Result<Self, JsonError> {
        serde_json::from_value(json.try_into_json()?)
    }
}

#[derive(Error, Debug)]
pub enum RawTxDataError {
    #[error(
        "Invalid data length found for field '{field}': actual length in bytes '{actual}', valid options: '{valid:?}'"
    )]
    InvalidDataLen {
        field: &'static str,
        actual: usize,
        valid: &'static [usize],
    },
    #[error("maximum total tag length exceeded: '{actual}' byte > '{max}' byte")]
    TagsMaxLenExceeded { max: usize, actual: usize },
    #[error("maximum embedded data length exceeded: '{actual}' > '{max}' byte")]
    EmbeddedDataMaxLenExceeded { max: usize, actual: usize },
    #[error("non-integer number found in field '{field}', invalid value: '{value}'")]
    NonIntegerNumber { field: &'static str, value: String },
    #[error("negative number found in field '{field}', invalid value: '{value}'")]
    NegativeNumber { field: &'static str, value: String },
    #[error("quantity is missing but mandatory for this tx")]
    MissingQuantity,
    #[error("target is missing but mandatory for this tx")]
    MissingTarget,
    #[error("tx id does not match the signature")]
    IdSignatureMismatch,
}

static ZERO_BD: LazyLock<BigDecimal> = LazyLock::new(|| BigDecimal::zero());

fn validate_positive_integer(
    number: &BigDecimal,
    field: &'static str,
) -> Result<(), RawTxDataError> {
    if number.fractional_digit_count() > 0 {
        return Err(RawTxDataError::NonIntegerNumber {
            field,
            value: number.to_plain_string(),
        });
    }

    if number < ZERO_BD.deref() {
        return Err(RawTxDataError::NegativeNumber {
            field,
            value: number.to_plain_string(),
        });
    }

    Ok(())
}

fn validate_byte_len(
    bytes: &[u8],
    valid: &'static [usize],
    field: &'static str,
) -> Result<(), RawTxDataError> {
    let len = bytes.len();
    if !valid.contains(&len) {
        return Err(RawTxDataError::InvalidDataLen {
            field,
            actual: len,
            valid,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::tx::Format;
    use crate::tx::raw::{RawTxData, UnvalidatedRawTx};
    use crate::validation::ValidateExt;
    use bigdecimal::BigDecimal;
    use std::str::FromStr;

    static TX_V1: &'static [u8] = include_bytes!("../../testdata/tx_v1.json");
    static TX_V2: &'static [u8] = include_bytes!("../../testdata/tx_v2.json");
    static TX_V2_2: &'static [u8] = include_bytes!("../../testdata/tx_v2_2.json");
    static TX_V2_3: &'static [u8] = include_bytes!("../../testdata/tx_v2_3.json");

    static ALL: &'static [&'static [u8]] = &[TX_V1, TX_V2, TX_V2_2, TX_V2_3];

    #[test]
    fn basic_deser_all() -> anyhow::Result<()> {
        for tx in ALL {
            let tx = RawTxData::from_json(*tx)?;
            let str = tx.to_json_string()?;
            let tx2 = RawTxData::from_json(&str)?;
            assert_eq!(tx2, tx);
        }
        Ok(())
    }

    #[test]
    fn check_v1() -> anyhow::Result<()> {
        let tx = RawTxData::from_json(TX_V1)?;
        assert_eq!(tx.format, Format::V1);
        assert_eq!(tx.quantity, Some(BigDecimal::from(0)));
        assert_eq!(tx.data_size, 1033478);
        assert_eq!(tx.reward, BigDecimal::from_str("124145681682")?);
        assert!(tx.data.is_some());
        assert_eq!(tx.data.as_ref().unwrap().len() as u64, tx.data_size);
        assert_eq!(tx.tags.len(), 0);
        assert_eq!(tx.owner.as_ref().unwrap().len(), 512);
        assert_eq!(tx.signature.len(), 512);
        assert!(tx.target.is_none());
        Ok(())
    }

    #[test]
    fn check_v2() -> anyhow::Result<()> {
        let tx = RawTxData::from_json(TX_V2)?;
        assert_eq!(tx.format, Format::V2);
        assert_eq!(tx.quantity, Some(BigDecimal::from(0)));
        assert_eq!(tx.data_size, 128355);
        assert_eq!(tx.reward, BigDecimal::from_str("557240107")?);
        assert!(tx.data.is_none());
        assert_eq!(tx.tags.len(), 6);
        assert_eq!(tx.owner.as_ref().unwrap().len(), 512);
        assert_eq!(tx.signature.len(), 512);
        assert!(tx.target.is_none());
        Ok(())
    }

    #[test]
    fn check_v2_3() -> anyhow::Result<()> {
        let tx = RawTxData::from_json(TX_V2_3)?;
        assert_eq!(tx.format, Format::V2);
        assert_eq!(tx.quantity, Some(BigDecimal::from(100000)));
        assert_eq!(tx.data_size, 0);
        assert_eq!(tx.reward, BigDecimal::from(600912));
        assert!(tx.data.is_none());
        assert_eq!(tx.tags.len(), 1);
        assert_eq!(tx.owner.as_ref().unwrap().len(), 256);
        assert_eq!(tx.signature.len(), 256);
        assert!(tx.target.is_some());
        Ok(())
    }

    #[test]
    fn validate_all() -> anyhow::Result<()> {
        for tx in ALL {
            let unvalidated = UnvalidatedRawTx::from_json(*tx)?;
            let validated = unvalidated.validate().map_err(|(_, err)| err)?;
            let _raw: RawTxData = validated.into();
        }
        Ok(())
    }
}
