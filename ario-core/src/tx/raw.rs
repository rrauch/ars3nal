use crate::base64::OptionalBase64As;
use crate::blob::Blob;
use crate::crypto::hash::HashableExt;
use crate::crypto::hash::Sha256Hasher;
use crate::json::JsonSource;
use crate::tx::Format;
use crate::validation::{SupportsValidation, Valid, Validator};
use crate::{JsonError, JsonValue};
use bigdecimal::{BigDecimal, Zero};
use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;
use serde_with::NoneAsEmptyString;
use serde_with::base64::Base64;
use serde_with::base64::UrlSafe;
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use std::ops::Deref;
use std::sync::LazyLock;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub(super) struct RawTx<'a, const VALIDATED: bool = false>(RawTxData<'a>);

pub(super) type UnvalidatedRawTx<'a> = RawTx<'a, false>;
pub(super) type ValidatedRawTx<'a> = RawTx<'a, true>;

impl<'a> From<RawTxData<'a>> for UnvalidatedRawTx<'a> {
    fn from(value: RawTxData<'a>) -> Self {
        RawTx(value)
    }
}

impl<'a> From<ValidatedRawTx<'a>> for RawTxData<'a> {
    fn from(value: ValidatedRawTx<'a>) -> Self {
        value.0
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
        Ok(Self(tx_data))
    }
}

impl<'a> SupportsValidation for UnvalidatedRawTx<'a> {
    type Unvalidated = RawTxData<'a>;
    type Validated = ValidatedRawTx<'a>;
    type Validator = RawTxDataValidator;

    fn into_valid(self, _token: Valid<Self>) -> Self::Validated
    where
        Self: Sized,
    {
        RawTx(self.0)
    }

    fn as_unvalidated(&self) -> &Self::Unvalidated {
        &self.0
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
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
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

// This follows the definition found here:
// https://docs.arweave.org/developers/arweave-node-server/http-api#field-definitions
#[serde_as]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub(super) struct RawTxData<'a> {
    pub format: Format,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub id: Blob<'a>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub last_tx: Blob<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denomination: Option<JsonValue>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<JsonValue>,
}

impl<'a> RawTxData<'a> {
    fn tags_byte_len(&self) -> usize {
        self.tags.iter().map(|t| t.byte_len()).sum()
    }

    pub fn to_json_string(&self) -> Result<String, JsonError> {
        serde_json::to_string_pretty(self)
    }

    pub fn into_json(self) -> Result<JsonValue, JsonError> {
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

pub struct RawTxDataValidator;

impl Validator<RawTxData<'_>> for RawTxDataValidator {
    type Error = RawTxDataError;

    fn validate(data: &RawTxData) -> Result<(), Self::Error> {
        const VALID_ID_LENGTHS: &[usize] = &[32];
        const VALID_LAST_TX_LENGTHS: &[usize] = &[32, 48];
        const VALID_OWNER_LENGTHS: &[usize] = &[256, 512];
        const MAX_TAGS_TOTAL_LEN: usize = 2048;
        const VALID_TARGET_LENGTHS: &[usize] = &[32];
        const MAX_EMBEDDED_DATA_LEN: usize = 1024 * 1024 * 12;
        const VALID_SIG_LENGTHS: &[usize] = &[256, 512];
        const VALID_DATA_ROOT_LENGTHS: &[usize] = &[32];

        validate_byte_len(data.id.bytes(), VALID_ID_LENGTHS, "id")?;
        validate_byte_len(data.last_tx.bytes(), VALID_LAST_TX_LENGTHS, "last_tx")?;

        if let Some(owner) = &data.owner {
            validate_byte_len(owner.bytes(), VALID_OWNER_LENGTHS, "owner")?;
        }

        if data.tags_byte_len() > MAX_TAGS_TOTAL_LEN {
            return Err(RawTxDataError::TagsMaxLenExceeded {
                max: MAX_TAGS_TOTAL_LEN,
                actual: data.tags_byte_len(),
            });
        }

        if let Some(target) = &data.target {
            validate_byte_len(target.bytes(), VALID_TARGET_LENGTHS, "target")?;
        }

        if let Some(data) = &data.data {
            if data.len() > MAX_EMBEDDED_DATA_LEN {
                return Err(RawTxDataError::EmbeddedDataMaxLenExceeded {
                    max: MAX_EMBEDDED_DATA_LEN,
                    actual: data.len(),
                });
            }
        }

        validate_byte_len(data.signature.bytes(), VALID_SIG_LENGTHS, "signature")?;

        if let Some(data_root) = &data.data_root {
            validate_byte_len(data_root.bytes(), VALID_DATA_ROOT_LENGTHS, "data_root")?;
        }

        let mut positive_quantity = false;
        if let Some(quantity) = &data.quantity {
            validate_positive_integer(quantity, "quantity")?;

            if quantity != ZERO_BD.deref() {
                if data.target.is_none() {
                    return Err(RawTxDataError::MissingTarget);
                }
                positive_quantity = true;
            }
        }

        validate_positive_integer(&data.reward, "reward")?;

        if data.target.is_some() {
            if !positive_quantity {
                return Err(RawTxDataError::MissingQuantity);
            }
        }

        let expected_tx_id = data.signature.bytes().digest::<Sha256Hasher>();
        if expected_tx_id.as_slice() != data.id.bytes() {
            return Err(RawTxDataError::IdSignatureMismatch);
        }

        Ok(())
    }
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
