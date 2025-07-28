use crate::JsonError;
use crate::crypto::keys;
use crate::crypto::signature::Scheme as SignatureScheme;
use crate::json::JsonSource;
use crate::money::{CurrencyExt, Winston};
use crate::tx::raw::{RawTxDataError, UnvalidatedRawTx, ValidatedRawTx};
use crate::tx::v1::V1TxDataError::MissingOwner;
use crate::tx::{EmbeddedData, Format, LastTx, Quantity, Reward, Tag, TxId, TxSignature};
use crate::typed::FromInner;
use crate::validation::{SupportsValidation, Valid, ValidateExt, Validator};
use crate::wallet::{WalletAddress, WalletPk};
use anyhow::anyhow;
use derive_where::derive_where;
use thiserror::Error;

#[derive_where(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub(super) struct V1Tx<'a, S: SignatureScheme, const VALIDATED: bool = false>(V1TxData<'a, S>);

pub(super) type UnvalidatedV1Tx<'a, S: SignatureScheme> = V1Tx<'a, S, false>;
pub(super) type ValidatedV1Tx<'a, S: SignatureScheme> = V1Tx<'a, S, true>;

impl<'a, S: SignatureScheme> From<V1TxData<'a, S>> for UnvalidatedV1Tx<'a, S> {
    fn from(value: V1TxData<'a, S>) -> Self {
        V1Tx(value)
    }
}

impl<'a, S: SignatureScheme> From<ValidatedV1Tx<'a, S>> for V1TxData<'a, S> {
    fn from(value: ValidatedV1Tx<'a, S>) -> Self {
        value.0
    }
}

impl<'a, S: SignatureScheme> ValidatedV1Tx<'a, S> {
    pub(super) fn into_inner(self) -> V1TxData<'a, S> {
        self.0
    }
}

#[derive(Error, Debug)]
pub enum V1TxError {
    #[error(transparent)]
    JsonError(#[from] JsonError),
    #[error(transparent)]
    RawDataError(#[from] RawTxDataError),
    #[error(transparent)]
    DataError(#[from] V1TxDataError),
}

impl<S: SignatureScheme> UnvalidatedV1Tx<'static, S> {
    pub fn from_json<J: JsonSource>(json: J) -> Result<Self, V1TxError> {
        let tx_data = UnvalidatedRawTx::from_json(json)?
            .validate()
            .map_err(|(_, e)| e)?
            .try_into()?;

        Ok(Self(tx_data))
    }
}

impl<'a, S: SignatureScheme> SupportsValidation for UnvalidatedV1Tx<'a, S> {
    type Unvalidated = V1TxData<'a, S>;
    type Validated = ValidatedV1Tx<'a, S>;
    type Validator = V1TxDataValidator;

    fn into_valid(self, _token: Valid<Self>) -> Self::Validated
    where
        Self: Sized,
    {
        V1Tx(self.0)
    }

    fn as_unvalidated(&self) -> &Self::Unvalidated {
        &self.0
    }
}

#[derive_where(Debug, Clone, PartialEq)]
pub(super) struct V1TxData<'a, S: SignatureScheme> {
    pub id: TxId,
    pub last_tx: LastTx,
    pub owner: WalletPk<S::Verifier>,
    pub tags: Vec<Tag<'a>>,
    pub target: Option<WalletAddress>,
    pub quantity: Option<Quantity>,
    pub data_size: u64,
    pub data: Option<EmbeddedData<'a>>,
    pub reward: Reward,
    pub signature: TxSignature<S>,
}

#[derive(Error, Debug)]
pub enum V1TxDataError {
    #[error("expected format '1' but found '{0}")]
    IncorrectFormat(Format),
    #[error("no owner field found but mandatory")]
    MissingOwner,
    #[error("invalid id: {0}")]
    InvalidId(String),
    #[error("invalid last_tx: {0}")]
    InvalidLastTx(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("invalid quantity: {0}")]
    InvalidQuantity(String),
    #[error("invalid reward: {0}")]
    InvalidReward(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error(transparent)]
    InvalidKey(#[from] keys::KeyError),
}

impl<'a, S: SignatureScheme> TryFrom<ValidatedRawTx<'a>> for V1TxData<'a, S> {
    type Error = V1TxDataError;

    fn try_from(raw: ValidatedRawTx<'a>) -> Result<Self, Self::Error> {
        let raw = raw.into_inner();
        if raw.format != Format::V1 {
            return Err(V1TxDataError::IncorrectFormat(raw.format));
        }

        let id = TxId::try_from(raw.id).map_err(|e| V1TxDataError::InvalidId(e.to_string()))?;

        let last_tx = LastTx::try_from(raw.last_tx)
            .map_err(|e| V1TxDataError::InvalidLastTx(e.to_string()))?;

        let tags = raw
            .tags
            .into_iter()
            .map(|t| Tag::from(t))
            .collect::<Vec<_>>();

        let target = raw
            .target
            .map(WalletAddress::try_from)
            .transpose()
            .map_err(|e| V1TxDataError::InvalidTarget(e.to_string()))?;

        let quantity = raw
            .quantity
            .map(|raw| Winston::try_new(raw).and_then(|w| Ok(Quantity::from(w))))
            .transpose()
            .map_err(|e| V1TxDataError::InvalidQuantity(e.to_string()))?;

        let data_size = raw.data_size;
        let data = raw.data.map(|b| EmbeddedData::from_inner(b));

        let reward = Reward::from_inner(
            Winston::try_new(raw.reward)
                .map_err(|e| V1TxDataError::InvalidReward(e.to_string()))?,
        );

        // v1 tx always uses RSA
        let owner = match raw.owner {
            Some(owner) => {
                WalletPk::from_inner(<S::Verifier>::try_from(owner).map_err(|e| {
                    keys::KeyError::Other(anyhow!("error converting verifier: {}", e))
                })?)
            }
            None => {
                return Err(MissingOwner);
            }
        };

        let signature = TxSignature::from_inner(raw.signature.try_into().map_err(|_| {
            V1TxDataError::InvalidSignature("invalid signature length".to_string())
        })?);

        // todo: check if signature & owner are compatible

        Ok(Self {
            id,
            last_tx,
            owner,
            tags,
            target,
            quantity,
            data_size,
            data,
            reward,
            signature,
        })
    }
}

pub struct V1TxDataValidator;

impl<S: SignatureScheme> Validator<V1TxData<'_, S>> for V1TxDataValidator {
    type Error = V1TxDataError;

    fn validate(data: &V1TxData<S>) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::rsa::{Rsa4096, RsaPss};
    use crate::tx::Format;
    use crate::tx::v1::{UnvalidatedV1Tx, V1TxDataError, V1TxError};
    use crate::validation::ValidateExt;

    static TX_V1: &'static [u8] = include_bytes!("../../testdata/tx_v1.json");
    static TX_V2: &'static [u8] = include_bytes!("../../testdata/tx_v2.json");

    #[test]
    fn v1_ok() -> anyhow::Result<()> {
        let unvalidated = UnvalidatedV1Tx::<RsaPss<Rsa4096>>::from_json(TX_V1)?;
        let _validated = unvalidated.validate().map_err(|(_, e)| e)?;
        Ok(())
    }

    #[test]
    fn v2_err() -> anyhow::Result<()> {
        match UnvalidatedV1Tx::<RsaPss<Rsa4096>>::from_json(TX_V2) {
            Err(V1TxError::DataError(V1TxDataError::IncorrectFormat(f))) => {
                assert_eq!(f, Format::V2);
            }
            _ => unreachable!("should have been an incorrect format error"),
        }
        Ok(())
    }
}
