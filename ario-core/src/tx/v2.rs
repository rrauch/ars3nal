use crate::blob::Blob;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hasher, Sha384};
use crate::crypto::keys;
use crate::crypto::rsa::{RsaPss, RsaPublicKey};
use crate::json::JsonSource;
use crate::tx::raw::{UnvalidatedRawTx, ValidatedRawTx};
use crate::tx::{
    CommonTxDataError, Format, LastTx, Quantity, Reward, Tag, TxError, TxHash, TxId, TxSignature,
};
use crate::typed::FromInner;
use crate::validation::{SupportsValidation, Valid, ValidateExt, Validator};
use crate::wallet::{WalletAddress, WalletPk};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub(super) struct V2Tx<'a, const VALIDATED: bool = false>(V2TxData<'a>);

pub(super) type UnvalidatedV2Tx<'a> = V2Tx<'a, false>;
pub(super) type ValidatedV2Tx<'a> = V2Tx<'a, true>;

impl<'a> From<V2TxData<'a>> for UnvalidatedV2Tx<'a> {
    fn from(value: V2TxData<'a>) -> Self {
        V2Tx(value)
    }
}

impl<'a> From<ValidatedV2Tx<'a>> for V2TxData<'a> {
    fn from(value: ValidatedV2Tx<'a>) -> Self {
        value.0
    }
}

impl<'a> ValidatedV2Tx<'a> {
    pub(super) fn into_inner(self) -> V2TxData<'a> {
        self.0
    }
}

impl UnvalidatedV2Tx<'static> {
    pub fn from_json<J: JsonSource>(json: J) -> Result<Self, TxError> {
        let tx_data = UnvalidatedRawTx::from_json(json)?
            .validate()
            .map_err(|(_, e)| e)?
            .try_into()?;

        Ok(Self(tx_data))
    }
}

impl<'a> SupportsValidation for UnvalidatedV2Tx<'a> {
    type Unvalidated = V2TxData<'a>;
    type Validated = ValidatedV2Tx<'a>;
    type Validator = V2TxDataValidator;

    fn into_valid(self, _token: Valid<Self>) -> Self::Validated
    where
        Self: Sized,
    {
        V2Tx(self.0)
    }

    fn as_unvalidated(&self) -> &Self::Unvalidated {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum V2SignatureData {
    Rsa4096 {
        owner: WalletPk<RsaPublicKey<4096>>,
        signature: TxSignature<RsaPss<4096>>,
    },
    Rsa2048 {
        owner: WalletPk<RsaPublicKey<2048>>,
        signature: TxSignature<RsaPss<2048>>,
    },
}

impl V2SignatureData {
    fn from_raw<'a>(
        raw_owner: Option<Blob<'a>>,
        raw_signature: Blob<'a>,
    ) -> Result<Self, V2TxDataError> {
        use crate::crypto::rsa::SupportedPublicKey;
        use crate::crypto::signature::Scheme as SignatureScheme;
        use crate::crypto::signature::Signature;
        use CommonTxDataError::*;

        // v1 tx always uses RSA_PSS
        let raw_owner = raw_owner.ok_or(MissingOwner)?;

        Ok(
            match SupportedPublicKey::try_from(raw_owner)
                .map_err(|e| CommonTxDataError::from(keys::KeyError::RsaError(e)))?
            {
                SupportedPublicKey::Rsa4096(pk) => Self::Rsa4096 {
                    owner: WalletPk::from_inner(pk),
                    signature: TxSignature::from_inner(Signature::from_inner(
                        <<RsaPss<4096> as SignatureScheme>::Output>::try_from(raw_signature)
                            .map_err(|e| InvalidSignature(e.to_string()))?,
                    )),
                },
                SupportedPublicKey::Rsa2048(pk) => Self::Rsa2048 {
                    owner: WalletPk::from_inner(pk),
                    signature: TxSignature::from_inner(Signature::from_inner(
                        <<RsaPss<2048> as SignatureScheme>::Output>::try_from(raw_signature)
                            .map_err(|e| InvalidSignature(e.to_string()))?,
                    )),
                },
            },
        )
    }

    fn verify_sig(&self, tx_hash: &TxHash) -> Result<(), V2TxDataError> {
        match self {
            Self::Rsa4096 { owner, signature } => owner
                .verify_tx(tx_hash, signature)
                .map_err(|e| CommonTxDataError::InvalidSignature(e).into()),
            Self::Rsa2048 { owner, signature } => owner
                .verify_tx(tx_hash, signature)
                .map_err(|e| CommonTxDataError::InvalidSignature(e).into()),
        }
    }

    fn deep_hash_owner<H: Hasher>(&self) -> Digest<H> {
        match self {
            Self::Rsa4096 { owner, .. } => owner.deep_hash(),
            Self::Rsa2048 { owner, .. } => owner.deep_hash(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct V2TxData<'a> {
    pub id: TxId,
    pub last_tx: LastTx,
    pub tags: Vec<Tag<'a>>,
    pub target: Option<WalletAddress>,
    pub quantity: Option<Quantity>,
    pub data_size: u64,
    pub data_root: Option<Blob<'a>>, //todo
    pub reward: Reward,
    pub signature_data: V2SignatureData,
}

impl<'a> V2TxData<'a> {
    pub fn tx_hash(&self) -> TxHash {
        // todo: find out if there are very old transactions that require a different approach
        TxHash::from_inner(self.deep_hash::<Sha384>())
    }
}

impl<'a> TryFrom<ValidatedRawTx<'a>> for V2TxData<'a> {
    type Error = V2TxDataError;

    fn try_from(raw: ValidatedRawTx<'a>) -> Result<Self, Self::Error> {
        let raw = raw.into_inner();
        if raw.format != Format::V2 {
            return Err(V2TxDataError::IncorrectFormat(raw.format));
        }
        todo!()
    }
}

impl DeepHashable for V2TxData<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::list([
            Format::V2.deep_hash(),
            self.signature_data.deep_hash_owner(),
            self.target.deep_hash(),
            self.quantity.deep_hash(),
            self.reward.deep_hash(),
            self.last_tx.deep_hash(),
            self.tags.deep_hash(),
            self.data_size.deep_hash(),
            self.data_root.deep_hash(),
        ])
    }
}

#[derive(Error, Debug)]
pub enum V2TxDataError {
    #[error("expected format '2' but found '{0}")]
    IncorrectFormat(Format),
    #[error(transparent)]
    Common(#[from] CommonTxDataError),
}

pub struct V2TxDataValidator;

impl Validator<V2TxData<'_>> for V2TxDataValidator {
    type Error = V2TxDataError;

    fn validate(data: &V2TxData) -> Result<(), Self::Error> {
        data.signature_data.verify_sig(&(data.tx_hash()))
    }
}
