use crate::JsonError;
use crate::blob::Blob;
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hasher, Sha256};
use crate::crypto::keys;
use crate::crypto::rsa::{RsaPss, RsaPublicKey};
use crate::json::JsonSource;
use crate::money::{CurrencyExt, Winston};
use crate::tx::raw::{RawTxDataError, UnvalidatedRawTx, ValidatedRawTx};
use crate::tx::{EmbeddedData, Format, LastTx, Quantity, Reward, Tag, TxHash, TxId, TxSignature};
use crate::typed::FromInner;
use crate::validation::{SupportsValidation, Valid, ValidateExt, Validator};
use crate::wallet::{WalletAddress, WalletPk};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub(super) struct V1Tx<'a, const VALIDATED: bool = false>(V1TxData<'a>);

pub(super) type UnvalidatedV1Tx<'a> = V1Tx<'a, false>;
pub(super) type ValidatedV1Tx<'a> = V1Tx<'a, true>;

impl<'a> From<V1TxData<'a>> for UnvalidatedV1Tx<'a> {
    fn from(value: V1TxData<'a>) -> Self {
        V1Tx(value)
    }
}

impl<'a> From<ValidatedV1Tx<'a>> for V1TxData<'a> {
    fn from(value: ValidatedV1Tx<'a>) -> Self {
        value.0
    }
}

impl<'a> ValidatedV1Tx<'a> {
    pub(super) fn into_inner(self) -> V1TxData<'a> {
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

impl UnvalidatedV1Tx<'static> {
    pub fn from_json<J: JsonSource>(json: J) -> Result<Self, V1TxError> {
        let tx_data = UnvalidatedRawTx::from_json(json)?
            .validate()
            .map_err(|(_, e)| e)?
            .try_into()?;

        Ok(Self(tx_data))
    }
}

impl<'a> SupportsValidation for UnvalidatedV1Tx<'a> {
    type Unvalidated = V1TxData<'a>;
    type Validated = ValidatedV1Tx<'a>;
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

#[derive(Debug, Clone, PartialEq)]
pub(super) enum RsaPssSignatureData {
    Rsa4096 {
        owner: WalletPk<RsaPublicKey<4096>>,
        signature: TxSignature<RsaPss<4096>>,
    },
    Rsa2048 {
        owner: WalletPk<RsaPublicKey<2048>>,
        signature: TxSignature<RsaPss<2048>>,
    },
}

impl RsaPssSignatureData {
    fn from_raw<'a>(
        raw_owner: Option<Blob<'a>>,
        raw_signature: Blob<'a>,
    ) -> Result<Self, V1TxDataError> {
        use crate::crypto::rsa::SupportedPublicKey;
        use crate::crypto::signature::Scheme as SignatureScheme;
        use crate::crypto::signature::Signature;
        use crate::tx::v1::V1TxDataError::*;

        // v1 tx always uses RSA_PSS
        let raw_owner = raw_owner.ok_or(MissingOwner)?;

        Ok(
            match SupportedPublicKey::try_from(raw_owner)
                .map_err(|e| keys::KeyError::RsaError(e))?
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

    fn verify_sig(&self, tx_hash: &TxHash) -> Result<(), V1TxDataError> {
        match self {
            Self::Rsa4096 { owner, signature } => owner
                .verify_tx(tx_hash, signature)
                .map_err(|e| V1TxDataError::InvalidSignature(e)),
            Self::Rsa2048 { owner, signature } => owner
                .verify_tx(tx_hash, signature)
                .map_err(|e| V1TxDataError::InvalidSignature(e)),
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
pub(super) struct V1TxData<'a> {
    pub id: TxId,
    pub last_tx: LastTx,
    pub tags: Vec<Tag<'a>>,
    pub target: Option<WalletAddress>,
    pub quantity: Option<Quantity>,
    pub data_size: u64,
    pub data: Option<EmbeddedData<'a>>,
    pub reward: Reward,
    pub signature_data: RsaPssSignatureData,
}

impl<'a> V1TxData<'a> {
    pub fn tx_hash(&self) -> TxHash {
        // todo: find out if there are very old transactions that require a different approach
        TxHash::from_inner(self.deep_hash::<Sha256>())
    }
}

impl DeepHashable for V1TxData<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::list([
            self.signature_data.deep_hash_owner(),
            self.target.deep_hash(),
            self.data.deep_hash(),
            self.quantity.deep_hash(),
            self.reward.deep_hash(),
            self.last_tx.deep_hash(),
            self.tags.deep_hash(),
        ])
    }
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

impl<'a> TryFrom<ValidatedRawTx<'a>> for V1TxData<'a> {
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

        let signature_data = RsaPssSignatureData::from_raw(raw.owner, raw.signature)?;

        Ok(Self {
            id,
            last_tx,
            tags,
            target,
            quantity,
            data_size,
            data,
            reward,
            signature_data,
        })
    }
}

pub struct V1TxDataValidator;

impl Validator<V1TxData<'_>> for V1TxDataValidator {
    type Error = V1TxDataError;

    fn validate(data: &V1TxData) -> Result<(), Self::Error> {
        data.signature_data.verify_sig(&(data.tx_hash()))
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::crypto::rsa::RsaPss;
    use crate::money::{CurrencyExt, Winston};
    use crate::tx::v1::{RsaPssSignatureData, UnvalidatedV1Tx, V1TxDataError, V1TxError};
    use crate::tx::{Format, Reward, TxData, ZERO_QUANTITY};
    use crate::validation::ValidateExt;
    use std::ops::Deref;

    static TX_V1: &'static [u8] = include_bytes!("../../testdata/tx_v1.json");
    static TX_V2: &'static [u8] = include_bytes!("../../testdata/tx_v2.json");

    #[test]
    fn v1_ok() -> anyhow::Result<()> {
        let unvalidated = UnvalidatedV1Tx::from_json(TX_V1)?;
        let _validated = unvalidated.validate().map_err(|(_, e)| e)?;
        Ok(())
    }

    #[test]
    fn tx_data_ok_v1() -> anyhow::Result<()> {
        let tx_data = UnvalidatedV1Tx::from_json(TX_V1)?.0;
        assert_eq!(
            tx_data.id.to_base64(),
            "BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ"
        );
        assert_eq!(
            tx_data.last_tx.to_base64(),
            "jUcuEDZQy2fC6T3fHnGfYsw0D0Zl4NfuaXfwBOLiQtA"
        );

        if let RsaPssSignatureData::Rsa4096 { owner, .. } = &tx_data.signature_data {
            assert_eq!(
                owner.to_base64(),
                "posmEh5k2_h7fgj-0JwB2l2AU72u-UizJOA2m8gyYYcVjh_6N3A3DhwbLmnbIWjVWmsidgQZDDibiJhhyHsy28ARxrt5BJ3OCa1VRAk2ffhbaUaGUoIkVt6G8mnnTScN9JNPS7UYEqG_L8J48c2tQNsydbon2ImKIwCYmnMHKcpyEgXcgLDGhtGhIKtkuI-QOAu-TMqVjn5EaWsfJTW5J-ty8mswAMSxepgsUbUB3GXZfCyOAK0EGjrClZ1MLvyc8ANGQfLPjwTipMcUtX47Udy8i4C-c-vLC9oB_z5ZCDCat-5wGh2OA-lyghro2SpkxX0e-D-nbi91Pp9LORwDZIRQ5RCMDvtQx1-QD2adxn_P2zDN0hk5IWXoCnHyeoj-IdNIyCXNkDzT2A184CxjReE5XOUF7UFeOmvVwbUTMfnNBOSWeRz3U_e3MPNlc2JTIprRLC8IegyfS6NdCr90lYnuviEr0g75NE6-muJdHAd9gu2QZ1MpkX9OnsbtvCvvFje-K_p_4AR9l43CLemfdSZeHHMIzdPwKe75SFMbsuklsyc-ieq-OHrJCeL0WrkLT4Gf6rpGVkS8MjORuMOBRFrHRE7XKswzhwmV2SuzeU6ojtPNP87aNdiUGHtYCIyt7cRN5bRbrVjdCAXj2NnuWMzM6J6dme4e2R8gqNpsEok"
            );
        } else {
            unreachable!()
        }

        assert_eq!(&tx_data.tags, &vec![]);
        assert!(tx_data.target.is_none());
        assert_eq!(tx_data.quantity.as_ref().unwrap(), ZERO_QUANTITY.deref(),);
        assert_eq!(tx_data.data_size, 1033478);
        assert_eq!(tx_data.data.as_ref().unwrap().len(), 1033478);
        //todo: verify data value
        assert_eq!(
            &tx_data.reward,
            &Reward::from(Winston::from_str("124145681682")?),
        );
        Ok(())
    }

    #[test]
    fn v2_err() -> anyhow::Result<()> {
        match UnvalidatedV1Tx::from_json(TX_V2) {
            Err(V1TxError::DataError(V1TxDataError::IncorrectFormat(f))) => {
                assert_eq!(f, Format::V2);
            }
            _ => unreachable!("should have been an incorrect format error"),
        }
        Ok(())
    }
}
