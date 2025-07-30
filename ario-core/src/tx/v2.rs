use crate::blob::{AsBlob, Blob};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hasher, Sha384};
use crate::json::JsonSource;
use crate::tx::CommonTxDataError::MissingOwner;
use crate::tx::Format::V2;
use crate::tx::raw::{RawTxData, UnvalidatedRawTx, ValidatedRawTx};
use crate::tx::rsa::RsaSignatureData;
use crate::tx::{
    CommonData, CommonTxDataError, Format, Owner, Quantity, Reward, Signature, SignatureType, Tag,
    TxAnchor, TxError, TxHash, TxId,
};
use crate::validation::{SupportsValidation, Valid, ValidateExt, Validator};
use crate::wallet::WalletAddress;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub(super) struct V2Tx<'a, const VALIDATED: bool = false>(V2TxData<'a>);

pub(super) type UnvalidatedV2Tx<'a> = V2Tx<'a, false>;
pub(super) type ValidatedV2Tx<'a> = V2Tx<'a, true>;

impl<'a> From<ValidatedV2Tx<'a>> for ValidatedRawTx<'a> {
    fn from(value: ValidatedV2Tx<'a>) -> Self {
        let v2 = value.0;
        Self::danger_from_raw_tx_data(RawTxData {
            format: V2,
            id: v2.id.as_blob().into_owned(),
            last_tx: v2.last_tx.as_blob().into_owned(),
            denomination: v2.denomination,
            owner: Some(v2.signature_data.owner().as_blob().into_owned()),
            tags: v2.tags.into_iter().map(|t| t.into()).collect(),
            target: v2.target.map(|w| w.as_blob().into_owned()),
            quantity: v2.quantity.map(|q| q.into_inner().into()),
            data_tree: vec![],
            data_root: v2.data_root,
            data_size: v2.data_size,
            data: None,
            reward: v2.reward.into_inner().into(),
            signature: v2.signature_data.signature().as_blob().into_owned(),
            signature_type: Some(v2.signature_data.signature_type()),
        })
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
    Rsa(RsaSignatureData),
}

impl V2SignatureData {
    fn from_raw<'a>(
        signature_type: SignatureType,
        raw_owner: Option<Blob<'a>>,
        raw_signature: Blob<'a>,
    ) -> Result<Self, V2TxDataError> {
        match signature_type {
            SignatureType::RsaPss => {
                let raw_owner = raw_owner.ok_or(MissingOwner)?;
                Ok(Self::Rsa(RsaSignatureData::from_raw(
                    raw_owner,
                    raw_signature,
                )?))
            }
            SignatureType::EcdsaSecp256k1 => {
                todo!("ecdsa")
            }
        }
    }

    fn owner(&self) -> Owner {
        match self {
            Self::Rsa(rsa) => rsa.owner(),
        }
    }

    fn signature(&self) -> Signature {
        match self {
            Self::Rsa(rsa) => rsa.signature(),
        }
    }

    fn verify_sig(&self, tx_hash: &TxHash) -> Result<(), V2TxDataError> {
        match self {
            Self::Rsa(rsa) => Ok(rsa.verify_sig(tx_hash)?),
        }
    }

    fn signature_type(&self) -> SignatureType {
        match self {
            Self::Rsa(_) => SignatureType::RsaPss,
        }
    }

    fn deep_hash<H: Hasher>(&self) -> Option<Digest<H>> {
        match self {
            Self::Rsa(rsa) => Some(rsa.deep_hash()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct V2TxData<'a> {
    pub id: TxId,
    pub last_tx: TxAnchor,
    pub tags: Vec<Tag<'a>>,
    pub target: Option<WalletAddress>,
    pub quantity: Option<Quantity>,
    pub data_size: u64,
    pub data_root: Option<Blob<'a>>, //todo
    pub reward: Reward,
    pub signature_data: V2SignatureData,
    pub denomination: Option<u32>,
}

impl<'a> V2TxData<'a> {
    pub fn tx_hash(&self) -> TxHash {
        TxHash::DeepHash(self.deep_hash::<Sha384>())
    }
}

impl<'a> TryFrom<ValidatedRawTx<'a>> for V2TxData<'a> {
    type Error = V2TxDataError;

    fn try_from(raw: ValidatedRawTx<'a>) -> Result<Self, Self::Error> {
        let raw = raw.into_inner();
        if raw.format != Format::V2 {
            return Err(V2TxDataError::IncorrectFormat(raw.format));
        }
        let signature_data = V2SignatureData::from_raw(
            raw.signature_type.unwrap_or_default(),
            raw.owner,
            raw.signature,
        )?;

        let common_data = CommonData::try_from_raw(
            raw.id,
            raw.tags,
            raw.target,
            raw.quantity,
            raw.reward,
            raw.denomination,
        )?;

        let last_tx = TxAnchor::try_from(raw.last_tx)
            .map_err(|e| CommonTxDataError::InvalidLastTx(e.to_string()))?;

        if raw.data_root.is_some() && raw.data_size == 0 {
            return Err(V2TxDataError::DataRootWithoutDataSize);
        }

        if raw.data_root.is_none() && raw.data_size > 0 {
            return Err(V2TxDataError::DataSizeWithoutDataRoot(raw.data_size));
        }

        //todo: data_root

        Ok(Self {
            id: common_data.id,
            last_tx,
            tags: common_data.tags,
            target: common_data.target,
            quantity: common_data.quantity,
            data_size: raw.data_size,
            data_root: raw.data_root,
            reward: common_data.reward,
            signature_data,
            denomination: common_data.denomination,
        })
    }
}

impl DeepHashable for V2TxData<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        let mut elements = vec![Format::V2.deep_hash()];
        if let Some(signature_data) = self.signature_data.deep_hash() {
            elements.push(signature_data);
        }
        elements.extend([
            self.target.deep_hash(),
            self.quantity.deep_hash(),
            self.reward.deep_hash(),
            self.last_tx.deep_hash(),
            self.tags.deep_hash(),
            self.data_size.deep_hash(),
            self.data_root.deep_hash(),
        ]);

        if let Some(denomination) = self.denomination {
            elements.push(denomination.deep_hash());
        }

        Self::list(elements)
    }
}

#[derive(Error, Debug)]
pub enum V2TxDataError {
    #[error("expected format '2' but found '{0}")]
    IncorrectFormat(Format),
    #[error(transparent)]
    Common(#[from] CommonTxDataError),
    #[error("data size set  to '{0}' but data root is empty")]
    DataSizeWithoutDataRoot(u64),
    #[error("data root is set but data size is '0'")]
    DataRootWithoutDataSize,
}

pub struct V2TxDataValidator;

impl Validator<V2TxData<'_>> for V2TxDataValidator {
    type Error = V2TxDataError;

    fn validate(data: &V2TxData) -> Result<(), Self::Error> {
        data.signature_data.verify_sig(&(data.tx_hash()))
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::money::{CurrencyExt, Winston};
    use crate::tx::raw::ValidatedRawTx;
    use crate::tx::v2::{UnvalidatedV2Tx, V2TxDataError};
    use crate::tx::{CommonTxDataError, Quantity, Reward};
    use crate::validation::ValidateExt;
    use std::ops::Deref;
    use std::sync::LazyLock;

    static ZERO_QUANTITY: LazyLock<Quantity> = LazyLock::new(|| Quantity::zero());
    static TX_V2: &'static [u8] = include_bytes!("../../testdata/tx_v2.json");
    static TX_V2_2: &'static [u8] = include_bytes!("../../testdata/tx_v2_2.json");
    static TX_V2_3: &'static [u8] = include_bytes!("../../testdata/tx_v2_3.json");
    static TX_V2_INVALID: &'static [u8] = include_bytes!("../../testdata/tx_v2_invalid_sig.json");

    #[test]
    fn tx_hash_ok() -> anyhow::Result<()> {
        let tx_data = UnvalidatedV2Tx::from_json(TX_V2_3)?.0;
        let tx_hash = tx_data.tx_hash();
        let deep_digest = tx_hash.as_slice();

        let expected: [u8; 48] = [
            74, 15, 74, 255, 248, 205, 47, 229, 107, 195, 69, 76, 215, 249, 34, 186, 197, 31, 178,
            163, 72, 54, 78, 179, 19, 178, 1, 132, 183, 231, 131, 213, 146, 203, 6, 99, 106, 231,
            215, 199, 181, 171, 52, 255, 205, 55, 203, 117,
        ];

        assert_eq!(deep_digest, &expected);
        Ok(())
    }

    #[test]
    fn tx_data_ok_v2() -> anyhow::Result<()> {
        let tx_data = UnvalidatedV2Tx::from_json(TX_V2)?.0;
        assert_eq!(
            tx_data.id.to_base64(),
            "bXGqzNQNmHTeL54cUQ6wPo-MO0thLP44FeAoM93kEwk"
        );
        assert_eq!(
            tx_data.last_tx.to_base64(),
            "gVhey9KN6Fjc3nZbSOqLPRyDjjw6O5-sLSWPLZ_S7LoX5XOrFRja8A_wuj22OpHj"
        );
        assert!(tx_data.target.is_none());
        assert_eq!(tx_data.quantity.as_ref().unwrap(), ZERO_QUANTITY.deref(),);
        //todo: data root
        assert_eq!(tx_data.data_size, 128355);
        assert_eq!(
            tx_data.reward,
            Reward::from(Winston::from_str("557240107")?),
        );

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

        Ok(())
    }

    #[test]
    fn tx_data_ok_transfer() -> anyhow::Result<()> {
        let tx_data = UnvalidatedV2Tx::from_json(TX_V2_2)?.0;
        assert_eq!(
            tx_data.id.to_base64(),
            "oo6wzsvLtpGmOInBvyJ3ORjbhVelFEZKTOAy6wtjZtQ"
        );
        assert_eq!(
            tx_data.last_tx.to_base64(),
            "mxi51DabflJu7YNcJSIm54cWjXDu69MAknQFuujhzDp7lEI7MT5zCufHlyhpq5lm"
        );
        assert_eq!(
            tx_data.quantity.as_ref(),
            Some(&Quantity::from(Winston::from_str("2199990000000000")?))
        );
        assert_eq!(
            tx_data.target.as_ref().unwrap().to_base64(),
            "fGPsv2_-ueOvwFQF5zvYCRmawBGgc9FiDOXkbfurQtI"
        );
        assert_eq!(tx_data.reward, Reward::from(Winston::from_str("6727794")?));
        Ok(())
    }

    #[test]
    fn tx_valid_sig() -> anyhow::Result<()> {
        let tx = UnvalidatedV2Tx::from_json(TX_V2_2)?;
        let _valid = tx.validate().expect("sig to be valid");
        Ok(())
    }

    #[test]
    fn tx_invalid_sig() -> anyhow::Result<()> {
        let tx = UnvalidatedV2Tx::from_json(TX_V2_INVALID)?;
        match tx.validate() {
            Err((_, V2TxDataError::Common(CommonTxDataError::InvalidSignature(_)))) => {
                // ok
            }
            _ => unreachable!("signature validation failure expected"),
        }
        Ok(())
    }

    #[test]
    fn tx_raw_rountrip() -> anyhow::Result<()> {
        let unvalidated = UnvalidatedV2Tx::from_json(TX_V2)?;
        let validated = unvalidated.validate().map_err(|(_, e)| e)?;
        let raw = ValidatedRawTx::from(validated);
        let json_string = raw.to_json_string()?;
        let unvalidated = UnvalidatedV2Tx::from_json(&json_string)?;
        let _validated = unvalidated.validate().map_err(|(_, e)| e)?;
        Ok(())
    }
}
