use crate::blob::{AsBlob, Blob};
use crate::crypto::ec::ecdsa::Ecdsa;
use crate::crypto::ec::{Curve, EcPublicKey, EcSecretKey};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hasher, Sha384};
use crate::crypto::merkle::DefaultMerkleRoot;
use crate::crypto::rsa::{Rsa, RsaPrivateKey, SupportedRsaKeySize};
use crate::crypto::signature;
use crate::crypto::signature::SigningError;
use crate::json::JsonSource;
use crate::money::{Money, MoneyError, Winston};
use crate::tx::CommonTxDataError::MissingOwner;
use crate::tx::Format::V2;
use crate::tx::ecdsa::EcdsaSignatureData;
use crate::tx::pss::PssSignatureData;
use crate::tx::raw::{RawTx, RawTxData, UnvalidatedRawTx, ValidatedRawTx};
use crate::tx::{
    CommonData, CommonTxDataError, ExternalData, Format, Owner, Quantity, Reward, Signature,
    SignatureType, Tag, TxAnchor, TxDeepHash, TxError, TxHash, TxId, TxSignature,
};
use crate::tx::{RewardError, Transfer};
use crate::typed::FromInner;
use crate::validation::{SupportsValidation, Valid, ValidateExt, Validator};
use crate::wallet::{WalletAddress, WalletPk, WalletSk};
use crate::{JsonError, JsonValue};
use anyhow::anyhow;
use bon::Builder;
use mown::Mown;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub(crate) struct V2Tx<'a, const VALIDATED: bool = false>(V2TxData<'a>);

pub(crate) type UnvalidatedV2Tx<'a> = V2Tx<'a, false>;
pub(crate) type ValidatedV2Tx<'a> = V2Tx<'a, true>;

pub(crate) type DataRoot = DefaultMerkleRoot;

impl<'a, const VALIDATED: bool> V2Tx<'a, VALIDATED> {
    pub(super) fn as_inner(&self) -> &V2TxData<'a> {
        &self.0
    }

    pub(super) fn into_owned(self) -> V2Tx<'static, VALIDATED> {
        V2Tx(self.0.into_owned())
    }
}

impl<'a, const VALIDATED: bool> From<V2Tx<'a, VALIDATED>> for RawTx<'a, VALIDATED> {
    fn from(value: V2Tx<'a, VALIDATED>) -> Self {
        let v2 = value.0;
        Self::danger_from_raw_tx_data(RawTxData {
            format: V2,
            id: v2.id.as_blob().into_owned(),
            last_tx: v2.last_tx.as_blob().into_owned(),
            denomination: v2.denomination,
            owner: v2
                .signature_data
                .tx_owner()
                .map(|o| o.as_blob().into_owned()),
            tags: v2.tags.into_iter().map(|t| t.into()).collect(),
            target: v2.target.map(|w| w.as_blob().into_owned()),
            quantity: v2.quantity.map(|q| q.into_inner().into()),
            data_tree: vec![],
            data_root: v2.data_root.map(|dr| dr.as_blob().into_owned()),
            data_size: v2.data_size,
            data: None,
            reward: v2.reward.into_inner().into(),
            signature: v2.signature_data.signature().as_blob().into_owned(),
            signature_type: Some(v2.signature_data.signature_type()),
        })
    }
}

impl<'a> ValidatedV2Tx<'a> {
    pub fn invalidate(self) -> UnvalidatedV2Tx<'a> {
        V2Tx(self.0)
    }

    pub(super) fn to_json_string(&self) -> Result<String, JsonError> {
        ValidatedRawTx::from(self.clone()).to_json_string()
    }

    pub(super) fn to_json(&self) -> Result<JsonValue, JsonError> {
        ValidatedRawTx::from(self.clone()).to_json()
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

impl<'a> UnvalidatedV2Tx<'a> {
    pub(crate) fn try_from_raw(raw: ValidatedRawTx<'a>) -> Result<Self, TxError> {
        Ok(Self(V2TxData::try_from(raw)?))
    }
}

impl<'a> SupportsValidation for UnvalidatedV2Tx<'a> {
    type Unvalidated = V2TxData<'a>;
    type Validated = ValidatedV2Tx<'a>;
    type Validator = V2TxValidator;

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
    Pss(PssSignatureData),
    Ecdsa(EcdsaSignatureData),
}

impl V2SignatureData {
    pub(super) fn owner(&self) -> Owner {
        match self {
            Self::Pss(pss) => pss.owner(),
            Self::Ecdsa(ecdsa) => ecdsa.owner(),
        }
    }

    pub(super) fn tx_owner(&self) -> Option<Owner> {
        match self {
            Self::Pss(pss) => Some(pss.owner()),
            Self::Ecdsa(_) => None,
        }
    }

    pub(super) fn signature(&self) -> Signature {
        match self {
            Self::Pss(pss) => pss.signature(),
            Self::Ecdsa(ecdsa) => ecdsa.signature(),
        }
    }

    fn verify_sig(&self, tx_hash: &TxHash) -> Result<(), V2TxDataError> {
        match self {
            Self::Pss(pss) => Ok(pss.verify_sig(tx_hash)?),
            Self::Ecdsa(ecdsa) => Ok(ecdsa.verify_sig(tx_hash)?),
        }
    }

    fn signature_type(&self) -> SignatureType {
        match self {
            Self::Pss(_) => SignatureType::RsaPss,
            Self::Ecdsa(EcdsaSignatureData::Secp256k1 { .. }) => SignatureType::EcdsaSecp256k1,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct V2TxData<'a> {
    id: TxId,
    last_tx: TxAnchor,
    tags: Vec<Tag<'a>>,
    target: Option<WalletAddress>,
    quantity: Option<Quantity>,
    data_size: u64,
    data_root: Option<DataRoot>,
    reward: Reward,
    signature_data: V2SignatureData,
    denomination: Option<u32>,
    tx_hash: Option<TxHash>,
}

impl<'a> V2TxData<'a> {
    fn into_owned(self) -> V2TxData<'static> {
        V2TxData {
            id: self.id,
            last_tx: self.last_tx,
            tags: self.tags.into_iter().map(|t| t.into_owned()).collect(),
            target: self.target,
            quantity: self.quantity,
            data_size: self.data_size,
            data_root: self.data_root,
            reward: self.reward,
            signature_data: self.signature_data,
            denomination: self.denomination,
            tx_hash: self.tx_hash,
        }
    }

    pub fn id(&self) -> &TxId {
        &self.id
    }

    pub fn last_tx(&self) -> &TxAnchor {
        &self.last_tx
    }

    pub fn tags(&self) -> &Vec<Tag<'a>> {
        &self.tags
    }

    pub fn target(&self) -> Option<&WalletAddress> {
        self.target.as_ref()
    }

    pub fn quantity(&self) -> Option<&Quantity> {
        self.quantity.as_ref()
    }

    pub fn data_root(&self) -> Option<&DataRoot> {
        self.data_root.as_ref()
    }

    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    pub fn reward(&self) -> &Reward {
        &self.reward
    }

    pub fn signature_data(&self) -> &V2SignatureData {
        &self.signature_data
    }

    pub fn tx_hash(&self) -> Mown<TxHash> {
        if let Some(tx_hash) = self.tx_hash.as_ref() {
            Mown::Borrowed(tx_hash)
        } else {
            let owner = self
                .signature_data
                .tx_owner()
                .map(|o| o.as_blob().into_owned());

            let mut tx_hash_builder = TxHashBuilder::from(self);
            tx_hash_builder.owner = owner.as_ref();
            Mown::Owned(tx_hash_builder.tx_hash())
        }
    }
}

impl<'a> TryFrom<ValidatedRawTx<'a>> for V2TxData<'a> {
    type Error = V2TxDataError;

    fn try_from(raw: ValidatedRawTx<'a>) -> Result<Self, Self::Error> {
        let raw = raw.into_inner();
        if raw.format != Format::V2 {
            return Err(V2TxDataError::IncorrectFormat(raw.format));
        }

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

        let data_root = raw
            .data_root
            .map(|b| DataRoot::try_from(b))
            .transpose()
            .map_err(|e| V2TxDataError::InvalidDataRoot(e.to_string()))?;

        let (signature_data, tx_hash) = match raw.signature_type.unwrap_or_default() {
            SignatureType::RsaPss => {
                let raw_owner = raw.owner.ok_or(MissingOwner)?;
                (
                    V2SignatureData::Pss(PssSignatureData::from_raw(raw_owner, raw.signature)?),
                    None,
                )
            }
            SignatureType::EcdsaSecp256k1 => {
                // ecdsa txs require the tx_hash to recover the owner
                let tx_hash = TxHashBuilder {
                    owner: None,
                    target: common_data.target.as_ref(),
                    quantity: common_data.quantity.as_ref(),
                    reward: &common_data.reward,
                    last_tx: &last_tx,
                    tags: &common_data.tags,
                    data_size: raw.data_size,
                    data_root: data_root.as_ref(),
                    denomination: common_data.denomination,
                }
                .tx_hash();
                (
                    V2SignatureData::Ecdsa(EcdsaSignatureData::from_raw(raw.signature, &tx_hash)?),
                    Some(tx_hash),
                )
            }
        };

        Ok(Self {
            id: common_data.id,
            last_tx,
            tags: common_data.tags,
            target: common_data.target,
            quantity: common_data.quantity,
            data_size: raw.data_size,
            data_root,
            reward: common_data.reward,
            signature_data,
            denomination: common_data.denomination,
            tx_hash,
        })
    }
}

struct TxHashBuilder<'a> {
    owner: Option<&'a Blob<'a>>,
    target: Option<&'a WalletAddress>,
    quantity: Option<&'a Quantity>,
    reward: &'a Reward,
    last_tx: &'a TxAnchor,
    tags: &'a Vec<Tag<'a>>,
    data_size: u64,
    data_root: Option<&'a DataRoot>,
    denomination: Option<u32>,
}

impl<'a> From<&'a V2TxData<'a>> for TxHashBuilder<'a> {
    fn from(value: &'a V2TxData<'a>) -> Self {
        Self {
            owner: None,
            target: value.target.as_ref(),
            quantity: value.quantity.as_ref(),
            reward: &value.reward,
            last_tx: &value.last_tx,
            tags: &value.tags,
            data_size: value.data_size,
            data_root: value.data_root.as_ref(),
            denomination: value.denomination.clone(),
        }
    }
}

impl TxHashBuilder<'_> {
    pub fn tx_hash(&self) -> TxHash {
        TxHash::DeepHash(TxDeepHash::from_inner(self.deep_hash::<Sha384>()))
    }
}

impl DeepHashable for TxHashBuilder<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        let mut elements = vec![Format::V2.deep_hash()];
        if let Some(owner) = self.owner {
            elements.push(owner.deep_hash());
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
    #[error("provided data root is invalid: {0}")]
    InvalidDataRoot(String),
}

pub struct V2TxValidator;

impl Validator<V2TxData<'_>> for V2TxValidator {
    type Error = V2TxDataError;

    fn validate(data: &V2TxData) -> Result<(), Self::Error> {
        data.signature_data.verify_sig(&(data.tx_hash()))
    }
}

trait TxSigner {
    fn sign(&self, data: &TxDraft) -> Result<V2SignatureData, TxError>;
}

impl<const BIT: usize> TxSigner for WalletSk<RsaPrivateKey<BIT>>
where
    Rsa<BIT>: SupportedRsaKeySize,
{
    fn sign(&self, data: &TxDraft) -> Result<V2SignatureData, TxError> {
        let pk = self.public_key().clone();
        let pk_blob = pk.as_blob();
        let mut tx_hash_builder = TxHashBuilder::from(data);
        tx_hash_builder.owner = Some(&pk_blob);
        let tx_hash = tx_hash_builder.tx_hash();

        let sig = self
            .sign_tx_hash(&tx_hash)
            .map_err(|s| TxError::Other(anyhow!("tx signing failed: {}", s)))?;

        Ok(V2SignatureData::Pss(
            PssSignatureData::from_rsa(pk, sig)
                .map_err(|e| signature::Error::SigningError(SigningError::Other(e.to_string())))?,
        ))
    }
}

impl<C: Curve> TxSigner for WalletSk<EcSecretKey<C>>
where
    (WalletPk<EcPublicKey<C>>, TxSignature<Ecdsa<C>>): Into<EcdsaSignatureData>,
{
    fn sign(&self, data: &TxDraft) -> Result<V2SignatureData, TxError> {
        let tx_hash = TxHashBuilder::from(data).tx_hash();

        let sig = self
            .sign_tx_hash(&tx_hash)
            .map_err(|e| TxError::Other(anyhow!("tx signing failed: {}", e)))?;

        Ok(V2SignatureData::Ecdsa(EcdsaSignatureData::from_ecdsa(
            self.public_key().clone(),
            sig,
        )))
    }
}

#[derive(Builder, Clone, Debug, PartialEq)]
#[builder(
    builder_type(
      name = V2TxBuilder,
      vis = "pub",
    ),
    derive(Clone, Debug),
    finish_fn(
      name = draft,
    )
)]
pub struct TxDraft<'a> {
    #[builder(with = |r: impl TryInto<Money<Winston>, Error: Into<MoneyError>>| -> Result<_, RewardError> {
        Ok(Reward::try_from(r)?)
    })]
    reward: Reward,
    #[builder(default)]
    tags: Vec<Tag<'a>>,
    tx_anchor: TxAnchor,
    transfer: Option<Transfer>,
    data_upload: Option<ExternalData>,
}

impl<'a> From<&'a TxDraft<'a>> for TxHashBuilder<'a> {
    fn from(value: &'a TxDraft<'a>) -> Self {
        let (target, quantity) = match &value.transfer {
            Some(transfer) => (Some(&transfer.target), Some(&transfer.quantity)),
            None => (None, None),
        };

        let (data_size, data_root) = match &value.data_upload {
            Some(upload) => (upload.size(), Some(upload.root())),
            None => (0, None),
        };

        Self {
            owner: None,
            target,
            quantity,
            reward: &value.reward,
            last_tx: &value.tx_anchor,
            tags: &value.tags,
            data_size,
            data_root,
            denomination: None,
        }
    }
}

impl<'a> TxDraft<'a> {
    pub(crate) fn sign<T: TxSigner>(self, signer: &T) -> Result<ValidatedV2Tx<'a>, TxError> {
        let signature_data = signer.sign(&self)?;
        let (target, quantity) = match self.transfer {
            Some(transfer) => (Some(transfer.target), Some(transfer.quantity)),
            None => (None, None),
        };

        let (data_size, data_root) = match self.data_upload {
            Some(upload) => (upload.size(), Some(upload.into_inner())),
            None => (0, None),
        };

        let tx_data = V2TxData {
            id: signature_data.signature().digest(),
            last_tx: self.tx_anchor,
            tags: self.tags,
            target,
            quantity,
            data_size,
            data_root,
            reward: self.reward,
            signature_data,
            denomination: None,
            tx_hash: None,
        };
        V2Tx::try_from_raw(RawTx::from(V2Tx(tx_data)).validate().map_err(|(_, e)| e)?)?
            .validate()
            .map_err(|(_, e)| e.into())
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
        assert_eq!(tx_data.reward, Reward::try_from(557240107)?,);

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
            Some(&Quantity::try_from(Winston::from_str("2199990000000000")?)?)
        );
        assert_eq!(
            tx_data.target.as_ref().unwrap().to_base64(),
            "fGPsv2_-ueOvwFQF5zvYCRmawBGgc9FiDOXkbfurQtI"
        );
        assert_eq!(tx_data.reward, Reward::try_from(6727794)?);
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
