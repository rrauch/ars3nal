use crate::blob::{AsBlob, Blob};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher, Sha256};
use crate::entity::pss::{Rsa2048SignatureData, Rsa4096SignatureData};
use crate::entity::{Owner, Signature, pss};
use crate::json::JsonSource;
use crate::tag::Tag;
use crate::tx::CommonTxDataError::MissingOwner;
use crate::tx::raw::{RawTx, RawTxData, UnvalidatedRawTx, ValidatedRawTx};
use crate::tx::{
    CommonData, CommonTxDataError, EmbeddedDataItem, Format, LastTx, Quantity, Reward,
    SignatureType, TxDeepHash, TxError, TxHash, TxId, TxShallowHash,
};
use crate::typed::FromInner;
use crate::validation::{SupportsValidation, ValidateExt};
use crate::wallet::WalletAddress;
use crate::{Authenticated, AuthenticationState, JsonError, JsonValue, Unauthenticated, entity};
use itertools::Either;
use serde::{Deserialize, Deserializer, Serialize};
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Hash, Serialize)]
#[repr(transparent)]
pub(super) struct V1Tx<'a, Auth: AuthenticationState = Unauthenticated>(
    V1TxData<'a>,
    PhantomData<Auth>,
);

pub(super) type UnauthenticatedV1Tx<'a> = V1Tx<'a, Unauthenticated>;

impl<'de, 'a> Deserialize<'de> for UnauthenticatedV1Tx<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(V1TxData::deserialize(deserializer)?, PhantomData))
    }
}

pub(super) type AuthenticatedV1Tx<'a> = V1Tx<'a, Authenticated>;

impl<'a, Auth: AuthenticationState> V1Tx<'a, Auth> {
    pub(super) fn as_inner(&self) -> &V1TxData<'a> {
        &self.0
    }

    pub(super) fn into_owned(self) -> V1Tx<'static, Auth> {
        V1Tx(self.0.into_owned(), PhantomData)
    }

    pub(super) fn to_json_string(&self) -> Result<String, JsonError> {
        RawTx::from(self.clone()).to_json_string()
    }

    pub(super) fn to_json(&self) -> Result<JsonValue, JsonError> {
        RawTx::from(self.clone()).to_json()
    }
}

impl<'a, Auth: AuthenticationState> From<V1Tx<'a, Auth>> for RawTx<'a, Auth> {
    fn from(value: V1Tx<'a, Auth>) -> Self {
        let v1 = value.0;
        Self::danger_from_raw_tx_data(RawTxData {
            format: Format::V1,
            id: v1.id.as_blob().into_owned(),
            last_tx: v1.last_tx.as_blob().into_owned(),
            denomination: v1.denomination,
            owner: Some(v1.signature_data.owner().as_blob().into_owned()),
            tags: v1.tags.into_iter().map(|t| t.into()).collect(),
            target: v1.target.map(|w| w.as_blob().into_owned()),
            quantity: v1.quantity.map(|q| q.into_inner().into()),
            data_tree: vec![],
            data_root: None,
            data_size: v1.data_item.as_ref().map(|d| d.len() as u64).unwrap_or(0),
            data: v1.data_item.map(|d| d.into_inner()),
            reward: v1.reward.into_inner().into(),
            signature: v1.signature_data.signature().as_blob().into_owned(),
            signature_type: None,
        })
    }
}

impl<'a> AuthenticatedV1Tx<'a> {
    pub fn invalidate(self) -> UnauthenticatedV1Tx<'a> {
        V1Tx(self.0, PhantomData)
    }
}

impl UnauthenticatedV1Tx<'static> {
    pub fn from_json<J: JsonSource>(json: J) -> Result<Self, TxError> {
        let tx_data = UnvalidatedRawTx::from_json(json)?
            .validate()
            .map_err(|(_, e)| e)?
            .try_into()?;

        Ok(Self(tx_data, PhantomData))
    }
}

impl<'a> UnauthenticatedV1Tx<'a> {
    pub(crate) fn try_from_raw(raw: ValidatedRawTx<'a>) -> Result<Self, TxError> {
        Ok(Self(V1TxData::try_from(raw)?, PhantomData))
    }
}

impl<'a> SupportsValidation for UnauthenticatedV1Tx<'a> {
    type Validated = AuthenticatedV1Tx<'a>;
    type Error = V1TxDataError;
    type Reference<'r> = ();

    fn validate_with(
        self,
        _: &Self::Reference<'_>,
    ) -> Result<Self::Validated, (Self, Self::Error)> {
        if let Err(err) = self.0.signature_data.verify_sig(&(self.0.tx_hash())) {
            return Err((self, err.into()));
        }
        Ok(V1Tx(self.0, PhantomData))
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
pub(super) enum V1SignatureData {
    Rsa4096(Rsa4096SignatureData<TxHash>),
    Rsa2048(Rsa2048SignatureData<TxHash>),
}

impl Hashable for V1SignatureData {
    #[inline]
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        match self {
            Self::Rsa4096(rsa) => rsa.feed(hasher),
            Self::Rsa2048(rsa) => rsa.feed(hasher),
        }
    }
}

impl DeepHashable for V1SignatureData {
    #[inline]
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        match self {
            Self::Rsa4096(rsa) => rsa.deep_hash(),
            Self::Rsa2048(rsa) => rsa.deep_hash(),
        }
    }
}

impl V1SignatureData {
    #[inline]
    fn from_raw(raw_owner: Blob<'_>, raw_signature: Blob<'_>) -> Result<Self, entity::Error> {
        Ok(match pss::from_raw_autodetect(raw_owner, raw_signature)? {
            Either::Left(rsa) => V1SignatureData::Rsa4096(rsa),
            Either::Right(rsa) => V1SignatureData::Rsa2048(rsa),
        })
    }

    #[inline]
    fn verify_sig(&self, tx_hash: &TxHash) -> Result<(), entity::Error> {
        match self {
            Self::Rsa4096(rsa) => rsa.verify_sig(tx_hash),
            Self::Rsa2048(rsa) => rsa.verify_sig(tx_hash),
        }
    }

    #[inline]
    pub fn owner(&self) -> Owner<'_> {
        match self {
            Self::Rsa4096(rsa) => rsa.owner(),
            Self::Rsa2048(rsa) => rsa.owner(),
        }
    }

    #[inline]
    pub fn signature(&self) -> Signature<'_, TxHash> {
        match self {
            Self::Rsa4096(rsa) => rsa.signature(),
            Self::Rsa2048(rsa) => rsa.signature(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
pub(super) struct V1TxData<'a> {
    pub id: TxId,
    pub last_tx: LastTx<'a>,
    pub tags: Vec<Tag<'a>>,
    pub target: Option<WalletAddress>,
    pub quantity: Option<Quantity>,
    pub data_item: Option<EmbeddedDataItem<'a>>,
    pub reward: Reward,
    pub signature_data: V1SignatureData,
    pub denomination: Option<u32>,
}

impl<'a> V1TxData<'a> {
    pub fn tx_hash(&self) -> TxHash {
        if self.denomination.is_some() {
            TxHash::DeepHash(TxDeepHash::from_inner(self.deep_hash()))
        } else {
            let mut hasher = Sha256::new();
            self.feed(&mut hasher);
            TxHash::Shallow(TxShallowHash::from_inner(hasher.finalize()))
        }
    }

    fn into_owned(self) -> V1TxData<'static> {
        V1TxData {
            id: self.id,
            last_tx: self.last_tx.into_owned(),
            tags: self.tags.into_iter().map(|t| t.into_owned()).collect(),
            target: self.target,
            quantity: self.quantity,
            data_item: self.data_item.map(|d| d.into_owned()),
            reward: self.reward,
            signature_data: self.signature_data,
            denomination: self.denomination,
        }
    }
}

impl DeepHashable for V1TxData<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        let mut elements = Vec::with_capacity(8);
        if let Some(denomination) = self.denomination {
            elements.push(denomination.deep_hash());
        }
        elements.extend([
            self.signature_data.deep_hash(),
            self.target.deep_hash(),
            self.data_item.deep_hash(),
            self.quantity.deep_hash(),
            self.reward.deep_hash(),
            self.last_tx.deep_hash(),
            self.tags.deep_hash(),
        ]);
        Self::list(elements)
    }
}

impl Hashable for V1TxData<'_> {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.signature_data.feed(hasher);
        self.target.feed(hasher);
        self.data_item.feed(hasher);
        self.quantity.feed(hasher);
        self.reward.feed(hasher);
        self.last_tx.feed(hasher);
        self.tags.feed(hasher);
    }
}

#[derive(Error, Debug)]
pub enum V1TxDataError {
    #[error("expected format '1' but found '{0}")]
    IncorrectFormat(Format),
    #[error(transparent)]
    Common(#[from] CommonTxDataError),
    #[error(transparent)]
    Entity(#[from] entity::Error),
    #[error("v1 transactions only support RSA_PSS signatures, found: '{0}")]
    NonRsaSignatureType(SignatureType),
    #[error("data_size '{expected}' does not correspond to actual data size '{actual}'")]
    IncorrectDataSize { actual: u64, expected: u64 },
}

impl<'a> TryFrom<ValidatedRawTx<'a>> for V1TxData<'a> {
    type Error = V1TxDataError;

    fn try_from(raw: ValidatedRawTx<'a>) -> Result<Self, Self::Error> {
        let raw = raw.into_inner();
        if raw.format != Format::V1 {
            return Err(V1TxDataError::IncorrectFormat(raw.format));
        }

        let signature_type = raw.signature_type.unwrap_or_default();
        if signature_type != SignatureType::RsaPss {
            return Err(V1TxDataError::NonRsaSignatureType(signature_type));
        }

        let raw_owner = raw.owner.ok_or(MissingOwner)?;
        let signature_data = V1SignatureData::from_raw(raw_owner, raw.signature)?;

        let last_tx = LastTx::try_from(raw.last_tx)
            .map_err(|e| CommonTxDataError::InvalidLastTx(e.to_string()))?;

        let data = raw.data.map(|b| EmbeddedDataItem::from_inner(b));

        match (
            data.as_ref().map(|d| d.len() as u64).unwrap_or(0),
            raw.data_size,
        ) {
            (actual, expected) if actual != expected => {
                // incorrect length
                return Err(V1TxDataError::IncorrectDataSize { actual, expected });
            }
            _ => {
                // correct length, do nothing
            }
        }

        let common_data = CommonData::try_from_raw(
            raw.id,
            raw.tags,
            raw.target,
            raw.quantity,
            raw.reward,
            raw.denomination,
        )?;

        Ok(Self {
            id: common_data.id,
            last_tx,
            tags: common_data.tags,
            target: common_data.target,
            quantity: common_data.quantity,
            data_item: data,
            reward: common_data.reward,
            signature_data,
            denomination: common_data.denomination,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::entity;
    use crate::tx::raw::ValidatedRawTx;
    use crate::tx::v1::{TxError, UnauthenticatedV1Tx, V1SignatureData, V1TxDataError};
    use crate::tx::{Format, Quantity, Reward};
    use crate::validation::ValidateExt;
    use std::ops::Deref;
    use std::sync::LazyLock;

    static ZERO_QUANTITY: LazyLock<Quantity> = LazyLock::new(|| Quantity::zero());
    static TX_V1: &'static [u8] = include_bytes!("../../testdata/tx_v1.json");
    static TX_V1_2: &'static [u8] = include_bytes!("../../testdata/tx_v1_2.json");
    static TX_V1_INVALID_SIG: &'static [u8] =
        include_bytes!("../../testdata/tx_v1_invalid_sig.json");
    static TX_V2: &'static [u8] = include_bytes!("../../testdata/tx_v2.json");

    #[test]
    fn v1_hash() -> anyhow::Result<()> {
        let tx_data = UnauthenticatedV1Tx::from_json(TX_V1)?.0;
        assert_eq!(
            tx_data.id.to_base64(),
            "BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ"
        );

        let tx_hash = tx_data.tx_hash();
        let hash = tx_hash.as_slice();

        let expected: [u8; 32] = [
            0x38, 0xc0, 0xe2, 0x7a, 0x72, 0xbd, 0xa1, 0x40, 0x0f, 0x72, 0x61, 0x19, 0xda, 0xf7,
            0xac, 0x0f, 0x47, 0xfe, 0x0a, 0xba, 0x65, 0xca, 0xd6, 0x5a, 0x78, 0x78, 0x84, 0xe5,
            0x11, 0xce, 0x20, 0x57,
        ];

        assert_eq!(hash, expected);

        Ok(())
    }

    #[test]
    fn v1_hash_2() -> anyhow::Result<()> {
        let tx_data = UnauthenticatedV1Tx::from_json(TX_V1_2)?.0;
        assert_eq!(
            tx_data.id.to_base64(),
            "XnLdl7XiYIZoQ0pM6GcQeLLgYGsGwN9vM4E-kXa_rzY"
        );

        let tx_hash = tx_data.tx_hash();
        let hash = tx_hash.as_slice();

        let expected: [u8; 32] = [
            0xa9, 0x90, 0xda, 0x4d, 0xad, 0x24, 0xef, 0xf8, 0x97, 0x3f, 0xaf, 0xc2, 0x32, 0x11,
            0x4d, 0xbe, 0x1a, 0xdc, 0xbe, 0xfd, 0xf1, 0xa5, 0x1b, 0x1e, 0xce, 0xdb, 0x68, 0xef,
            0xe5, 0x5c, 0xc2, 0x99,
        ];

        assert_eq!(hash, expected);

        Ok(())
    }

    #[test]
    fn v1_verify_ok() -> anyhow::Result<()> {
        let unvalidated = UnauthenticatedV1Tx::from_json(TX_V1)?;
        let _validated = unvalidated.validate().map_err(|(_, e)| e)?;
        Ok(())
    }

    #[test]
    fn v1_verify_2_ok() -> anyhow::Result<()> {
        let unvalidated = UnauthenticatedV1Tx::from_json(TX_V1_2)?;
        let _validated = unvalidated.validate().map_err(|(_, e)| e)?;
        Ok(())
    }

    #[test]
    fn v1_raw_rountrip() -> anyhow::Result<()> {
        let unvalidated = UnauthenticatedV1Tx::from_json(TX_V1_2)?;
        let validated = unvalidated.validate().map_err(|(_, e)| e)?;
        let raw = ValidatedRawTx::from(validated);
        let json_string = raw.to_json_string()?;
        let unvalidated = UnauthenticatedV1Tx::from_json(&json_string)?;
        let _validated = unvalidated.validate().map_err(|(_, e)| e)?;
        Ok(())
    }

    #[test]
    fn v1_verify_invalid() -> anyhow::Result<()> {
        let tx = UnauthenticatedV1Tx::from_json(TX_V1_INVALID_SIG)?;
        match tx.validate() {
            Err((_, V1TxDataError::Entity(entity::Error::InvalidSignature(_)))) => {
                // ok
            }
            _ => unreachable!("signature validation failure expected"),
        }
        Ok(())
    }

    #[test]
    fn tx_data_ok_v1() -> anyhow::Result<()> {
        let tx_data = UnauthenticatedV1Tx::from_json(TX_V1)?.0;
        assert_eq!(
            tx_data.id.to_base64(),
            "BNttzDav3jHVnNiV7nYbQv-GY0HQ-4XXsdkE5K9ylHQ"
        );
        assert_eq!(
            tx_data.last_tx.to_base64(),
            "jUcuEDZQy2fC6T3fHnGfYsw0D0Zl4NfuaXfwBOLiQtA"
        );

        if let V1SignatureData::Rsa4096(rsa) = &tx_data.signature_data {
            assert_eq!(
                rsa.owner().to_base64(),
                "posmEh5k2_h7fgj-0JwB2l2AU72u-UizJOA2m8gyYYcVjh_6N3A3DhwbLmnbIWjVWmsidgQZDDibiJhhyHsy28ARxrt5BJ3OCa1VRAk2ffhbaUaGUoIkVt6G8mnnTScN9JNPS7UYEqG_L8J48c2tQNsydbon2ImKIwCYmnMHKcpyEgXcgLDGhtGhIKtkuI-QOAu-TMqVjn5EaWsfJTW5J-ty8mswAMSxepgsUbUB3GXZfCyOAK0EGjrClZ1MLvyc8ANGQfLPjwTipMcUtX47Udy8i4C-c-vLC9oB_z5ZCDCat-5wGh2OA-lyghro2SpkxX0e-D-nbi91Pp9LORwDZIRQ5RCMDvtQx1-QD2adxn_P2zDN0hk5IWXoCnHyeoj-IdNIyCXNkDzT2A184CxjReE5XOUF7UFeOmvVwbUTMfnNBOSWeRz3U_e3MPNlc2JTIprRLC8IegyfS6NdCr90lYnuviEr0g75NE6-muJdHAd9gu2QZ1MpkX9OnsbtvCvvFje-K_p_4AR9l43CLemfdSZeHHMIzdPwKe75SFMbsuklsyc-ieq-OHrJCeL0WrkLT4Gf6rpGVkS8MjORuMOBRFrHRE7XKswzhwmV2SuzeU6ojtPNP87aNdiUGHtYCIyt7cRN5bRbrVjdCAXj2NnuWMzM6J6dme4e2R8gqNpsEok"
            );
        } else {
            unreachable!()
        }

        assert_eq!(&tx_data.tags, &vec![]);
        assert!(tx_data.target.is_none());
        assert!(tx_data.denomination.is_none());
        assert_eq!(tx_data.quantity.as_ref().unwrap(), ZERO_QUANTITY.deref(),);
        assert_eq!(tx_data.data_item.as_ref().unwrap().len(), 1033478);
        //todo: verify data value
        assert_eq!(&tx_data.reward, &Reward::try_from("124145681682")?);
        Ok(())
    }

    #[test]
    fn v2_err() -> anyhow::Result<()> {
        match UnauthenticatedV1Tx::from_json(TX_V2) {
            Err(TxError::V1DataError(V1TxDataError::IncorrectFormat(f))) => {
                assert_eq!(f, Format::V2);
            }
            _ => unreachable!("should have been an incorrect format error"),
        }
        Ok(())
    }
}
