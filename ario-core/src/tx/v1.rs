use crate::keys;
use crate::keys::{Rsa4096, RsaPublicKey};
use crate::tx::raw::RawTxData;
use crate::tx::v1::DeserializationError::MissingOwner;
use crate::tx::{EmbeddedData, Format, LastTx, Quantity, Reward, Tag, TxId, TxSignature};
use crate::typed::FromInner;
use crate::wallet::{WalletAddress, WalletPKey};
use thiserror::Error;

#[derive(Debug, Clone)]
pub(crate) struct V1Tx {
    id: TxId,
    last_tx: LastTx,
    owner: WalletPKey<RsaPublicKey<Rsa4096>>,
    tags: Vec<Tag>,
    target: Option<WalletAddress>,
    quantity: Option<Quantity>,
    data_size: u64,
    data: Option<EmbeddedData>,
    reward: Option<Reward>,
    signature: TxSignature,
}

#[derive(Error, Debug)]
pub enum DeserializationError {
    #[error("expected format '1' but found '{0}")]
    IncorrectFormat(Format),
    #[error("no owner field found but mandatory")]
    MissingOwner,
    #[error("invalid id: {0}")]
    InvalidId(String),
    #[error("invalid last_tx: {0}")]
    InvalidLastTx(String),
    #[error(transparent)]
    InvalidKey(#[from] keys::KeyError),
}

impl<'a> TryFrom<RawTxData<'a>> for V1Tx {
    type Error = DeserializationError;

    fn try_from(raw: RawTxData) -> Result<Self, Self::Error> {
        if raw.format != Format::V1 {
            return Err(DeserializationError::IncorrectFormat(raw.format));
        }

        let id =
            TxId::try_from(raw.id).map_err(|e| DeserializationError::InvalidId(e.to_string()))?;
        let last_tx = LastTx::try_from(raw.last_tx)
            .map_err(|e| DeserializationError::InvalidLastTx(e.to_string()))?;

        let owner = match raw.owner {
            Some(owner) => {
                let pkey = RsaPublicKey::<Rsa4096>::try_from(owner)?;
                WalletPKey::from_inner(pkey)
            }
            None => {
                return Err(MissingOwner);
            }
        };

        /*let tags = raw
        .tags
        .into_iter()
        .map(|r| Tag2 {
            name: TagName2::try_from_blob(r.name).expect("conversion should never fail"),
            value: TagValue2::try_from_blob(r.value).expect("conversion should never fail"),
        })
        .collect::<Result<Vec<Tag2>, _>>()?;*/

        todo!()
    }
}
