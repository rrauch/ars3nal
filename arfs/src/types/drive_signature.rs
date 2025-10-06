use crate::types::{BytesToStr, Chain, Cipher, DisplayFromStr, Entity, Model, SignatureFormat};
use ario_core::blob::{Blob, OwnedBlob};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};

#[derive(Debug)]
pub struct DriveSignatureKind;

impl Entity for DriveSignatureKind {
    const TYPE: &'static str = "drive-signature";
    type Header = DriveSignatureHeader;
    type Metadata = ();
}

pub(crate) type DriveSignatureEntity = Model<DriveSignatureKind>;

impl DriveSignatureEntity {
    pub fn signature_format(&self) -> SignatureFormat {
        self.header.inner.signature_format
    }

    pub fn cipher(&self) -> Option<Cipher> {
        self.header.inner.cipher
    }

    pub fn cipher_iv(&self) -> Blob<'_> {
        self.header.inner.cipher_iv.borrow()
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct DriveSignatureHeader {
    #[serde_as(as = "Chain<(BytesToStr, DisplayFromStr)>")]
    #[serde(rename = "Signature-Format")]
    signature_format: SignatureFormat,
    #[serde_as(as = "Option<Chain<(BytesToStr, DisplayFromStr)>>")]
    #[serde(default, rename = "Cipher")]
    cipher: Option<Cipher>,
    #[serde(rename = "Cipher-IV")]
    cipher_iv: OwnedBlob,
    //data: Blob<'a>,
}

#[cfg(test)]
mod tests {
    use crate::ArFsVersion;
    use crate::types::drive_signature::{
        DriveSignatureEntity, DriveSignatureHeader, DriveSignatureKind,
    };
    use crate::types::{Cipher, Header, Metadata, SignatureFormat};
    use ario_client::location::ItemArl;
    use ario_core::BlockNumber;
    use ario_core::blob::Blob;
    use ario_core::tag::Tag;
    use std::str::FromStr;

    #[test]
    fn drive_signature_entity_roundtrip() -> anyhow::Result<()> {
        let tags = vec![
            Tag::from((Blob::from("ArFS".as_bytes()), Blob::from("0.15".as_bytes()))),
            Tag::from((
                Blob::from("Signature-Format".as_bytes()),
                Blob::from("1".as_bytes()),
            )),
            Tag::from((
                Blob::from("Cipher".as_bytes()),
                Blob::from("AES256-GCM".as_bytes()),
            )),
            Tag::from((
                Blob::from("Cipher-IV".as_bytes()),
                Blob::from("todo".as_bytes()),
            )),
            Tag::from((
                Blob::from("Entity-Type".as_bytes()),
                Blob::from("drive-signature".as_bytes()),
            )),
        ];

        let header = Header::<DriveSignatureHeader, DriveSignatureKind>::try_from(&tags)?;
        let sig_entity = DriveSignatureEntity::new(
            header,
            Metadata::none(),
            BlockNumber::from_inner(1),
            ItemArl::from_str("ar://item/Y0wJvUkHFhcJZAduC8wfaiaDMHkrCoqHMSkenHD75VU").unwrap(),
        );

        assert_eq!(
            sig_entity.header().version(),
            &ArFsVersion::from_str("0.15")?
        );

        assert_eq!(
            sig_entity.header().inner.signature_format,
            SignatureFormat::V1
        );
        assert_eq!(sig_entity.header().inner.cipher, Some(Cipher::Aes256Gcm));
        //todo: check iv && data

        // roundtrip testing

        let tags2: Vec<Tag<'_>> = sig_entity.header().try_into()?;

        let header2 = Header::<DriveSignatureHeader, DriveSignatureKind>::try_from(&tags2)?;
        let _tags3: Vec<Tag<'_>> = (&header2).try_into()?;

        assert_eq!(sig_entity.header(), &header2);

        Ok(())
    }
}
