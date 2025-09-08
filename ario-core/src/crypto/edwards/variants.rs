use crate::crypto::edwards::Ed25519;
use crate::crypto::signature::{Scheme, SchemeVariant};
use ct_codecs::{Encoder, Hex};
use std::borrow::Cow;

pub struct Ed25519HexStr;

impl SchemeVariant for Ed25519HexStr {
    type Scheme = Ed25519;
    type Error = ct_codecs::Error;
    type Message<'a> = [u8];

    fn process<'m>(
        msg: &Self::Message<'m>,
    ) -> Result<Cow<'m, <Self::Scheme as Scheme>::Message<'m>>, Self::Error> {
        // Encodes the msg in hex first before passing it on
        Ok(Cow::Owned(Hex::encode_to_string(msg)?.into_bytes()))
    }
}

pub struct Aptos;

impl SchemeVariant for Aptos {
    type Scheme = Ed25519;
    type Error = ct_codecs::Error;
    type Message<'a> = [u8];

    fn process<'m>(
        msg: &Self::Message<'m>,
    ) -> Result<Cow<'m, <Self::Scheme as Scheme>::Message<'m>>, Self::Error> {
        // Encodes the msg in hex first before, then wraps it in a prefix & suffix.
        Ok(Cow::Owned(
            format!(
                "APTOS\nmessage: {}\nnonce: bundlr",
                Hex::encode_to_string(msg)?
            )
            .into_bytes(),
        ))
    }
}
