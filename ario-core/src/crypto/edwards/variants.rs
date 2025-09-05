use crate::crypto::edwards::Ed25519;
use crate::crypto::signature::{Scheme, SchemeVariant};
use ct_codecs::{Encoder, Hex};
use std::borrow::Cow;

pub struct Ed25519HexStr;

impl SchemeVariant for Ed25519HexStr {
    type Scheme = Ed25519;
    type Error = ct_codecs::Error;
    type Message = [u8];

    fn process(msg: &Self::Message) -> Result<Cow<<Self::Scheme as Scheme>::Message>, Self::Error> {
        // Encodes the msg in hex first before passing it on
        Ok(Cow::Owned(Hex::encode_to_string(msg)?.into_bytes()))
    }
}
