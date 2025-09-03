use crate::crypto::edwards::Ed25519;
use crate::crypto::hash::{Digest, Sha512HexStr};
use crate::crypto::signature::{Scheme, SchemeVariant};
use std::convert::Infallible;

pub struct Ed25519HexStr;

pub type Ed25519HexStrHasher = Sha512HexStr;

impl SchemeVariant for Ed25519HexStr {
    type Scheme = Ed25519;
    type Error = Infallible;
    type Message<'a> = &'a Digest<Ed25519HexStrHasher>;

    fn process(
        msg: Self::Message<'_>,
    ) -> Result<<Self::Scheme as Scheme>::Message<'_>, Self::Error> {
        Ok(msg.as_variant())
    }
}
