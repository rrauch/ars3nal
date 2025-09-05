use crate::crypto::edwards::Ed25519;
use crate::crypto::hash::{Digest, Sha512HexStr};
use crate::crypto::signature::{Scheme, SchemeVariant};
use std::borrow::Cow;
use std::convert::Infallible;

pub struct Ed25519HexStr;

pub type Ed25519HexStrHasher = Sha512HexStr;

impl SchemeVariant for Ed25519HexStr {
    type Scheme = Ed25519;
    type Error = Infallible;
    type Message = Digest<Ed25519HexStrHasher>;

    fn process(msg: &Self::Message) -> Result<Cow<<Self::Scheme as Scheme>::Message>, Self::Error>
    where
        <Self::Scheme as Scheme>::Message: Clone,
    {
        Ok(Cow::Borrowed(msg.as_variant()))
    }
}
