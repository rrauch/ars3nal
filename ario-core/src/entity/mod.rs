pub mod ecdsa;
pub mod ed25519;
pub mod pss;

use crate::blob::{AsBlob, Blob};
use crate::crypto::ec::EcPublicKey;
use crate::crypto::ec::ecdsa::Ecdsa;
use crate::crypto::ec::ethereum::{Eip191, Eip712};
use crate::crypto::edwards::variants::{Aptos, Ed25519HexStr};
use crate::crypto::edwards::{Ed25519, Ed25519VerifyingKey};
use crate::crypto::rsa::RsaPublicKey;
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::signature::Scheme as SignatureScheme;
use crate::crypto::{keys, signature};
use crate::wallet::{WalletAddress, WalletKind, WalletPk};
use k256::Secp256k1;
use maybe_owned::MaybeOwned;
use std::borrow::Cow;
use std::fmt::{Debug, Display};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error(transparent)]
    InvalidKey(#[from] keys::KeyError),
}

pub trait ArEntityHash: ToSignableMessage + PartialEq + Clone + Send {}

pub type ArEntitySignature<T: ArEntityHash, S: SignatureScheme> =
    signature::TypedSignature<T, WalletKind, S>;

pub trait ArEntity {
    type Id: PartialEq + Clone + Debug + Display + Send;
    type Hash: ArEntityHash;

    fn id(&self) -> &Self::Id;
}

impl<H: ArEntityHash, S: SignatureScheme> MessageFor<S> for H
where
    for<'a> Cow<'a, <S as SignatureScheme>::Message<'a>>: From<&'a H>,
{
    fn message(&self) -> Cow<'_, S::Message<'_>> {
        self.into()
    }
}

pub(crate) trait MessageFor<S: SignatureScheme> {
    fn message(&self) -> Cow<'_, S::Message<'_>>;
}

pub(super) trait ToSignableMessage {
    fn to_signable_message<S: SignatureScheme>(&self) -> Cow<'_, S::Message<'_>>
    where
        Self: MessageFor<S>;
}

impl<T: ?Sized> ToSignableMessage for T {
    fn to_signable_message<S: SignatureScheme>(&self) -> Cow<'_, S::Message<'_>>
    where
        Self: MessageFor<S>,
    {
        self.message()
    }
}

#[derive(Debug)]
pub enum Owner<'a> {
    Rsa4096(MaybeOwned<'a, WalletPk<RsaPublicKey<4096>>>),
    Rsa2048(MaybeOwned<'a, WalletPk<RsaPublicKey<2048>>>),
    Secp256k1(MaybeOwned<'a, WalletPk<EcPublicKey<Secp256k1>>>),
    Ed25519(MaybeOwned<'a, WalletPk<Ed25519VerifyingKey>>),
}

impl<'a> Owner<'a> {
    pub fn address(&self) -> WalletAddress {
        match self {
            Self::Rsa4096(inner) => inner.derive_address(),
            Self::Rsa2048(inner) => inner.derive_address(),
            Self::Secp256k1(inner) => inner.derive_address(),
            Self::Ed25519(inner) => inner.derive_address(),
        }
    }
}

impl AsBlob for Owner<'_> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa4096(rsa) => rsa.as_blob(),
            Self::Rsa2048(rsa) => rsa.as_blob(),
            Self::Secp256k1(ec) => ec.as_blob(),
            Self::Ed25519(ed25519) => ed25519.as_blob(),
        }
    }
}

#[derive(Debug)]
pub enum Signature<'a, T: ArEntityHash> {
    Rsa4096(MaybeOwned<'a, ArEntitySignature<T, RsaPss<4096>>>),
    Rsa2048(MaybeOwned<'a, ArEntitySignature<T, RsaPss<2048>>>),
    Secp256k1(MaybeOwned<'a, ArEntitySignature<T, Ecdsa<Secp256k1>>>),
    Eip191(MaybeOwned<'a, ArEntitySignature<T, Eip191>>),
    Eip712(MaybeOwned<'a, ArEntitySignature<T, Eip712>>),
    Ed25519(MaybeOwned<'a, ArEntitySignature<T, Ed25519>>),
    Ed25519HexStr(MaybeOwned<'a, ArEntitySignature<T, Ed25519HexStr>>),
    Aptos(MaybeOwned<'a, ArEntitySignature<T, Aptos>>),
    Kyve(MaybeOwned<'a, ArEntitySignature<T, Eip191>>),
}

impl<T: ArEntityHash> AsBlob for Signature<'_, T> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa4096(pss) => pss.as_blob(),
            Self::Rsa2048(pss) => pss.as_blob(),
            Self::Secp256k1(ecdsa) => ecdsa.as_blob(),
            Self::Eip191(eip191) => eip191.as_blob(),
            Self::Eip712(eip712) => eip712.as_blob(),
            Self::Ed25519(ed25519) => ed25519.as_blob(),
            Self::Ed25519HexStr(ed25519) => ed25519.as_blob(),
            Self::Aptos(aptos) => aptos.as_blob(),
            Self::Kyve(kyve) => kyve.as_blob(),
        }
    }
}
