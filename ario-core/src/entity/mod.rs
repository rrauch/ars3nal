pub mod ecdsa;
pub mod ed25519;
pub mod pss;

use crate::blob::{AsBlob, Blob};
use crate::crypto::ec::EcPublicKey;
use crate::crypto::ec::ecdsa::Ecdsa;
use crate::crypto::edwards::variants::Ed25519HexStr;
use crate::crypto::edwards::{Ed25519, Ed25519VerifyingKey};
use crate::crypto::hash::{Digest, Hasher};
use crate::crypto::rsa::RsaPublicKey;
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::signature::{Scheme as SignatureScheme};
use crate::crypto::{keys, signature};
use crate::wallet::{WalletAddress, WalletKind, WalletPk};
use k256::Secp256k1;
use maybe_owned::MaybeOwned;
use std::fmt::{Debug, Display};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error(transparent)]
    InvalidKey(#[from] keys::KeyError),
}

pub trait ArEntityHash: ToSignPrehash + PartialEq + Clone + Send {}

pub type ArEntitySignature<T: ArEntityHash, S: SignatureScheme> =
    signature::TypedSignature<T, WalletKind, S>;

pub trait ArEntity {
    type Id: PartialEq + Clone + Debug + Display + Send;
    type Hash: ArEntityHash;

    fn id(&self) -> &Self::Id;
}

pub(crate) trait PrehashFor<H: Hasher> {
    fn prehash(&self) -> MaybeOwned<'_, Digest<H>>;
}

pub(super) trait ToSignPrehash {
    fn to_sign_prehash<H: Hasher>(&self) -> MaybeOwned<'_, Digest<H>>
    where
        Self: PrehashFor<H>;
}

impl<T: ?Sized> ToSignPrehash for T {
    fn to_sign_prehash<H: Hasher>(&self) -> MaybeOwned<'_, Digest<H>>
    where
        Self: PrehashFor<H>,
    {
        self.prehash()
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
    Ed25519(MaybeOwned<'a, ArEntitySignature<T, Ed25519>>),
    Ed25519HexStr(MaybeOwned<'a, ArEntitySignature<T, Ed25519HexStr>>),
}

impl<T: ArEntityHash> AsBlob for Signature<'_, T> {
    fn as_blob(&self) -> Blob<'_> {
        match self {
            Self::Rsa4096(pss) => pss.as_blob(),
            Self::Rsa2048(pss) => pss.as_blob(),
            Self::Secp256k1(ecdsa) => ecdsa.as_blob(),
            Self::Ed25519(ed25519) => ed25519.as_blob(),
            Self::Ed25519HexStr(ed25519) => ed25519.as_blob(),
        }
    }
}
