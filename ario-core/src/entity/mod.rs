pub mod ecdsa;
pub mod ed25519;
pub mod multi_aptos;
pub mod pss;

use crate::blob::{AsBlob, Blob};
use crate::crypto::ec::EcPublicKey;
use crate::crypto::ec::ecdsa::Ecdsa;
use crate::crypto::ec::ethereum::{Eip191, Eip712};
use crate::crypto::edwards::multi_aptos::{MultiAptosEd25519, MultiAptosVerifyingKey};
use crate::crypto::edwards::variants::{Aptos, Ed25519HexStr};
use crate::crypto::edwards::{Ed25519, Ed25519VerifyingKey};
use crate::crypto::rsa::RsaPublicKey;
use crate::crypto::rsa::pss::RsaPss;
use crate::crypto::signature::Scheme as SignatureScheme;
use crate::crypto::{keys, signature};
use crate::typed::WithSerde;
use crate::wallet::{Wallet, WalletAddress, WalletKind, WalletPk};
use k256::Secp256k1;
use maybe_owned::MaybeOwned;
use std::borrow::Cow;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error(transparent)]
    InvalidKey(#[from] keys::KeyError),
    #[error("signing failed: {0}")]
    SigningError(String),
}

pub trait ArEntityHash: ToSignableMessage + PartialEq + Clone + Send + Hash {}

pub type ArEntitySignature<T: ArEntityHash, S: SignatureScheme> =
    signature::TypedSignature<T, WalletKind, S>;

impl<T: ArEntityHash, S: SignatureScheme> WithSerde for ArEntitySignature<T, S> {}

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

#[derive(Clone, Debug)]
pub enum Owner<'a> {
    Rsa4096(MaybeOwned<'a, WalletPk<RsaPublicKey<4096>>>),
    Rsa2048(MaybeOwned<'a, WalletPk<RsaPublicKey<2048>>>),
    Secp256k1(MaybeOwned<'a, WalletPk<EcPublicKey<Secp256k1>>>),
    Ed25519(MaybeOwned<'a, WalletPk<Ed25519VerifyingKey>>),
    MultiAptos(MaybeOwned<'a, WalletPk<MultiAptosVerifyingKey>>),
}

impl<'a> Owner<'a> {
    pub fn into_owned(self) -> Owner<'static> {
        match self {
            Self::Rsa4096(inner) => Owner::Rsa4096(inner.into_owned().into()),
            Self::Rsa2048(inner) => Owner::Rsa2048(inner.into_owned().into()),
            Self::Secp256k1(inner) => Owner::Secp256k1(inner.into_owned().into()),
            Self::Ed25519(inner) => Owner::Ed25519(inner.into_owned().into()),
            Self::MultiAptos(inner) => Owner::MultiAptos(inner.into_owned().into()),
        }
    }
}

impl<'a> From<&'a Wallet> for Owner<'a> {
    fn from(value: &'a Wallet) -> Self {
        value.to_entity_owner()
    }
}

impl<'a> From<&'a WalletPk<RsaPublicKey<4096>>> for Owner<'a> {
    fn from(value: &'a WalletPk<RsaPublicKey<4096>>) -> Self {
        Self::Rsa4096(value.into())
    }
}

impl<'a> From<&'a WalletPk<RsaPublicKey<2048>>> for Owner<'a> {
    fn from(value: &'a WalletPk<RsaPublicKey<2048>>) -> Self {
        Self::Rsa2048(value.into())
    }
}

impl<'a> From<&'a WalletPk<EcPublicKey<Secp256k1>>> for Owner<'a> {
    fn from(value: &'a WalletPk<EcPublicKey<Secp256k1>>) -> Self {
        Self::Secp256k1(value.into())
    }
}

impl<'a> From<&'a WalletPk<Ed25519VerifyingKey>> for Owner<'a> {
    fn from(value: &'a WalletPk<Ed25519VerifyingKey>) -> Self {
        Self::Ed25519(value.into())
    }
}

impl<'a> From<&'a WalletPk<MultiAptosVerifyingKey>> for Owner<'a> {
    fn from(value: &'a WalletPk<MultiAptosVerifyingKey>) -> Self {
        Self::MultiAptos(value.into())
    }
}

impl<'a> Owner<'a> {
    pub fn address(&self) -> WalletAddress {
        match self {
            Self::Rsa4096(inner) => inner.derive_address(),
            Self::Rsa2048(inner) => inner.derive_address(),
            Self::Secp256k1(inner) => inner.derive_address(),
            Self::Ed25519(inner) => inner.derive_address(),
            Self::MultiAptos(inner) => inner.derive_address(),
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
            Self::MultiAptos(multi) => multi.as_blob(),
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
    MultiAptos(MaybeOwned<'a, ArEntitySignature<T, MultiAptosEd25519>>),
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
            Self::MultiAptos(multi) => multi.as_blob(),
            Self::Kyve(kyve) => kyve.as_blob(),
        }
    }
}
