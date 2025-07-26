extern crate core;
use crate::hash::Sha256Hasher;
pub use rsa::BoxedUint as BigUint;
pub use rsa::Error as RsaError;
pub use serde_json::Error as JsonError;
pub use serde_json::Value as JsonValue;
use std::marker::PhantomData;

pub mod tx;

pub(crate) mod base64;
pub mod blob;
pub mod hash;
pub mod keys;
pub mod money;
pub mod signature;
pub mod typed;
mod validation;
pub mod wallet;
mod json;
//pub struct DriveKind;
//pub type DriveId = id::TypedUuid<DriveKind>;

//pub struct FolderKind;
//pub type FolderId = id::TypedUuid<FolderKind>;

//pub struct FileKind;
//pub type FileId = id::TypedUuid<FileKind>;

pub struct AddressKind<T>(PhantomData<T>);
pub type Address<T> = hash::TypedDigest<AddressKind<T>, Sha256Hasher>;
