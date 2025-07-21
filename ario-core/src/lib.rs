pub use rsa::BoxedUint as BigUint;
pub use rsa::Error as RsaError;
use std::marker::PhantomData;

pub mod id;
pub mod tx;

mod base64;
pub mod blob;
pub mod keys;
pub mod money;
pub(crate) mod serde;
mod stringify;
pub mod typed;
pub mod wallet;

pub struct DriveKind;
pub type DriveId = id::TypedUuid<DriveKind>;

pub struct FolderKind;
pub type FolderId = id::TypedUuid<FolderKind>;

pub struct FileKind;
pub type FileId = id::TypedUuid<FileKind>;

pub struct AddressKind<T>(PhantomData<T>);
pub type Address<T> = id::Typed256B64Id<AddressKind<T>>;
