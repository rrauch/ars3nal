use crate::ContentType;
use ario_client::graphql::ItemId;
use ario_core::blob::OwnedBlob;
use chrono::{DateTime, Utc};
use derive_more::Display;
use std::collections::HashMap;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use typed_path::{Utf8Component, Utf8UnixEncoding, Utf8UnixPath, Utf8UnixPathBuf};
use uuid::Uuid;

const ROOT_INODE_ID: InodeId = InodeId(2);
const MIN_INODE_ID: usize = 1000;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    NameError(#[from] NameError),
    #[error(transparent)]
    InodeIdError(#[from] InodeIdError),
    #[error(transparent)]
    VfsPathError(#[from] VfsPathError),
}

#[derive(Error, Debug)]
pub enum NameError {
    #[error("Name cannot be empty")]
    Empty,
    #[error("Name cannot be '.' or '..'")]
    Reserved,
    #[error("Name contains invalid character")]
    InvalidCharacter,
    #[error("Name exceeds maximum length of 255 bytes")]
    TooLong,
    #[error("Name cannot have leading or trailing whitespace")]
    LeadingOrTrailingWhitespace,
}

#[derive(Error, Debug)]
pub enum InodeIdError {
    #[error("Inode Ids below {} are reserved", { MIN_INODE_ID })]
    Reserved,
}

#[derive(Error, Debug)]
pub enum VfsPathError {
    #[error("path contains invalid elements")]
    Invalid,
    #[error(transparent)]
    NameError(#[from] NameError),
    #[error("path is not absolute")]
    NotAbsolute,
}

pub struct Vfs {}

impl Vfs {
    pub async fn root(&self) -> Result<Directory, Error> {
        todo!()
    }

    pub async fn inode_by_id<I: TryInto<InodeId, Error = InodeIdError>>(
        &self,
        id: I,
    ) -> Result<Inode, Error> {
        let id = id.try_into()?;
        todo!()
    }

    pub async fn inode_by_path<P: TryInto<VfsPath, Error = VfsPathError>>(
        &self,
        path: P,
    ) -> Result<Inode, Error> {
        let path = path.try_into()?;
        todo!()
    }
}

#[derive(Debug, PartialEq, Clone, Display)]
#[repr(transparent)]
pub struct VfsPath(Arc<Utf8UnixPathBuf>);

impl VfsPath {
    pub fn try_from<S: AsRef<str> + ?Sized>(value: &S) -> Result<Self, VfsPathError> {
        TryFrom::<&str>::try_from(value.as_ref())
    }
}

impl TryFrom<&str> for VfsPath {
    type Error = VfsPathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let path = Utf8UnixPath::new(value);
        Ok(Self(Arc::new(sanitize_path(path)?)))
    }
}

impl TryFrom<String> for VfsPath {
    type Error = VfsPathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let path = Utf8UnixPathBuf::from(value);
        Ok(Self(Arc::new(sanitize_path(&path)?)))
    }
}

fn check_valid_filename(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }

    if name.trim() != name {
        return Err(NameError::LeadingOrTrailingWhitespace);
    }

    if name == "." || name == ".." {
        return Err(NameError::Reserved);
    }

    if name.len() > 255 {
        return Err(NameError::TooLong);
    }

    if name.chars().any(|c| {
        matches!(
            c,
            '/' | '\0' | '\\' | '*' | '?' | '"' | '<' | '>' | '|' | ':'
        ) || c.is_control()
    }) {
        return Err(NameError::InvalidCharacter);
    }

    Ok(())
}

fn sanitize_path(path: &Utf8UnixPath) -> Result<Utf8UnixPathBuf, VfsPathError> {
    let normalized = path.normalize();
    if !normalized.is_absolute() {
        return Err(VfsPathError::NotAbsolute);
    }
    if !normalized.is_valid() {
        return Err(VfsPathError::Invalid);
    }
    // extended validity test
    normalized.components().try_for_each(|c| {
        if let Some(file_name) = c.as_path::<Utf8UnixEncoding>().file_name() {
            check_valid_filename(file_name)
        } else {
            Ok(())
        }
    })?;

    Ok(normalized)
}

impl AsRef<str> for VfsPath {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Display)]
#[repr(transparent)]
pub struct InodeId(usize);

impl Deref for InodeId {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&InodeId> for InodeId {
    fn from(value: &InodeId) -> Self {
        Self(value.0)
    }
}

impl TryFrom<usize> for InodeId {
    type Error = InodeIdError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value < MIN_INODE_ID {
            Err(InodeIdError::Reserved)
        } else {
            Ok(InodeId(value))
        }
    }
}

pub type File = VfsNode<FileData>;
#[derive(Debug, PartialEq, Clone)]
struct FileData {
    size: u64,
    last_modified: DateTime<Utc>,
    content_type: ContentType,
    data_item_id: ItemId<'static>,
}

pub type Directory = VfsNode<DirData>;

#[derive(Debug, PartialEq, Clone)]
struct DirData;

#[derive(Debug, PartialEq, Clone)]
#[repr(transparent)]
struct Name(Arc<str>);

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        check_valid_filename(s)?;
        Ok(Name(Arc::from(s)))
    }
}

#[derive(Debug, PartialEq, Clone)]
struct VfsNode<T> {
    id: Uuid,
    name: Name,
    created_at: DateTime<Utc>,
    hidden: bool,
    extra: HashMap<String, OwnedBlob>,
    decryption: Option<Decryption>,
    inner: T,
}

#[derive(Debug, PartialEq, Clone)]
enum Decryption {
    Aes256Gcm(OwnedBlob),
    Aes256Ctr(OwnedBlob),
}

#[derive(Debug, PartialEq, Clone)]
pub enum Inode {
    Root(Directory),
    File(File),
    Directory(Directory),
}

#[cfg(test)]
mod tests {
    use crate::vfs::{NameError, VfsPath, VfsPathError};

    #[test]
    fn vfs_path() -> anyhow::Result<()> {
        let path = VfsPath::try_from("/foo/bar")?;
        assert_eq!(path.as_ref(), "/foo/bar");

        let path = VfsPath::try_from("/foo//bar")?;
        assert_eq!(path.as_ref(), "/foo/bar");

        let path = VfsPath::try_from("/foo/./bar")?;
        assert_eq!(path.as_ref(), "/foo/bar");

        let path = VfsPath::try_from("/foo/baz/../bar")?;
        assert_eq!(path.as_ref(), "/foo/bar");

        assert!(matches!(
            VfsPath::try_from("../foo/bar"),
            Err(VfsPathError::NotAbsolute)
        ));

        assert!(matches!(
            VfsPath::try_from("bar"),
            Err(VfsPathError::NotAbsolute)
        ));

        assert!(matches!(
            VfsPath::try_from(""),
            Err(VfsPathError::NotAbsolute)
        ));

        assert!(matches!(
            VfsPath::try_from("/|invalid|/bar"),
            Err(VfsPathError::NameError(NameError::InvalidCharacter))
        ));

        Ok(())
    }
}
