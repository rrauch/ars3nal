use crate::db::{DataError, Db, Read, Transaction, TxScope};
use crate::types::file::{FileEntity, FileKind};
use crate::types::folder::{FolderEntity, FolderKind};
use crate::types::{Entity, Model};
use crate::wal::WalNode;
use crate::{CacheSettings, ContentType, Visibility, db, wal};
use ario_client::location::Arl;
use ario_client::{ByteSize, Client};
use ario_core::blob::Blob;
use ario_core::wallet::WalletAddress;
use chrono::{DateTime, Utc};
use derive_more::Display;
use futures_lite::{AsyncRead, AsyncSeek, AsyncWrite, AsyncWriteExt, Stream, StreamExt, stream};
use maybe_owned::MaybeOwnedMut;
use moka::future::Cache;
use ouroboros::self_referencing;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::io::SeekFrom;
use std::ops::Deref;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::task::{Context, Poll};
use thiserror::Error;
use typed_path::{Utf8UnixEncoding, Utf8UnixPath, Utf8UnixPathBuf};

pub(crate) const ROOT_INODE_ID: InodeId = InodeId(2);
static ROOT_NAME: LazyLock<Name> =
    LazyLock::new(|| Name::from_str("ROOT").expect("ROOT should be a valid name"));
pub(crate) static ROOT_PATH: LazyLock<VfsPath> =
    LazyLock::new(|| VfsPath::try_from("/").expect("/ to be valid Root path"));

const MIN_INODE_ID: u64 = 1000;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    NameError(#[from] NameError),
    #[error(transparent)]
    InodeIdError(#[from] InodeIdError),
    #[error(transparent)]
    VfsPathError(#[from] VfsPathError),
    #[error(transparent)]
    DbError(#[from] db::Error),
    #[error(transparent)]
    CachedDbError(Arc<db::Error>),
    #[error(transparent)]
    CachedError(Arc<Error>),
    #[error(transparent)]
    InodeError(#[from] InodeError),
    #[error("An Inode with name '{0}' already exists on same level")]
    NameAlreadyExists(Name),
    #[error(transparent)]
    InvalidOperation(#[from] InvalidOperation),
}

#[derive(Error, Debug)]
pub enum InvalidOperation {
    #[error("cannot replace existing directory at '{0}'")]
    ReplaceDir(VfsPath),
    #[error("cannot replace file system root")]
    ReplaceRoot,
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
pub enum InodeError {
    #[error("Inode with id '{0}' not found")]
    NotFound(InodeId),
    #[error("Inode at '{0}' not found")]
    NotFoundByPath(VfsPath),
    #[error("Parent needs to be a directory or root")]
    ParentNotDirOrRoot,
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

pub type Timestamp = DateTime<Utc>;

#[derive(Debug, Clone)]
pub struct Vfs(Arc<VfsInner>);

type PathCache = Cache<VfsPath, Option<InodeId>>;
type InodeCache = Cache<InodeId, Option<Inode>>;
type DirCache = Cache<InodeId, Vec<Inode>>;

#[derive(Debug)]
struct VfsInner {
    client: Client,
    db: Db,
    stats: Arc<Stats>,
    root: Mutex<Root>,
    path_cache: PathCache,
    inode_cache: InodeCache,
    dir_cache: DirCache,
    wal_chunk_size: u32,
}

#[derive(Debug)]
pub struct Stats {
    pub(crate) num_files: usize,
    pub(crate) num_dirs: usize,
    pub(crate) total_size: ByteSize,
    pub(crate) last_modified: Timestamp,
}

async fn stats(db: &Db) -> Result<Stats, crate::Error> {
    Ok(db.read().await?.stats().await?)
}

async fn root<C: TxScope>(
    conn: &mut Transaction<C>,
    path_cache: &PathCache,
    inode_cache: &InodeCache,
) -> Result<Root, crate::Error>
where
    Transaction<C>: Read,
{
    let config = conn.config().await?;
    let ts = config.drive.timestamp().clone();

    let ids = conn.list_root().await?;
    let content = inode_ids_to_inodes(inode_cache, path_cache, ids.into_iter(), conn).await?;

    let root = Root(Arc::new(RootInner {
        last_modified: ts,
        content,
    }));

    Ok(root)
}

impl Vfs {
    pub(super) async fn new(
        client: Client,
        db: Db,
        cache_settings: CacheSettings,
        wal_chunk_size: u32,
    ) -> Result<Self, crate::Error> {
        let path_cache = Cache::builder()
            .name("path_cache")
            .support_invalidation_closures()
            .max_capacity(cache_settings.path_cache_capacity)
            .time_to_live(cache_settings.path_cache_ttl)
            .build();
        let inode_cache = Cache::builder()
            .name("inode_cache")
            .support_invalidation_closures()
            .max_capacity(cache_settings.inode_cache_capacity)
            .time_to_live(cache_settings.inode_cache_ttl)
            .build();
        let dir_cache = Cache::builder()
            .name("dir_cache")
            .support_invalidation_closures()
            .max_capacity(cache_settings.dir_cache_capacity)
            .time_to_live(cache_settings.dir_cache_ttl)
            .build();

        let stats = stats(&db).await?;
        let root = root(&mut db.read().await?, &path_cache, &inode_cache).await?;
        Ok(Self(Arc::new(VfsInner {
            client,
            db,
            stats: Arc::new(stats),
            root: Mutex::new(root),
            path_cache,
            inode_cache,
            dir_cache,
            wal_chunk_size,
        })))
    }

    pub(crate) async fn invalidate_cache(&self, ids: Vec<InodeId>) {
        let ids = Arc::new(ids);
        {
            let ids = ids.clone();
            let _ = self
                .0
                .path_cache
                .invalidate_entries_if(move |_, v| match v {
                    Some(id) => ids.contains(id),
                    None => true, // invalidate all None-entries
                });
        }
        {
            let ids = ids.clone();
            let _ = self
                .0
                .inode_cache
                .invalidate_entries_if(move |k, _| ids.contains(k));
        }
        {
            let ids = ids.clone();
            let _ = self.0.dir_cache.invalidate_entries_if(move |k, v| {
                if ids.contains(k) {
                    true
                } else {
                    v.iter().find(|inode| ids.contains(&inode.id())).is_some()
                }
            });
        }

        let _ = self.reload_root().await; //todo: logging
    }

    async fn reload_root(&self) -> Result<(), crate::Error> {
        let root = root(
            &mut self.0.db.read().await?,
            &self.0.path_cache,
            &self.0.inode_cache,
        )
        .await?;
        let mut guard = self.0.root.lock().expect("to acquire lock");
        *guard = root;
        Ok(())
    }

    pub fn root(&self) -> Root {
        self.0.root.lock().expect("to acquire lock").clone()
    }

    pub async fn inode_by_id(&self, id: InodeId) -> Result<Option<Inode>, Error> {
        self._inode_by_id::<db::ReadOnly>(id, None).await
    }

    async fn _inode_by_id<C: TxScope>(
        &self,
        id: InodeId,
        conn: Option<&mut Transaction<C>>,
    ) -> Result<Option<Inode>, Error>
    where
        Transaction<C>: db::Read,
    {
        if id == ROOT_INODE_ID {
            return Ok(Some(Inode::Root(self.root())));
        }

        let db = &self.0.db;
        let path_cache = &self.0.path_cache;
        Ok(self
            .0
            .inode_cache
            .try_get_with(id, async {
                let res = match conn {
                    Some(conn) => conn.inode_by_id(id).await,
                    None => db.read().await?.inode_by_id(id).await,
                };

                match res? {
                    Some(inode) => {
                        path_cache
                            .insert(inode.path().clone(), Some(inode.id()))
                            .await;
                        Ok(Some(inode))
                    }
                    None => Ok(None),
                }
            })
            .await
            .map_err(Error::CachedDbError)?)
    }

    pub async fn inode_by_path(&self, path: &VfsPath) -> Result<Option<Inode>, Error> {
        let conn = self.0.db.read().await?;
        self._inode_by_path(path, conn).await
    }

    async fn _inode_by_path<'tx, C: TxScope>(
        &self,
        path: &VfsPath,
        conn: impl Into<MaybeOwnedMut<'tx, Transaction<C>>> + Send,
    ) -> Result<Option<Inode>, Error>
    where
        Transaction<C>: Read,
    {
        if path == ROOT_PATH.deref() {
            return Ok(Some(Inode::Root(self.root())));
        }
        let mut conn = conn.into();

        let id = match self
            .0
            .path_cache
            .try_get_with_by_ref(path, async { conn.inode_id_by_path(path.as_ref()).await })
            .await
            .map_err(Error::CachedDbError)?
        {
            Some(id) => id,
            None => return Ok(None),
        };

        self._inode_by_id(id, Some(&mut conn)).await
    }

    async fn _list<'tx, L: Listable, C: TxScope>(
        &self,
        listable: &L,
        conn: impl Into<MaybeOwnedMut<'tx, Transaction<C>>> + Send,
    ) -> Result<impl Stream<Item = Result<Inode, Error>> + Send + Unpin, Error>
    where
        Transaction<C>: Read,
    {
        Ok(listable.list(self, conn).await?)
    }

    pub async fn list<'a>(
        &'a self,
        inode: &'a Inode,
    ) -> Result<impl Stream<Item = Result<Inode, Error>> + Send + Unpin + 'a, Error> {
        Ok(match inode {
            Inode::Root(root) => Box::pin(self._list(root, self.0.db.read().await?).await?)
                as Pin<Box<dyn Stream<Item = Result<Inode, Error>> + Send + Unpin>>,
            Inode::Directory(dir) => Box::pin(self._list(dir, self.0.db.read().await?).await?)
                as Pin<Box<dyn Stream<Item = Result<Inode, Error>> + Send + Unpin>>,
            Inode::File(_) => Box::pin(stream::empty())
                as Pin<Box<dyn Stream<Item = Result<Inode, Error>> + Send + Unpin>>,
        })
    }

    pub async fn read_file(&self, file: &File) -> Result<FileHandle<ReadOnly>, crate::Error> {
        match &file.0.inner {
            Variant::Permanent(model) => self.open_perma_file(model).await,
            Variant::Wal(wal_node) => self.open_wal_file(wal_node, file.size()).await,
        }
    }

    async fn open_wal_file(
        &self,
        wal_node: &WalNode,
        expected_size: ByteSize,
    ) -> Result<FileHandle<ReadOnly>, crate::Error> {
        match wal_node {
            WalNode::File(wal_file_id) => {
                let reader =
                    wal::file_reader::FileReader::open(*wal_file_id, self.0.db.read().await?)
                        .await?;
                if reader.len() != expected_size.as_u64() {
                    Err(wal::Error::InvalidFileSize(
                        expected_size.as_u64(),
                        reader.len(),
                    ))?
                }
                Ok(FileHandle(ReadOnly(Box::new(reader))))
            }
            WalNode::Directory => Err(wal::Error::InvalidWalNodeType(
                "File".to_string(),
                "Directory".to_string(),
            ))?,
        }
    }

    async fn open_perma_file(
        &self,
        model: &Model<FileKind>,
    ) -> Result<FileHandle<ReadOnly>, crate::Error> {
        let data_location = model.data_location().ok_or_else(|| {
            db::Error::from(DataError::MissingData(
                "data_location not set for file".to_ascii_lowercase(),
            ))
        })?;
        let reader = self.0.client.read_any(data_location).await?;
        Ok(FileHandle(ReadOnly(Box::new(reader))))
    }

    pub async fn find(
        &self,
        prefix: Option<&str>,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<(Vec<Inode>, bool), crate::Error> {
        let mut conn = self.0.db.read().await?;
        let (ids, has_more) = conn
            .find_inodes(prefix, delimiter, start_after, max_keys)
            .await?;
        let mut matches = Vec::with_capacity(ids.len());
        for id in ids {
            let inode = self
                ._inode_by_id(id, Some(&mut conn))
                .await?
                .ok_or(crate::Error::VfsError(InodeError::NotFound(id).into()))?;
            matches.push(inode);
        }
        Ok((matches, has_more))
    }

    pub async fn create_file(
        &self,
        dir: &VfsPath,
        name: &Name,
        last_modified: Option<DateTime<Utc>>,
        content_type: Option<ContentType>,

        overwrite_existing: bool,
        create_dirs: bool,
    ) -> Result<FileHandle<WriteOnly>, crate::Error> {
        let mut tx = self.0.db.write().await?;

        let dir = match self._inode_by_path(dir, &mut tx).await? {
            Some(inode) => inode,
            None if create_dirs => {
                todo!()
            }
            None => Err(Error::InodeError(InodeError::NotFoundByPath(dir.clone())))?,
        };

        let path = match dir {
            Inode::Root(_) | Inode::Directory(_) => dir.path().join(name),
            Inode::File(_) => Err(Error::InodeError(InodeError::ParentNotDirOrRoot))?,
        };

        let file_exists = match self._inode_by_path(&path, &mut tx).await? {
            Some(Inode::Directory(_)) => Err(Error::InvalidOperation(
                InvalidOperation::ReplaceDir(path.clone()),
            ))?,
            Some(Inode::Root(_)) => Err(Error::InvalidOperation(InvalidOperation::ReplaceRoot))?,
            Some(Inode::File(_)) => true,
            None => false,
        };

        if file_exists && !overwrite_existing {
            Err(Error::NameAlreadyExists(name.clone()))?
        }

        Ok(FileHandle::<WriteOnly>::new(
            self.0.wal_chunk_size,
            tx,
            path,
            self.clone(),
            last_modified,
        )
        .await?)
    }
}

trait FileReader: AsyncRead + AsyncSeek + Send + Sync + Unpin {}
impl<T> FileReader for T where T: AsyncRead + AsyncSeek + Send + Sync + Unpin {}

pub struct ReadOnly(Box<dyn FileReader>);

#[repr(transparent)]
pub struct FileHandle<T>(T);

impl AsyncRead for FileHandle<ReadOnly> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0.0).poll_read(cx, buf)
    }
}

impl AsyncSeek for FileHandle<ReadOnly> {
    #[inline]
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<std::io::Result<u64>> {
        Pin::new(&mut self.0.0).poll_seek(cx, pos)
    }
}

#[self_referencing]
pub struct WriteOnly {
    tx: Transaction<db::ReadWrite>,
    path: VfsPath,
    vfs: Vfs,
    last_modified: Option<DateTime<Utc>>,
    #[not_covariant]
    #[borrows(mut tx)]
    writer: wal::file_writer::FileWriter<'this, db::ReadWrite>,
}

impl FileHandle<WriteOnly> {
    pub(crate) async fn new(
        chunk_size: u32,
        tx: Transaction<db::ReadWrite>,
        path: VfsPath,
        vfs: Vfs,
        last_modified: Option<DateTime<Utc>>,
    ) -> Result<Self, crate::Error> {
        let write_only = WriteOnly::try_new_async_send(tx, path, vfs, last_modified, |tx| {
            Box::pin(async move { wal::file_writer::FileWriter::new(chunk_size, tx).await })
        })
        .await?;

        Ok(Self(write_only))
    }
}

impl FileHandle<WriteOnly> {
    pub async fn finalize(mut self) -> Result<File, crate::Error> {
        self.close().await?;
        let (wal_entity_id, bytes_written) = self
            .0
            .with_writer(|writer| (writer.file_id(), writer.bytes_written()));
        let mut heads = self.0.into_heads();
        let last_modified = heads.last_modified.unwrap_or_else(|| Utc::now());
        let size = ByteSize::b(bytes_written);
        let (inode_id, affected_ids) = heads
            .tx
            .upsert_vfs_file(&heads.path, &last_modified, size, wal_entity_id)
            .await?;

        let file = match heads.tx.inode_by_id(inode_id).await? {
            Some(Inode::File(file)) => file,
            None => Err(wal::Error::FileNotFound(inode_id.0))?,
            _ => Err(wal::Error::InvalidWalNodeType(
                "File".to_string(),
                "not a file".to_string(),
            ))?,
        };
        heads.tx.commit().await?;
        heads.vfs.invalidate_cache(affected_ids).await;

        Ok(file)
    }
}

impl AsyncWrite for FileHandle<WriteOnly> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0
            .with_writer_mut(|writer| Pin::new(writer).poll_write(cx, buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.0
            .with_writer_mut(|writer| Pin::new(writer).poll_flush(cx))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.0
            .with_writer_mut(|writer| Pin::new(writer).poll_close(cx))
    }
}

trait Listable {
    fn list<'tx, C: TxScope>(
        &self,
        vfs: &Vfs,
        conn: impl Into<MaybeOwnedMut<'tx, Transaction<C>>> + Send,
    ) -> impl Future<Output = Result<impl Stream<Item = Result<Inode, Error>> + Send + Unpin, Error>>
    + Send
    where
        Transaction<C>: Read;
}

impl Listable for Root {
    async fn list<'tx, C: TxScope>(
        &self,
        _: &Vfs,
        _: impl Into<MaybeOwnedMut<'tx, Transaction<C>>> + Send,
    ) -> Result<impl Stream<Item = Result<Inode, Error>> + Send + Unpin, Error>
    where
        Transaction<C>: Read,
    {
        Ok(stream::iter(self.0.content.iter().map(|i| Ok(i.clone()))))
    }
}

impl Listable for Directory {
    async fn list<'tx, C: TxScope>(
        &self,
        vfs: &Vfs,
        conn: impl Into<MaybeOwnedMut<'tx, Transaction<C>>> + Send,
    ) -> Result<impl Stream<Item = Result<Inode, Error>> + Send + Unpin, Error>
    where
        Transaction<C>: Read,
    {
        let mut conn = conn.into();
        let id = self.0.id;
        let inode_cache = &vfs.0.inode_cache;
        let path_cache = &vfs.0.path_cache;

        let content = vfs
            .0
            .dir_cache
            .try_get_with(id, async {
                let ids = conn.as_mut().list_dir(id).await?;
                inode_ids_to_inodes(inode_cache, path_cache, ids.into_iter(), conn.as_mut()).await
            })
            .await
            .map_err(Error::CachedError)?;

        Ok(stream::iter(content.into_iter().map(|i| Ok(i))))
    }
}

async fn inode_ids_to_inodes<C: TxScope>(
    inode_cache: &InodeCache,
    path_cache: &PathCache,
    inode_ids: impl Iterator<Item = InodeId>,
    conn: &mut Transaction<C>,
) -> Result<Vec<Inode>, Error>
where
    Transaction<C>: Read,
{
    let mut inodes = vec![];
    for id in inode_ids {
        if let Some(inode) = inode_cache.get(&id).await.flatten() {
            inodes.push(inode);
        } else {
            match conn.inode_by_id(id).await? {
                Some(inode) => {
                    inode_cache.insert(id, Some(inode.clone())).await;
                    path_cache.insert(inode.path().clone(), Some(id)).await;
                    inodes.push(inode);
                }
                None => Err(InodeError::NotFound(id))?,
            }
        }
    }
    Ok(inodes)
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Display)]
#[repr(transparent)]
pub struct VfsPath(Arc<Utf8UnixPathBuf>);

impl VfsPath {
    pub fn try_from<S: AsRef<str> + ?Sized>(value: &S) -> Result<Self, VfsPathError> {
        TryFrom::<&str>::try_from(value.as_ref())
    }

    pub fn join(&self, name: &Name) -> VfsPath {
        Self(Arc::new(self.0.as_path().join(name.as_ref())))
    }

    pub fn split(&self) -> (Option<VfsPath>, Option<Name>) {
        (
            self.0.parent().map(|p| Self(Arc::new(p.to_path_buf()))),
            self.0
                .file_name()
                .map(|n| Name::from_str(n).expect("name to be valid")),
        )
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
        matches!(c, '/' | '\0' | '\\' | '*' | '"' | '<' | '>' | '|' | ':') || c.is_control()
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Display)]
#[repr(transparent)]
pub struct InodeId(u64);

impl Deref for InodeId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&InodeId> for InodeId {
    fn from(value: &InodeId) -> Self {
        Self(value.0)
    }
}

impl TryFrom<u64> for InodeId {
    type Error = InodeIdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value < MIN_INODE_ID {
            Err(InodeIdError::Reserved)
        } else {
            Ok(InodeId(value))
        }
    }
}

pub type File = VfsNode<FileKind>;

impl File {
    pub(crate) fn new_permanent(
        id: InodeId,
        name: Name,
        size: ByteSize,
        last_modified: Timestamp,
        visibility: Visibility,
        path: VfsPath,
        entity: FileEntity,
    ) -> Self {
        Self(Arc::new(VfsNodeInner {
            id,
            name,
            last_modified,
            size,
            visibility,
            path,
            inner: Variant::Permanent(entity),
        }))
    }

    pub(crate) fn new_wal(
        id: InodeId,
        name: Name,
        size: ByteSize,
        last_modified: Timestamp,
        visibility: Visibility,
        path: VfsPath,
        wal_entity_id: u64,
    ) -> Self {
        Self(Arc::new(VfsNodeInner {
            id,
            name,
            last_modified,
            size,
            visibility,
            path,
            inner: Variant::Wal(WalNode::File(wal_entity_id)),
        }))
    }

    pub fn content_type(&self) -> &ContentType {
        match &self.0.inner {
            Variant::Permanent(model) => model.content_type(),
            Variant::Wal(_) => &ContentType::Binary,
        }
    }

    pub fn size(&self) -> ByteSize {
        self.0.size
    }

    pub fn pinned_owner(&self) -> Option<&WalletAddress> {
        match &self.0.inner {
            Variant::Permanent(model) => model.pinned_data_owner(),
            Variant::Wal(_) => None,
        }
    }

    pub fn data_location(&self) -> Option<&Arl> {
        match &self.0.inner {
            Variant::Permanent(model) => model.data_location(),
            Variant::Wal(_) => None,
        }
    }
}

pub type Directory = VfsNode<FolderKind>;

impl Directory {
    pub(crate) fn new_permanent(
        id: InodeId,
        name: Name,
        last_modified: Timestamp,
        visibility: Visibility,
        path: VfsPath,
        entity: FolderEntity,
    ) -> Self {
        Self(Arc::new(VfsNodeInner {
            id,
            name,
            last_modified,
            size: ByteSize::b(0),
            visibility,
            path,
            inner: Variant::Permanent(entity),
        }))
    }

    pub(crate) fn new_wal(
        id: InodeId,
        name: Name,
        last_modified: Timestamp,
        visibility: Visibility,
        path: VfsPath,
    ) -> Self {
        Self(Arc::new(VfsNodeInner {
            id,
            name,
            last_modified,
            size: ByteSize::b(0),
            visibility,
            path,
            inner: Variant::Wal(WalNode::Directory),
        }))
    }
}

#[derive(Debug, PartialEq, Clone)]
#[repr(transparent)]
pub struct Name(Arc<str>);

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

impl Display for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.0.deref(), f)
    }
}

#[derive(Debug, PartialEq, Clone)]
#[repr(transparent)]
pub struct VfsNode<E: Entity>(Arc<VfsNodeInner<E>>);

impl<E: Entity> VfsNode<E> {
    #[inline]
    pub fn id(&self) -> InodeId {
        self.0.id
    }

    #[inline]
    pub fn name(&self) -> &Name {
        &self.0.name
    }

    #[inline]
    pub fn last_modified(&self) -> &Timestamp {
        &self.0.last_modified
    }

    #[inline]
    pub fn is_hidden(&self) -> bool {
        match self.0.visibility {
            Visibility::Visible => false,
            Visibility::Hidden => true,
        }
    }

    #[inline]
    pub fn path(&self) -> &VfsPath {
        &self.0.path
    }

    pub fn extra_attributes(&self) -> HashMap<&str, Blob<'_>> {
        match &self.0.inner {
            Variant::Permanent(model) => model
                .extra_attribute_names()
                .filter_map(|name| {
                    if let Some(value) = model.extra_attribute(name) {
                        Some((name, value))
                    } else {
                        None
                    }
                })
                .collect(),
            Variant::Wal(_) => HashMap::default(), //todo
        }
    }

    #[inline]
    pub(crate) fn perm_type(&self) -> &Variant<E> {
        &self.0.inner
    }
}

#[derive(Debug, PartialEq, Clone)]
struct VfsNodeInner<E: Entity> {
    id: InodeId,
    name: Name,
    last_modified: Timestamp,
    size: ByteSize,
    visibility: Visibility,
    path: VfsPath,
    inner: Variant<E>,
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum Variant<E: Entity> {
    Permanent(Model<E>),
    Wal(WalNode),
}

#[derive(Debug, PartialEq, Clone)]
pub enum Inode {
    Root(Root),
    File(File),
    Directory(Directory),
}

#[derive(Debug, PartialEq, Clone)]
#[repr(transparent)]
pub struct Root(Arc<RootInner>);

#[derive(Debug, PartialEq, Clone)]
struct RootInner {
    last_modified: Timestamp,
    content: Vec<Inode>,
}

impl Inode {
    #[inline]
    pub fn id(&self) -> InodeId {
        match self {
            Self::Root(_) => ROOT_INODE_ID,
            Self::File(file) => file.id(),
            Self::Directory(dir) => dir.id(),
        }
    }

    #[inline]
    pub fn name(&self) -> &Name {
        match self {
            Self::Root(_) => ROOT_NAME.deref(),
            Self::File(file) => file.name(),
            Self::Directory(dir) => dir.name(),
        }
    }

    #[inline]
    pub fn last_modified(&self) -> &Timestamp {
        match self {
            Self::Root(root) => &root.0.last_modified,
            Self::File(file) => file.last_modified(),
            Self::Directory(dir) => dir.last_modified(),
        }
    }

    #[inline]
    pub fn is_hidden(&self) -> bool {
        match self {
            Self::Root(_) => false,
            Self::File(file) => file.is_hidden(),
            Self::Directory(dir) => dir.is_hidden(),
        }
    }

    #[inline]
    pub fn path(&self) -> &VfsPath {
        match self {
            Self::Root(_) => ROOT_PATH.deref(),
            Self::File(file) => file.path(),
            Self::Directory(dir) => dir.path(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::vfs::{InodeId, InodeIdError, NameError, VfsPath, VfsPathError};

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

        let path = VfsPath::try_from("/")?;
        assert_eq!(path.as_ref(), "/");

        let path = VfsPath::try_from("///")?;
        assert_eq!(path.as_ref(), "/");

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

    #[test]
    fn inode_id() -> anyhow::Result<()> {
        let id = InodeId::try_from(9999)?;
        assert_eq!(*id, 9999);

        assert!(matches!(
            InodeId::try_from(123),
            Err(InodeIdError::Reserved)
        ));

        Ok(())
    }
}
