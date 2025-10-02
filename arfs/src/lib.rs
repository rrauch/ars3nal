extern crate core;

pub(crate) mod serde_tag;
pub(crate) mod types;
mod vfs;

pub use ario_core::bundle::Owner as BundleOwner;
pub use ario_core::tx::Owner as TxOwner;
pub use types::{ArFsVersion, ContentType, DriveId, Privacy};
pub use vfs::{Directory, File, Inode, Timestamp, Vfs};

use crate::types::{
    AuthMode, DriveEntity, DriveHeader, DriveKind, DriveMetadata, Entity, Header, Metadata,
};
use crate::vfs::Error as VfsError;
use ario_client::Client;
use ario_client::Error as ClientError;
use ario_client::data_reader::{AsyncBundleItemReader, AsyncTxReader};
use ario_client::graphql::{
    ItemId, SortOrder, TagFilter, TxQuery, TxQueryFilterCriteria, TxQueryItem, WithTxResponseFields,
};
use ario_core::confidential::{Confidential, NewSecretExt};
use ario_core::wallet::{Wallet, WalletAddress};
use ario_core::{JsonValue, MaybeOwned};
use core::fmt;
use derive_more::Display;
use futures_lite::{AsyncRead, AsyncReadExt, AsyncSeek, Stream, StreamExt};
use serde_json::Error as JsonError;
use std::fmt::{Display, Formatter};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use strum::EnumString;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    EntityError(#[from] EntityError),
    #[error(transparent)]
    ClientError(#[from] ClientError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    VfsError(#[from] VfsError),
}

#[derive(Error, Debug)]
pub enum EntityError {
    #[error(transparent)]
    ParseError(#[from] types::ParseError),
    #[error(transparent)]
    MetadataError(#[from] MetadataError),
    #[error("entity of type '{entity_type}' with details '{details}' not found")]
    NotFound {
        entity_type: &'static str,
        details: String,
    },
    #[error("owner mismatch, expected '{expected}' but found '{actual}'")]
    OwnerMismatch {
        expected: WalletAddress,
        actual: WalletAddress,
    },
    #[error("privacy mode mismatch, expected '{expected}' but found '{actual}'")]
    PrivacyMismatch { expected: Privacy, actual: Privacy },
    #[error("auth mode mismatch, expected '{expected}' but found '{actual}'")]
    AuthModeMismatch { expected: String, actual: String },
}

#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("data length '{actual}' exceeds max '{max}'")]
    MaxLengthExceeded { max: usize, actual: usize },
    #[error(transparent)]
    JsonError(#[from] JsonError),
}

#[derive(Debug, Clone, Display)]
#[repr(transparent)]
pub struct ArFs(Arc<ErasedArFs>);

#[bon::bon]
impl ArFs {
    #[builder(derive(Debug))]
    pub async fn new(client: Client, drive_id: DriveId, scope: Scope) -> Result<Self, Error> {
        let drive_ref = find_drive_by_id_owner(&client, &drive_id, scope.owner().as_ref())
            .await?
            .into_owned();
        let drive = drive_entity(&client, &drive_ref, scope.as_private()).await?;
        Ok(Self(Arc::new(ErasedArFs::new(client, drive, scope))))
    }

    #[inline]
    pub fn version(&self) -> &ArFsVersion {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => inner.version(),
            ErasedArFs::PublicRW(inner) => inner.version(),
            ErasedArFs::PrivateRO(inner) => inner.version(),
            ErasedArFs::PrivateRW(inner) => inner.version(),
        }
    }

    #[inline]
    pub fn drive_id(&self) -> &DriveId {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => inner.drive_id(),
            ErasedArFs::PublicRW(inner) => inner.drive_id(),
            ErasedArFs::PrivateRO(inner) => inner.drive_id(),
            ErasedArFs::PrivateRW(inner) => inner.drive_id(),
        }
    }

    #[inline]
    pub fn created_at(&self) -> &Timestamp {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(inner) => inner.created_at(),
            ErasedArFs::PublicRW(inner) => inner.created_at(),
            ErasedArFs::PrivateRO(inner) => inner.created_at(),
            ErasedArFs::PrivateRW(inner) => inner.created_at(),
        }
    }

    #[inline]
    pub fn access_mode(&self) -> AccessMode {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(_) | ErasedArFs::PrivateRO(_) => AccessMode::ReadOnly,
            ErasedArFs::PublicRW(_) | ErasedArFs::PrivateRW(_) => AccessMode::ReadWrite,
        }
    }

    #[inline]
    pub fn privacy(&self) -> Privacy {
        match self.0.as_ref() {
            ErasedArFs::PublicRO(_) | ErasedArFs::PublicRW(_) => Privacy::Public,
            ErasedArFs::PrivateRO(_) | ErasedArFs::PrivateRW(_) => Privacy::Private,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, EnumString, strum::Display)]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug)]
pub enum Scope {
    Public(Access<WalletAddress, Wallet>),
    Private(Access<Credentials, Credentials>),
}

impl Scope {
    pub fn public(owner: WalletAddress) -> Self {
        Scope::Public(Access::ReadOnly(owner))
    }

    pub fn public_rw(wallet: Wallet) -> Self {
        Scope::Public(Access::ReadWrite(wallet))
    }

    pub fn private(credentials: Credentials) -> Self {
        Scope::Private(Access::ReadOnly(credentials))
    }

    pub fn private_rw(credentials: Credentials) -> Self {
        Scope::Private(Access::ReadWrite(credentials))
    }

    fn owner(&self) -> MaybeOwned<'_, WalletAddress> {
        match self {
            Self::Public(public) => match public {
                Access::ReadOnly(owner) => owner.into(),
                Access::ReadWrite(wallet) => wallet.address().into(),
            },
            Self::Private(private) => match private {
                Access::ReadOnly(creds) | Access::ReadWrite(creds) => {
                    (&creds.0.wallet_address).into()
                }
            },
        }
    }

    fn as_private(&self) -> Option<&Private> {
        match self {
            Self::Public(_) => None,
            Self::Private(private) => match private {
                Access::ReadOnly(creds) | Access::ReadWrite(creds) => Some(&creds.0),
            },
        }
    }
}

#[derive(Debug)]
pub enum Access<R, W> {
    ReadOnly(R),
    ReadWrite(W),
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Credentials(Private);

impl Credentials {
    pub fn with_password<P: Into<Password>>(wallet: Wallet, password: P) -> Self {
        Self(Private {
            wallet_address: wallet.address(),
            wallet,
            auth: password.into().into(),
        })
    }
}

#[derive(Debug, Display)]
enum ErasedArFs {
    PublicRW(ArFsInner<Public, ReadWrite<Wallet>>),
    PublicRO(ArFsInner<Public, ReadOnly>),
    PrivateRW(ArFsInner<Private, ReadWrite>),
    PrivateRO(ArFsInner<Private, ReadOnly>),
}

impl ErasedArFs {
    fn new(client: Client, drive: DriveEntity, scope: Scope) -> Self {
        match scope {
            Scope::Public(public) => match public {
                Access::ReadOnly(owner) => {
                    Self::PublicRO(ArFsInner::new_public_ro(client, drive, owner))
                }
                Access::ReadWrite(wallet) => {
                    Self::PublicRW(ArFsInner::new_public_rw(client, drive, wallet))
                }
            },
            Scope::Private(private) => match private {
                Access::ReadOnly(creds) => {
                    Self::PrivateRO(ArFsInner::new_private_ro(client, drive, creds))
                }
                Access::ReadWrite(creds) => {
                    Self::PrivateRW(ArFsInner::new_private_rw(client, drive, creds))
                }
            },
        }
    }
}

impl ArFsInner<Public, ReadOnly> {
    fn new_public_ro(client: Client, drive: DriveEntity, owner: WalletAddress) -> Self {
        ArFsInner {
            client,
            drive,
            privacy: Public { owner },
            mode: ReadOnly,
        }
    }
}

impl ArFsInner<Public, ReadWrite<Wallet>> {
    fn new_public_rw(client: Client, drive: DriveEntity, wallet: Wallet) -> Self {
        ArFsInner {
            client,
            drive,
            privacy: Public {
                owner: wallet.address(),
            },
            mode: ReadWrite(wallet),
        }
    }
}

impl ArFsInner<Private, ReadOnly> {
    fn new_private_ro(client: Client, drive: DriveEntity, credentials: Credentials) -> Self {
        ArFsInner {
            client,
            drive,
            privacy: credentials.0,
            mode: ReadOnly,
        }
    }
}

impl ArFsInner<Private, ReadWrite> {
    fn new_private_rw(client: Client, drive: DriveEntity, credentials: Credentials) -> Self {
        ArFsInner {
            client,
            drive,
            privacy: credentials.0,
            mode: ReadWrite::default(),
        }
    }
}

impl<PRIVACY, MODE> ArFsInner<PRIVACY, MODE> {
    fn version(&self) -> &ArFsVersion {
        self.drive.header().version()
    }

    fn drive_id(&self) -> &DriveId {
        &self.drive.header().as_inner().drive_id
    }

    fn created_at(&self) -> &Timestamp {
        &self.drive.header().as_inner().time
    }

    async fn vfs(&self) -> Arc<Vfs> {
        todo!()
    }

    fn display(
        &self,
        f: &mut fmt::Formatter<'_>,
        privacy: &'static str,
        mode: &'static str,
        owner: &WalletAddress,
    ) -> fmt::Result {
        writeln!(f, "ArFS Version: {}", self.version())?;
        writeln!(f, "Drive ID: {}", self.drive_id())?;
        writeln!(f, "Owner: {}", &owner)?;
        writeln!(f, "Privacy: {}", privacy)?;
        writeln!(f, "Access Mode: {}", mode)?;
        write!(f, "Created at: {}", self.created_at())
    }
}

#[derive(Debug)]
struct ReadWrite<C = ()>(C);

impl Default for ReadWrite {
    fn default() -> Self {
        Self(())
    }
}

#[derive(Debug)]
struct ReadOnly;

#[derive(Debug)]
struct ArFsInner<PRIVACY, MODE> {
    client: Client,
    drive: DriveEntity,
    privacy: PRIVACY,
    mode: MODE,
}

#[derive(Debug)]
struct Public {
    owner: WalletAddress,
}

impl<Mode> ArFsInner<Public, Mode> {
    pub fn owner(&self) -> &WalletAddress {
        &self.privacy.owner
    }

    fn display_public(&self, f: &mut fmt::Formatter<'_>, mode: &'static str) -> fmt::Result {
        self.display(f, "Public", mode, self.owner())
    }
}

impl Display for ArFsInner<Public, ReadOnly> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_public(f, "Read Only")
    }
}

impl<C> Display for ArFsInner<Public, ReadWrite<C>> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_public(f, "Read/Write")
    }
}

#[derive(Debug)]
#[repr(transparent)]
struct Password(Confidential<Box<str>>);

impl Deref for Password {
    type Target = Confidential<Box<str>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for Password {
    fn from(mut value: String) -> Self {
        // into_boxed_str() calls shrink_to_fit(), which reallocates if capacity > len.
        // Reallocation would leave a copy of the plaintext password in the old buffer.
        // We handle this case explicitly to zeroize the old buffer before conversion.
        let value = if value.capacity() > value.len() {
            let mut new_string = String::with_capacity(value.len());
            new_string.push_str(&value);
            value.zeroize();
            new_string
        } else {
            value
        };

        Self(value.into_boxed_str().confidential())
    }
}

#[derive(Debug)]
enum AuthCredentials {
    Password(Password),
}

impl From<&AuthCredentials> for AuthMode {
    fn from(value: &AuthCredentials) -> Self {
        match value {
            AuthCredentials::Password(_) => AuthMode::Password,
        }
    }
}

impl From<Password> for AuthCredentials {
    fn from(value: Password) -> Self {
        AuthCredentials::Password(value)
    }
}

#[derive(Debug)]
struct Private {
    wallet: Wallet,
    wallet_address: WalletAddress,
    auth: AuthCredentials,
}

impl Private {
    fn new(wallet: Wallet, auth: AuthCredentials) -> Self {
        let wallet_address = wallet.address();
        Self {
            wallet,
            wallet_address,
            auth,
        }
    }
}

impl<Mode> ArFsInner<Private, Mode> {
    pub fn owner(&self) -> &WalletAddress {
        &self.privacy.wallet_address
    }

    fn display_private(&self, f: &mut fmt::Formatter<'_>, mode: &'static str) -> fmt::Result {
        match self.privacy.auth {
            AuthCredentials::Password(_) => {
                self.display(f, "Private (Password)", mode, self.owner())
            }
        }
    }
}

impl Display for ArFsInner<Private, ReadOnly> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_private(f, "Read Only")
    }
}

impl Display for ArFsInner<Private, ReadWrite> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_private(f, "Read/Write")
    }
}

#[derive(Debug)]
pub struct DriveRef<'a> {
    drive_id: DriveId,
    container_id: ItemId<'a>,
    owner: MaybeOwned<'a, WalletAddress>,
}

impl<'a> DriveRef<'a> {
    fn into_owned(self) -> DriveRef<'static> {
        DriveRef {
            drive_id: self.drive_id,
            container_id: self.container_id.into_owned(),
            owner: self.owner.into_owned().into(),
        }
    }
}

type TagsOnly = WithTxResponseFields<false, false, false, false, false, false, true, false>;

fn find_drive_ids_by_owner<'a>(
    client: &'a Client,
    owner: &'a WalletAddress,
) -> impl Stream<Item = Result<DriveRef<'a>, Error>> + Unpin + 'a {
    client
        .query_transactions_with_fields::<TagsOnly>(
            TxQuery::builder()
                .filter_criteria(
                    TxQueryFilterCriteria::builder()
                        .owners([owner])
                        .tags([TagFilter::builder()
                            .name("Entity-Type")
                            .values(["drive"])
                            .build()])
                        .build(),
                )
                .sort_order(SortOrder::HeightDescending)
                .build(),
        )
        .map(|r| match r {
            Ok(item) => to_drive_ref(item, MaybeOwned::Borrowed(owner)),
            Err(e) => Err(e.into()),
        })
}

fn to_drive_ref(item: TxQueryItem, owner: MaybeOwned<WalletAddress>) -> Result<DriveRef, Error> {
    let drive_header =
        Header::<DriveHeader, DriveKind>::try_from(item.tags()).map_err(EntityError::ParseError)?;

    Ok(DriveRef {
        drive_id: drive_header.as_inner().drive_id.clone(),
        container_id: item.id().clone().into_owned(),
        owner,
    })
}

async fn find_drive_by_id_owner<'a>(
    client: &'a Client,
    drive_id: &'a DriveId,
    owner: &'a WalletAddress,
) -> Result<DriveRef<'a>, Error> {
    client
        .query_transactions_with_fields::<TagsOnly>(
            TxQuery::builder()
                .filter_criteria(
                    TxQueryFilterCriteria::builder()
                        .owners([owner])
                        .tags([
                            TagFilter::builder()
                                .name("Entity-Type")
                                .values(["drive"])
                                .build(),
                            TagFilter::builder()
                                .name("Drive-Id")
                                .values([drive_id.to_string()])
                                .build(),
                        ])
                        .build(),
                )
                .sort_order(SortOrder::HeightDescending)
                .max_results(NonZeroUsize::try_from(1).unwrap())
                .build(),
        )
        .map(|r| match r {
            Ok(item) => to_drive_ref(item, MaybeOwned::Borrowed(owner)),
            Err(e) => Err(e.into()),
        })
        .try_next()
        .await?
        .ok_or(
            EntityError::NotFound {
                entity_type: "drive",
                details: drive_id.to_string(),
            }
            .into(),
        )
}

trait MetadataReader: AsyncRead + AsyncSeek + Send + Unpin {
    fn len(&self) -> u64;
}

impl MetadataReader for AsyncTxReader<'_> {
    fn len(&self) -> u64 {
        AsyncTxReader::len(self)
    }
}

impl MetadataReader for AsyncBundleItemReader<'_> {
    fn len(&self) -> u64 {
        AsyncBundleItemReader::len(self)
    }
}

async fn drive_entity(
    client: &Client,
    drive_ref: &DriveRef<'_>,
    private: Option<&Private>,
) -> Result<DriveEntity, Error> {
    const MAX_METADATA_LEN: usize = 1024 * 1024;

    if let Some(address) = private.map(|p| p.wallet.address()) {
        if &address != drive_ref.owner.as_ref() {
            Err(EntityError::OwnerMismatch {
                expected: address,
                actual: drive_ref.owner.clone().into_owned(),
            })?;
        }
    }

    let tx_e;
    let bundle_item;
    let mut reader: Box<dyn MetadataReader>;
    let owner_address;

    let authenticated_tags = match &drive_ref.container_id {
        ItemId::Tx(tx) => {
            if let Some(tx) = client.tx_by_id(&tx).await? {
                tx_e = tx;
                let tags = tx_e.tags();
                owner_address = tx_e.owner().address();

                reader = Box::new(AsyncTxReader::new(client.clone(), &tx_e).await?);
                tags
            } else {
                return Err(EntityError::NotFound {
                    entity_type: DriveKind::TYPE,
                    details: drive_ref.drive_id.to_string(),
                })?;
            }
        }
        ItemId::BundleItem { item_id, bundle_id } => {
            if let Some(item) = client.bundle_item(item_id, bundle_id).await? {
                bundle_item = item;
                let tags = bundle_item.tags();
                owner_address = bundle_item.owner().address();
                reader = Box::new(client.read_bundle_item(&bundle_item).await?);
                tags
            } else {
                return Err(EntityError::NotFound {
                    entity_type: DriveKind::TYPE,
                    details: drive_ref.drive_id.to_string(),
                })?;
            }
        }
    };

    if &owner_address != drive_ref.owner.as_ref() {
        Err(EntityError::OwnerMismatch {
            expected: drive_ref.owner.clone().into_owned(),
            actual: owner_address,
        })?;
    }

    if reader.len() > MAX_METADATA_LEN as u64 {
        Err(EntityError::from(MetadataError::MaxLengthExceeded {
            max: MAX_METADATA_LEN,
            actual: reader.len() as usize,
        }))?;
    }

    let mut buf = vec![0u8; reader.len() as usize];
    reader.read_exact(&mut buf).await?;
    drop(reader);
    let metadata: JsonValue =
        serde_json::from_slice(buf.as_slice()).map_err(|e| EntityError::MetadataError(e.into()))?;

    let drive_header = Header::<DriveHeader, DriveKind>::try_from(authenticated_tags)
        .map_err(EntityError::from)?;

    let drive_metadata =
        Metadata::<DriveMetadata, DriveKind>::try_from(metadata).map_err(EntityError::from)?;

    let drive_entity = DriveEntity::new(drive_header, drive_metadata);

    let privacy = private.map(|_| Privacy::Private).unwrap_or(Privacy::Public);
    if drive_entity.header().as_inner().privacy != privacy {
        Err(EntityError::PrivacyMismatch {
            expected: privacy,
            actual: drive_entity.header().as_inner().privacy,
        })?;
    }

    let auth_mode = private.map(|p| AuthMode::from(&p.auth));
    if drive_entity.header().as_inner().auth_mode != auth_mode {
        Err(EntityError::AuthModeMismatch {
            expected: auth_mode
                .map(|a| a.to_string())
                .unwrap_or("None".to_string()),
            actual: drive_entity
                .header()
                .as_inner()
                .auth_mode
                .map(|a| a.to_string())
                .unwrap_or("None".to_string()),
        })?;
    }

    Ok(drive_entity)
}

#[cfg(test)]
mod tests {
    use crate::{ArFs, Credentials, Scope};
    use ario_client::Client;
    use ario_core::Gateway;
    use ario_core::jwk::Jwk;
    use ario_core::network::Network;
    use ario_core::wallet::Wallet;
    use futures_lite::stream::StreamExt;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    async fn init() -> anyhow::Result<(Client, Wallet)> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());
        let wallet_jwk = std::env::var("ARLOCAL_WALLET_JWK").unwrap();

        let client = Client::builder()
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .enable_netwatch(false)
            .build()
            .await?;

        let json =
            tokio::fs::read_to_string(<PathBuf as AsRef<Path>>::as_ref(&PathBuf::from(wallet_jwk)))
                .await?;

        let jwk = Jwk::from_json(json.as_str())?;
        let wallet = Wallet::from_jwk(&jwk)?;

        Ok((client, wallet))
    }

    #[ignore]
    #[tokio::test]
    async fn builder() -> anyhow::Result<()> {
        let (client, wallet) = init().await?;
        let drive_owner = wallet.address();
        let credentials = Credentials::with_password(wallet, "foo".to_string());

        let drive_ref = super::find_drive_ids_by_owner(&client, &drive_owner)
            .try_next()
            .await?
            .unwrap();

        let arfs = ArFs::builder()
            .client(client.clone())
            .drive_id(drive_ref.drive_id)
            .scope(Scope::private_rw(credentials))
            .build()
            .await?;

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn foo() -> anyhow::Result<()> {
        let (client, wallet) = init().await?;
        let drive_owner = wallet.address();

        let mut stream = super::find_drive_ids_by_owner(&client, &drive_owner);

        while let Some(drive_ref) = stream.try_next().await? {
            let arfs = ArFs::builder()
                .client(client.clone())
                .drive_id(drive_ref.drive_id)
                .scope(Scope::public(drive_owner.clone()))
                .build()
                .await?;
            println!("{}", arfs);
        }
        Ok(())
    }
}
