use crate::crypto::{DriveKey, DriveKeyError, FileKey};
use crate::types::file::FileId;
use crate::types::{AuthMode, SignatureFormat};
use crate::{DriveId, Password};
use ario_core::wallet::Wallet;
use moka::Equivalent;
use moka::sync::Cache;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct KeyRing(Arc<Mutex<Inner>>);

#[bon::bon]
impl KeyRing {
    #[builder(derive(Debug))]
    pub fn new(
        drive_id: &DriveId,
        wallet: &Wallet,
        #[builder(into)] password: Password,
        #[builder(default = 100)] max_cached_file_keys: u64,
        #[builder(default = Duration::from_secs(300))] max_cached_file_key_ttl: Duration,
    ) -> Result<Self, DriveKeyError> {
        let v1_drive_key = DriveKey::derive_v1(drive_id, wallet, &password)?;
        let v2_drive_key = DriveKey::derive_v2(drive_id, wallet, &password)?;
        let file_key_cache = Cache::builder()
            .name(format!("file_key_cache [{}]", drive_id).as_str())
            .max_capacity(max_cached_file_keys)
            .time_to_live(max_cached_file_key_ttl)
            .build();
        Ok(Self(Arc::new(Mutex::new(Inner {
            default_variant: None,
            v1_drive_key,
            v2_drive_key,
            file_key_cache,
        }))))
    }

    pub fn v1_drive_key(&self) -> DriveKey {
        let lock = self.0.lock().expect("lock not to be poisoned");
        lock.v1_drive_key.clone()
    }

    pub fn v2_drive_key(&self) -> DriveKey {
        let lock = self.0.lock().expect("lock not to be poisoned");
        lock.v2_drive_key.clone()
    }

    pub fn drive_key(&self) -> Option<DriveKey> {
        let lock = self.0.lock().expect("lock not to be poisoned");
        lock.drive_key().map(|k| k.clone())
    }

    pub fn set_signature_format(&self, signature_format: SignatureFormat) {
        let mut lock = self.0.lock().expect("lock not to be poisoned");
        lock.default_variant = Some(signature_format.into())
    }

    pub fn v1_file_key(&self, file_id: &FileId) -> FileKey {
        let lock = self.0.lock().expect("lock not to be poisoned");
        lock.v1_file_key(file_id)
    }

    pub fn v2_file_key(&self, file_id: &FileId) -> FileKey {
        let lock = self.0.lock().expect("lock not to be poisoned");
        lock.v2_file_key(file_id)
    }

    pub fn file_key(&self, file_id: &FileId) -> Option<FileKey> {
        let lock = self.0.lock().expect("lock not to be poisoned");
        lock.file_key(file_id)
    }

    pub fn auth_mode(&self) -> AuthMode {
        AuthMode::Password
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
enum KeyVariant {
    V1,
    V2,
}

impl From<SignatureFormat> for KeyVariant {
    fn from(value: SignatureFormat) -> Self {
        match value {
            SignatureFormat::V1 => Self::V1,
            SignatureFormat::V2 => Self::V2,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FileKeyCacheKey {
    file_id: FileId,
    variant: KeyVariant,
}

#[derive(Hash)]
struct BorrowedFileKeyCacheKey<'a> {
    file_id: &'a FileId,
    variant: KeyVariant,
}

impl<'a> Equivalent<FileKeyCacheKey> for BorrowedFileKeyCacheKey<'a> {
    fn equivalent(&self, key: &FileKeyCacheKey) -> bool {
        self.file_id == &key.file_id && self.variant == key.variant
    }
}

impl<'a> From<BorrowedFileKeyCacheKey<'a>> for FileKeyCacheKey {
    fn from(value: BorrowedFileKeyCacheKey<'a>) -> Self {
        Self {
            file_id: value.file_id.clone(),
            variant: value.variant,
        }
    }
}

#[derive(Debug)]
struct Inner {
    default_variant: Option<KeyVariant>,
    v1_drive_key: DriveKey,
    v2_drive_key: DriveKey,
    file_key_cache: Cache<FileKeyCacheKey, FileKey>,
}

impl Inner {
    fn drive_key(&self) -> Option<&DriveKey> {
        self.default_variant.map(|variant| match variant {
            KeyVariant::V1 => &self.v1_drive_key,
            KeyVariant::V2 => &self.v2_drive_key,
        })
    }

    fn file_key(&self, file_id: &FileId) -> Option<FileKey> {
        self.default_variant.map(|variant| match variant {
            KeyVariant::V1 => self.v1_file_key(file_id),
            KeyVariant::V2 => self.v2_file_key(file_id),
        })
    }

    fn v1_file_key(&self, file_id: &FileId) -> FileKey {
        let key = BorrowedFileKeyCacheKey {
            file_id,
            variant: KeyVariant::V1,
        };
        if let Some(file_key) = self.file_key_cache.get(&key) {
            return file_key;
        };

        let file_key = FileKey::derive_from(file_id, &self.v1_drive_key);
        self.file_key_cache.insert(key.into(), file_key.clone());
        file_key
    }

    fn v2_file_key(&self, file_id: &FileId) -> FileKey {
        let key = BorrowedFileKeyCacheKey {
            file_id,
            variant: KeyVariant::V2,
        };
        if let Some(file_key) = self.file_key_cache.get(&key) {
            return file_key;
        };

        let file_key = FileKey::derive_from(file_id, &self.v2_drive_key);
        self.file_key_cache.insert(key.into(), file_key.clone());
        file_key
    }
}
