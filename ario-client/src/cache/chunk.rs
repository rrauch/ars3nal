use crate::cache::{Context, Error, HasWeight, InnerCache, L2ChunkCache};
use crate::chunk::TxChunkProof;
use crate::{Cache, chunk};
use ario_core::crypto::merkle::DefaultProof;
use ario_core::data::{
    AuthenticatedTxDataChunk, DataRoot, TxDataAuthenticityProof, TxDataChunk,
    UnauthenticatedTxDataChunk,
};
use ario_core::tx::TxId;
use ario_core::{AuthenticationState, MaybeOwned};
use futures_concurrency::future::Join;
use std::iter;
use std::ops::Range;

#[derive(Eq, Hash, PartialEq, Clone)]
pub(crate) enum CacheKey<'a> {
    Authenticated(ChunkKey<'a>),
    Unauthenticated(ChunkKey<'a>),
}

impl<'a> CacheKey<'a> {
    #[inline]
    fn chunk_key(&self) -> &ChunkKey<'a> {
        match self {
            Self::Authenticated(v) => v,
            Self::Unauthenticated(v) => v,
        }
    }
}

#[derive(Eq, Hash, PartialEq, Clone)]
pub(crate) struct ChunkKey<'a> {
    relative_offset: u64,
    tx_id: MaybeOwned<'a, TxId>,
}

impl<'a> From<(u64, &'a TxId)> for ChunkKey<'a> {
    fn from(value: (u64, &'a TxId)) -> Self {
        Self {
            relative_offset: value.0,
            tx_id: MaybeOwned::Borrowed(value.1),
        }
    }
}

impl From<(u64, TxId)> for ChunkKey<'static> {
    fn from(value: (u64, TxId)) -> Self {
        Self {
            relative_offset: value.0,
            tx_id: MaybeOwned::Owned(value.1),
        }
    }
}

impl<'a> ChunkKey<'a> {
    fn into_owned(self) -> ChunkKey<'static> {
        ChunkKey {
            relative_offset: self.relative_offset,
            tx_id: self.tx_id.into_owned().into(),
        }
    }
}

impl<'a> HasWeight for CacheKey<'a> {
    fn weigh(&self) -> usize {
        size_of_val(&self)
    }
}

#[derive(Clone)]
pub(crate) enum CacheValue {
    Authenticated(AuthenticatedTxDataChunk<'static>),
    Unauthenticated(UnauthenticatedTxDataChunk<'static>),
}

impl Into<UnauthenticatedTxDataChunk<'static>> for CacheValue {
    fn into(self) -> UnauthenticatedTxDataChunk<'static> {
        match self {
            Self::Authenticated(auth) => auth.invalidate(),
            Self::Unauthenticated(unauth) => unauth,
        }
    }
}

impl TryInto<AuthenticatedTxDataChunk<'static>> for CacheValue {
    type Error = ();

    fn try_into(self) -> Result<AuthenticatedTxDataChunk<'static>, Self::Error> {
        match self {
            Self::Authenticated(auth) => Ok(auth),
            Self::Unauthenticated(_) => Err(()),
        }
    }
}

impl HasWeight for CacheValue {
    fn weigh(&self) -> usize {
        match self {
            CacheValue::Authenticated(v) => v.weigh(),
            CacheValue::Unauthenticated(v) => v.weigh(),
        }
    }
}

pub(super) type ChunkCache =
    InnerCache<CacheKey<'static>, CacheValue, Box<DynL2ChunkCache<'static>>>;

#[dynosaur::dynosaur(pub(super) DynL2ChunkCache = dyn(box) L2Cache)]
pub trait L2Cache: Send + Sync {
    fn init(&mut self, ctx: &Context) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn get_chunk(
        &self,
        relative_offset: u64,
        tx_id: &TxId,
    ) -> impl Future<Output = Result<Option<UnauthenticatedTxDataChunk<'static>>, std::io::Error>> + Send;
    fn insert_chunk(
        &self,
        relative_offset: u64,
        tx_id: TxId,
        value: UnauthenticatedTxDataChunk<'static>,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn invalidate(
        &self,
        relative_offset: u64,
        tx_id: &TxId,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send {
        self.invalidate_many(iter::once((relative_offset, tx_id)))
    }
    fn invalidate_many<'a>(
        &self,
        iter: impl Iterator<Item = (u64, &'a TxId)> + Send,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

impl Cache {
    pub(crate) async fn get_unauthenticated_chunk(
        &self,
        relative_range: &Range<u64>,
        tx_id: &TxId,
        f: impl AsyncFnOnce(
            &Range<u64>,
            &TxId,
        )
            -> Result<Option<UnauthenticatedTxDataChunk<'static>>, crate::Error>,
    ) -> Result<Option<UnauthenticatedTxDataChunk<'static>>, crate::Error> {
        let chunk_cache = &self.chunk_cache;
        let key = CacheKey::Unauthenticated(ChunkKey::from((relative_range.start, tx_id.clone())));
        Ok(chunk_cache
            .l1
            .try_get_with_by_ref(&key, async {
                // first, check if we have an authenticated variant present
                let auth_key = CacheKey::Authenticated(key.chunk_key().clone());
                if let Some(Some(auth)) = chunk_cache.l1.get(&auth_key).await {
                    return Ok(Some(CacheValue::Unauthenticated(auth.into())));
                }
                // no luck yet. check L2 next or retrieve
                Ok(
                    l2_or_retrieve(relative_range, tx_id, self.chunk_cache.l2.as_ref(), f)
                        .await?
                        .map(|c| CacheValue::Unauthenticated(c)),
                )
            })
            .await
            .map_err(Error::CachedError)?
            .map(|v| v.into()))
    }

    pub(crate) async fn get_authenticated_chunk(
        &self,
        offset: u128,
        relative_range: &Range<u64>,
        data_root: &DataRoot,
        tx_id: &TxId,
        retrieve_chunk: impl AsyncFnOnce(
            &Range<u64>,
            &TxId,
        ) -> Result<
            Option<UnauthenticatedTxDataChunk<'static>>,
            crate::Error,
        >,
        retrieve_chunk_proof: impl AsyncFnOnce(
            u128,
        )
            -> Result<Option<TxChunkProof<'static>>, crate::Error>,
    ) -> Result<Option<AuthenticatedTxDataChunk<'static>>, crate::Error> {
        let chunk_cache = &self.chunk_cache;
        let key = CacheKey::Authenticated(ChunkKey::from((relative_range.start, tx_id.clone())));
        Ok(chunk_cache
            .l1
            .try_get_with_by_ref(&key, async {
                let unauth_key = CacheKey::Unauthenticated(key.chunk_key().clone());

                let chunk_fut = async {
                    // first, check if we have an unauthenticated variant present
                    if let Some(Some(unauth)) = chunk_cache.l1.get(&unauth_key).await {
                        Ok::<_, crate::Error>(Some(unauth.into()))
                    } else {
                        // check L2 or retrieve
                        Ok(l2_or_retrieve(
                            relative_range,
                            tx_id,
                            chunk_cache.l2.as_ref(),
                            retrieve_chunk,
                        )
                        .await?)
                    }
                };

                let proof_fut = async {
                    match retrieve_chunk_proof(offset).await? {
                        Some(proof) => Ok::<_, crate::Error>(TxDataAuthenticityProof::new(
                            data_root,
                            DefaultProof::new(relative_range.clone(), proof.data_path),
                        )),
                        None => Err(Error::InvalidCachedResponse)?,
                    }
                };

                // await chunk & proof concurrently to reduce latency as much as we reasonably can here
                let (chunk, proof) = (chunk_fut, proof_fut).join().await;

                let unauthenticated_chunk = match chunk? {
                    Some(chunk) => chunk,
                    None => return Ok(None),
                };

                let proof = proof?;

                match unauthenticated_chunk.authenticate(&proof) {
                    Ok(authenticated) => Ok(Some(CacheValue::Authenticated(authenticated))),
                    Err((_, err)) => {
                        // authentication failed
                        // invalidate cached entries
                        if let Some(l2) = chunk_cache.l2.as_ref() {
                            let _ = l2.invalidate(relative_range.start, tx_id).await;
                            chunk_cache.l1.invalidate(&unauth_key).await;
                        }
                        Err(chunk::DownloadError::ProofError(err))?
                    }
                }
            })
            .await
            .map_err(Error::CachedError)?
            .map(|v| v.try_into().map_err(|_| Error::InvalidCachedResponse))
            .transpose()?)
    }
}

async fn l2_or_retrieve(
    relative_range: &Range<u64>,
    tx_id: &TxId,
    l2: Option<&impl L2ChunkCache>,
    f: impl AsyncFnOnce(
        &Range<u64>,
        &TxId,
    ) -> Result<Option<UnauthenticatedTxDataChunk<'static>>, crate::Error>,
) -> Result<Option<UnauthenticatedTxDataChunk<'static>>, crate::Error> {
    let offset = relative_range.start;

    if let Some(l2) = l2 {
        if let Some(chunk) = l2.get_chunk(offset, tx_id).await.map_err(Error::L2Error)? {
            return Ok(Some(chunk));
        }
    }

    // retrieve via supplied fn
    Ok(match f(relative_range, tx_id).await? {
        Some(value) => {
            // and insert into L2
            if let Some(l2) = l2 {
                l2.insert_chunk(offset, tx_id.clone(), value.clone())
                    .await
                    .map_err(Error::L2Error)?;
            }
            Some(value)
        }
        None => None,
    })
}

impl<'a, Auth: AuthenticationState> HasWeight for TxDataChunk<'a, Auth> {
    fn weigh(&self) -> usize {
        self.len() as usize + size_of_val(self)
    }
}
