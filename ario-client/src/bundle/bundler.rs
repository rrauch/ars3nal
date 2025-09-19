use crate::tx::{Prepared, Status, Submitted as TxSubmitted, TxSubmission, UploadChunks};
use crate::{Client, tx};
use ario_core::BlockNumber;
use ario_core::blob::OwnedBlob;
use ario_core::bundle::{BundleItemId, BundleItemVerifier, BundleType, ValidatedBundleItem};
use ario_core::chunking::DefaultChunker;
use ario_core::data::{DataItem, ExternalDataItemVerifier};
use ario_core::tag::Tag;
use ario_core::tx::v2::TxDraft;
use ario_core::tx::{Reward, TxBuilder, TxId, ValidatedTx};
use async_stream::try_stream;
use bytes::{BufMut, BytesMut};
use futures_lite::io::Cursor;
use futures_lite::{AsyncRead, AsyncSeek, AsyncSeekExt, Stream, StreamExt, ready};
use itertools::Itertools;
use rangemap::RangeMap;
use std::collections::{BTreeMap, HashSet};
use std::io::SeekFrom;
use std::iter;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};
use uuid::Uuid;

pub trait AsyncDataSource: AsyncRead + AsyncSeek + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncSeek + Send + Sync + Unpin> AsyncDataSource for T {}

#[derive(Error, Debug)]
pub enum Error {
    #[error("bundle is empty")]
    EmptyBundle,
    #[error("item with id '{0}' already in bundle")]
    ItemAlreadyInBundle(BundleItemId),
    #[error("invalid data length: expected '{expected}', actual '{actual}'")]
    InvalidDataLength { expected: u64, actual: u64 },
    #[error("unsupported bundle item. only version '2' is supported")]
    UnsupportedVersion,
    #[error("item error: {0}")]
    ItemError(String),
    #[error("bundler appears to have ended prematurely")]
    Dead,
    #[error("bundler was cancelled or ended prematurely")]
    Cancelled,
    #[error(transparent)]
    ClientError(#[from] crate::Error),
    #[error("signed transaction does not match draft")]
    TxMismatch,
    #[error("the submitted transaction completed prematurely")]
    TxCompletionPremature,
    #[error("other error: {0}")]
    Other(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct Receipt {
    item_id: BundleItemId,
    bundler_id: Uuid,
    state: State,
}

impl Receipt {
    pub fn item_id(&self) -> &BundleItemId {
        &self.item_id
    }

    pub fn bundler_id(&self) -> Uuid {
        self.bundler_id
    }

    pub fn status(&mut self) -> impl Stream<Item = Result<ItemStatus, Arc<Error>>> + Unpin {
        Box::pin(try_stream! {
              loop {
                match std::mem::replace(&mut self.state, State::Dead) {
                    State::Error(err) => {
                        self.state = State::Error(err.clone());
                        return Err(err)?;
                    }
                    State::Complete(tx_id, block_height, timestamp) => {
                        self.state = State::Complete(tx_id.clone(), block_height.clone(), timestamp.clone());
                        yield ItemStatus::Complete {
                            tx_id,
                            tx_completion: timestamp,
                            block_height,
                        };
                        break;
                    }
                    State::Active(mut rx) => {
                      let res = rx.borrow_and_update().clone();
                      match res {
                        Ok(ItemStatus::Complete{tx_id, block_height, tx_completion}) => {
                            self.state = State::Complete(tx_id, block_height, tx_completion);
                        }
                        Err(err) => {
                            self.state = State::Error(err);
                        }
                        Ok(other) => {
                            yield other;
                            match rx.changed().await {
                                Ok(_) => {
                                    self.state = State::Active(rx);
                                }
                                Err(_) => {
                                    // sender is gone
                                    // bundler is most likely dead
                                }
                            }
                        }
                      }
                    },
                    State::Dead => {
                        return Err(Arc::new(Error::Dead))?;
                    }
                }
              }
        })
    }
}

#[derive(Clone, Debug)]
enum State {
    Active(watch::Receiver<Result<ItemStatus, Arc<Error>>>),
    Complete(TxId, BlockNumber, SystemTime),
    Error(Arc<Error>),
    Dead,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ItemStatus {
    /// Item has been received by bundler
    Queued,
    /// Item is currently processed internally by the bundler
    Processing,
    /// Item ready for uploading
    UploadPending,
    /// Item is getting uploaded
    Uploading {
        tx_id: TxId,
        upload_start: SystemTime,
    },
    /// Upload complete, but transaction incomplete
    Uploaded {
        tx_id: TxId,
        upload_completion: SystemTime,
    },
    /// Transaction data has been uploaded completely.
    /// Waiting for Tx to settle.
    TxPending {
        tx_id: TxId,
        tx_upload_completion: SystemTime,
    },
    /// Transaction fully settled. Bundle Item available on network.
    Complete {
        tx_id: TxId,
        tx_completion: SystemTime,
        block_height: BlockNumber,
    },
}

struct Item<State> {
    item: ValidatedBundleItem<'static>,
    verifier: BundleItemVerifier<'static>,
    data_source: Box<dyn AsyncDataSource + 'static>,
    status_tx: watch::Sender<Result<ItemStatus, Arc<Error>>>,
    state: State,
}

impl<State> Item<State> {
    fn _state<Next>(self, next: Next) -> Item<Next> {
        Item {
            item: self.item,
            verifier: self.verifier,
            data_source: self.data_source,
            status_tx: self.status_tx,
            state: next,
        }
    }
}

struct Processed {
    header: OwnedBlob,
}

type UnprocessedItem = Item<()>;

impl UnprocessedItem {
    fn new(
        item: ValidatedBundleItem<'static>,
        verifier: BundleItemVerifier<'static>,
        data_source: Box<dyn AsyncDataSource + 'static>,
        status_tx: watch::Sender<Result<ItemStatus, Arc<Error>>>,
    ) -> Self {
        Self {
            item,
            verifier,
            data_source,
            status_tx,
            state: (),
        }
    }

    fn processed(self, header: OwnedBlob) -> ProcessedItem {
        let _ = self.status_tx.send(Ok(ItemStatus::UploadPending));
        self._state(Processed { header })
    }
}

impl ProcessedItem {
    fn uploaded(self, tx_id: TxId, timestamp: SystemTime) -> UploadedItem {
        let _ = self.status_tx.send(Ok(ItemStatus::Uploaded {
            tx_id,
            upload_completion: timestamp.clone(),
        }));
        self._state(Uploaded { timestamp })
    }
}

type ProcessedItem = Item<Processed>;

impl ProcessedItem {
    fn len(&self) -> u64 {
        self.state.header.len() as u64 + self.item.data_size()
    }
}

struct Uploaded {
    timestamp: SystemTime,
}

type UploadedItem = Item<Uploaded>;

pub struct AsyncBundler<State> {
    id: Uuid,
    client: Client,
    ct: CancellationToken,
    state: State,
    _drop_guard: DropGuard,
}

pub struct AcceptingItems {
    item_tx: mpsc::Sender<UnprocessedItem>,
    item_ids: HashSet<BundleItemId>,
    bundler_app_name: Option<String>,
    estimated_data_size: u64,
    processor_handle: JoinHandle<
        Result<
            (
                Vec<ProcessedItem>,
                OwnedBlob,
                ExternalDataItemVerifier<'static>,
            ),
            Arc<Error>,
        >,
    >,
}
pub struct Uploading {
    tx_id: TxId,
    started: SystemTime,
    reward_paid: Reward,
    item_count: usize,
    data_size: u64,
    uploader_handle: JoinHandle<Result<(Vec<UploadedItem>, TxSubmission<TxSubmitted>), Arc<Error>>>,
}

pub struct Submitted {
    tx_id: TxId,
    reward_paid: Reward,
    data_size: u64,
    upload_duration: Duration,
    items: Vec<UploadedItem>,
    tx_submission: TxSubmission<TxSubmitted>,
}

pub struct TxSigning {
    header: OwnedBlob,
    items: Vec<ProcessedItem>,
    data_verifier: ExternalDataItemVerifier<'static>,
    tx_draft: TxDraft<'static>,
    tx_submission: TxSubmission<Prepared>,
}

pub fn new_async_bundler(
    client: Client,
    bundler_app_name: Option<String>,
) -> AsyncBundler<AcceptingItems> {
    AsyncBundler::new(client, bundler_app_name)
}

impl AsyncBundler<AcceptingItems> {
    pub fn new(client: Client, bundler_app_name: Option<String>) -> Self {
        let id = Uuid::now_v7();
        let ct = CancellationToken::new();
        let (item_tx, item_rx) = mpsc::channel(10);

        let mut processor = Processor::new(id, item_rx, ct.clone());
        let processor_handle = tokio::spawn(async move { processor.run().await });

        let state = AcceptingItems {
            item_tx,
            item_ids: HashSet::new(),
            bundler_app_name,
            processor_handle,
            estimated_data_size: 0,
        };

        Self {
            id,
            client,
            _drop_guard: ct.clone().drop_guard(),
            ct,
            state,
        }
    }

    pub async fn submit<D: AsyncDataSource + 'static>(
        &mut self,
        item: ValidatedBundleItem<'static>,
        verifier: BundleItemVerifier<'static>,
        data_source: D,
    ) -> Result<Receipt, Error> {
        if item.bundle_type() != BundleType::V2 {
            return Err(Error::UnsupportedVersion);
        }

        if verifier.bundle_type() != BundleType::V2 {
            return Err(Error::UnsupportedVersion);
        }

        if self.state.item_ids.contains(item.id()) {
            return Err(Error::ItemAlreadyInBundle(item.id().clone()));
        }

        let item_id = item.id().clone();

        if self.ct.is_cancelled() {
            return Err(Error::Dead);
        }

        self.state.item_ids.insert(item.id().clone());

        // size estimation
        self.state.estimated_data_size += item.data_size() + item.data_offset();

        let (tx, rx) = watch::channel(Ok(ItemStatus::Queued));
        let item = UnprocessedItem::new(item, verifier, Box::new(data_source), tx);
        if let Err(_) = self.state.item_tx.send(item).await {
            // processor is dead
            self.ct.cancel();
            return Err(Error::Dead);
        }

        Ok(Receipt {
            item_id,
            bundler_id: self.id,
            state: State::Active(rx),
        })
    }

    pub fn item_count(&self) -> usize {
        self.state.item_ids.len()
    }

    pub fn estimated_data_size(&self) -> u64 {
        self.state.estimated_data_size
    }

    pub async fn transition<'a>(
        mut self,
        extra_tags: Option<Vec<Tag<'a>>>,
    ) -> Result<AsyncBundler<TxSigning>, Arc<Error>> {
        let processor_handle = self.state.processor_handle;
        drop(self.state.item_tx);
        let (items, header, data_verifier) = processor_handle
            .await
            .map_err(|_| Arc::new(Error::Dead))??;

        if items.is_empty() {
            return Err(Arc::new(Error::EmptyBundle));
        }

        // create a new tx
        let tx_submission = self
            .client
            .tx_begin()
            .await
            .map_err(|e| Arc::new(e.into()))?;

        let mut tags = vec![
            ("Bundle-Version", "2.0.0").into(),
            ("Bundle-Format", "binary").into(),
        ];

        if let Some(name) = self.state.bundler_app_name.take() {
            tags.push(("Bundler-App-Name".to_string(), name).into());
        }

        if let Some(extra_tags) = extra_tags {
            extra_tags
                .into_iter()
                .for_each(|t| tags.push(t.into_owned()))
        }

        let tx_draft = TxBuilder::v2()
            .tags(tags)
            .reward(0)
            .map_err(|e| Arc::new(Error::Other(e.to_string())))?
            .tx_anchor(tx_submission.tx_anchor().clone())
            .data_upload(data_verifier.data_item().clone().into())
            .draft();

        let state = TxSigning {
            header,
            items,
            data_verifier,
            tx_draft,
            tx_submission,
        };

        Ok(AsyncBundler {
            id: self.id,
            client: self.client,
            ct: self.ct,
            state,
            _drop_guard: self._drop_guard,
        })
    }
}

impl AsyncBundler<TxSigning> {
    pub fn item_count(&self) -> usize {
        self.state.items.len()
    }

    pub fn data_size(&self) -> u64 {
        self.state.data_verifier.data_item().data_size()
    }

    pub fn tx_draft(&self) -> TxDraft<'static> {
        self.state.tx_draft.clone()
    }

    pub async fn transition(
        self,
        signed_tx: ValidatedTx<'_>,
    ) -> Result<AsyncBundler<Uploading>, Error> {
        let data_item = match signed_tx.data_item() {
            Some(DataItem::External(di)) => di,
            _ => return Err(Error::TxMismatch),
        };
        let data_verifier = self.state.data_verifier;
        if data_item.data_size() != data_verifier.data_item().data_size()
            || data_item.data_root() != data_verifier.data_item().data_root()
        {
            return Err(Error::TxMismatch);
        }

        let data_size = data_verifier.data_item().data_size();
        let item_count = self.state.items.len();
        let reward_paid = signed_tx.reward().clone();

        let tx_sub = match self.state.tx_submission.submit(&signed_tx).await? {
            tx::Submission::AwaitingChunks(tx_sub) => tx_sub,
            _ => return Err(Error::TxCompletionPremature),
        };

        let tx_id = tx_sub.tx_id().clone();

        let mut uploader = Uploader::new(
            self.id,
            tx_sub
                .data(data_verifier.into())
                .map_err(|(_, e)| Error::from(e))?,
            self.state.header,
            self.state.items,
            self.ct.clone(),
        );
        let uploader_handle = tokio::spawn(async move { uploader.run().await });

        Ok(AsyncBundler {
            id: self.id,
            client: self.client,
            ct: self.ct,
            state: Uploading {
                tx_id,
                reward_paid,
                started: SystemTime::now(),
                item_count,
                data_size,
                uploader_handle,
            },
            _drop_guard: self._drop_guard,
        })
    }
}

impl AsyncBundler<Uploading> {
    pub fn tx_id(&self) -> &TxId {
        &self.state.tx_id
    }

    pub fn reward_paid(&self) -> &Reward {
        &self.state.reward_paid
    }

    pub fn item_count(&self) -> usize {
        self.state.item_count
    }

    pub fn data_size(&self) -> u64 {
        self.state.data_size
    }

    pub fn started(&self) -> SystemTime {
        self.state.started
    }

    pub async fn transition(self) -> Result<AsyncBundler<Submitted>, Arc<Error>> {
        let (mut items, tx_submission) = self
            .state
            .uploader_handle
            .await
            .map_err(|_| Arc::new(Error::Dead))??;
        items.iter_mut().for_each(|i| {
            let _ = i.status_tx.send(Ok(ItemStatus::TxPending {
                tx_id: tx_submission.tx_id().clone(),
                tx_upload_completion: tx_submission.submitted(),
            }));
        });
        Ok(AsyncBundler {
            id: self.id,
            client: self.client,
            ct: self.ct,
            state: Submitted {
                tx_id: self.state.tx_id,
                reward_paid: self.state.reward_paid,
                data_size: self.state.data_size,
                items,
                upload_duration: SystemTime::now()
                    .duration_since(self.state.started)
                    .expect("duration to never be negative"),
                tx_submission,
            },
            _drop_guard: self._drop_guard,
        })
    }
}

impl AsyncBundler<Submitted> {
    pub fn tx_id(&self) -> &TxId {
        &self.state.tx_id
    }

    pub fn reward_paid(&self) -> &Reward {
        &self.state.reward_paid
    }

    pub fn item_count(&self) -> usize {
        self.state.items.len()
    }

    pub fn data_size(&self) -> u64 {
        self.state.data_size
    }

    pub fn upload_duration(&self) -> Duration {
        self.state.upload_duration
    }

    pub async fn finalize(mut self) -> Result<(TxId, BlockNumber), Arc<Error>> {
        let mut status = self.state.tx_submission.status();
        while let Some(res) = status.next().await {
            match res {
                Ok(Status::Pending) => {}
                Ok(Status::Accepted(accepted)) => {
                    self.state.items.iter_mut().for_each(|i| {
                        let _ = i.status_tx.send(Ok(ItemStatus::Complete {
                            tx_id: self.state.tx_id.clone(),
                            tx_completion: SystemTime::now(),
                            block_height: accepted.block_height.clone(),
                        }));
                    });
                    return Ok((self.state.tx_id, accepted.block_height));
                }
                Err(err) => {
                    let err = Arc::new(Error::from(err));
                    self.state.items.iter_mut().for_each(|i| {
                        let _ = i.status_tx.send(Err(err.clone()));
                    });
                    return Err(err);
                }
            }
        }
        // stream ended prematurely
        let err = Arc::new(Error::Dead);
        self.state.items.iter_mut().for_each(|i| {
            let _ = i.status_tx.send(Err(err.clone()));
        });
        Err(err)
    }
}

struct Processor {
    bundler_id: Uuid,
    item_rx: mpsc::Receiver<UnprocessedItem>,
    ct: CancellationToken,
    _drop_guard: Option<DropGuard>,
}

impl Processor {
    fn new(
        bundler_id: Uuid,
        item_rx: mpsc::Receiver<UnprocessedItem>,
        ct: CancellationToken,
    ) -> Self {
        Self {
            bundler_id,
            item_rx,
            ct: ct.clone(),
            _drop_guard: Some(ct.drop_guard()),
        }
    }

    async fn run(
        &mut self,
    ) -> Result<
        (
            Vec<ProcessedItem>,
            OwnedBlob,
            ExternalDataItemVerifier<'static>,
        ),
        Arc<Error>,
    > {
        let mut processed_items = vec![];
        let ct = self.ct.clone();
        loop {
            tokio::select! {
                _ = ct.cancelled() => {
                    // task cancelled
                    return Err(Arc::new(Error::Cancelled));
                }
                maybe_item = self.item_rx.recv()  => {
                    if let Some(mut item) = maybe_item {
                        let _ = item.status_tx.send(Ok(ItemStatus::Processing));
                        tokio::select! {
                            _ = ct.cancelled() => {
                                // task cancelled
                                return Err(Arc::new(Error::Cancelled));
                            }
                            res = Self::process_item(&mut item) => {
                                match res {
                                    Ok(header) => {
                                        processed_items.push(item.processed(header));
                                    },
                                    Err(err) => {
                                        let err = Arc::new(err);
                                        let _ = item.status_tx.send(Err(err.clone()));
                                        return Err(err);
                                    }
                                }
                            }
                        }
                    } else {
                        // end reached
                        break;
                    }
                }
            }
        }

        tokio::select! {
            _ = ct.cancelled() => {
                // task cancelled
                Err(Arc::new(Error::Cancelled))
            }
            res = Self::process_all(processed_items.iter_mut()) => {
                match res {
                    Ok((header, verifier)) => {
                        // completed cleanly
                        // disarm drop_guard
                        self._drop_guard.take().unwrap().disarm();
                        Ok((processed_items, header, verifier))
                    }
                    Err(err) => {
                        Err(Arc::new(err))
                    }
                }
            }
        }
    }

    async fn process_item(item: &mut UnprocessedItem) -> Result<OwnedBlob, Error> {
        let header = match &item.item {
            ValidatedBundleItem::V2(v2) => v2
                .try_as_blob()
                .map_err(|e| Error::ItemError(e.to_string()))?,
        };
        let len = item.data_source.seek(SeekFrom::End(0)).await?;
        if len != item.item.data_size() {
            return Err(Error::InvalidDataLength {
                expected: item.item.data_size(),
                actual: len,
            });
        }
        Ok(header)
    }

    async fn process_all(
        items: impl Iterator<Item = &mut ProcessedItem>,
    ) -> Result<(OwnedBlob, ExternalDataItemVerifier<'static>), Error> {
        let items = items.collect_vec();
        let mut header = BytesMut::with_capacity(32 + (64 * items.len()));
        header.put_u16_le(items.len() as u16);
        header.extend(iter::repeat(0u8).take(30));

        for item in &items {
            header.put_u64_le(item.len());
            header.extend(iter::repeat(0u8).take(24));
            header.extend_from_slice(item.item.id().as_slice());
        }

        let header = OwnedBlob::from(header.freeze());

        let mut combinator = BundleItemCombinator::new(header.bytes(), items.into_iter());
        let verifier =
            ExternalDataItemVerifier::try_from_async_reader(&mut combinator, DefaultChunker::new())
                .await?;
        Ok((header, verifier))
    }
}

struct BundleItemCombinator<'a> {
    range_map: RangeMap<u64, u64>,
    entries: BTreeMap<u64, CombinedEntry<'a>>,
    pos: u64,
    len: u64,
    state: Option<CombiState>,
}

#[derive(PartialEq)]
enum CombiState {
    Reading(u64),
    Seeking(u64),
}

enum CombinedEntry<'a> {
    Header((Cursor<&'a [u8]>, u64)),
    Data((&'a mut Box<dyn AsyncDataSource>, u64)),
}

impl<'a> CombinedEntry<'a> {
    fn relative_pos(&self, pos: u64) -> Option<u64> {
        let (offset, len) = match self {
            Self::Header((_, len)) => (0, *len),
            Self::Data((_, len)) => (0, *len),
        };

        if pos > len { None } else { Some(pos + offset) }
    }

    fn as_data_source(&mut self) -> impl AsyncDataSource {
        let source: Box<dyn AsyncDataSource> = match self {
            Self::Header((cursor, _)) => Box::new(cursor),
            Self::Data((data, _)) => Box::new(data),
        };
        source
    }
}

impl<'a> BundleItemCombinator<'a> {
    fn new(header: &'a [u8], items: impl Iterator<Item = &'a mut ProcessedItem>) -> Self {
        let mut range_map = RangeMap::new();
        let mut entries = BTreeMap::new();
        let mut pos = 0;

        let len = header.len() as u64;
        entries.insert(pos, CombinedEntry::Header((Cursor::new(header), len)));
        range_map.insert(pos..(pos + len), pos);
        pos += len;

        items.into_iter().for_each(|i| {
            let header = i.state.header.bytes();
            let len = header.len() as u64;
            entries.insert(pos, CombinedEntry::Header((Cursor::new(header), len)));
            range_map.insert(pos..(pos + len), pos);
            pos += len;
            let data_len = i.item.data_size();
            entries.insert(pos, CombinedEntry::Data((&mut i.data_source, data_len)));
            range_map.insert(pos..(pos + data_len), pos);
            pos += data_len;
        });

        Self {
            len: pos,
            pos: 0,
            range_map,
            entries,
            state: None,
        }
    }

    fn get(&mut self, pos: u64) -> Option<(&mut CombinedEntry<'a>, u64)> {
        let start_pos = *self.range_map.get(&pos)?;
        let entry = self.entries.get_mut(&start_pos)?;
        let offset = pos - start_pos;
        Some((entry, offset))
    }

    fn poll_get(
        &mut self,
        cx: &mut Context<'_>,
        pos: u64,
        seek: bool,
    ) -> Poll<std::io::Result<impl AsyncDataSource + use<'_, 'a>>> {
        if pos > self.len {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "offset {} is out of bounds",
                pos
            ))));
        }

        let (entry, offset) = self.get(pos).ok_or(std::io::Error::other(format!(
            "no data found for offset {}",
            pos
        )))?;

        let relative_pos = entry
            .relative_pos(offset)
            .ok_or(std::io::Error::other(format!(
                "offset {} out of bounds for entry at pos {}",
                offset, pos
            )))?;

        let mut data_source = entry.as_data_source();
        if seek {
            ready!(Pin::new(&mut data_source).poll_seek(cx, SeekFrom::Start(relative_pos)))?;
        }
        Poll::Ready(Ok(data_source))
    }
}

impl AsyncRead for BundleItemCombinator<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let pos = this.pos;
        if pos >= this.len {
            return Poll::Ready(Ok(0));
        }

        let prev_state = this.state.replace(CombiState::Reading(pos));
        let seek = &prev_state != &this.state;

        let mut data_source = ready!(this.poll_get(cx, pos, seek))?;
        let n = ready!(Pin::new(&mut data_source).poll_read(cx, buf))?;
        drop(data_source);
        this.pos += n as u64;
        this.state.take();
        Poll::Ready(Ok(n))
    }
}

impl AsyncSeek for BundleItemCombinator<'_> {
    fn poll_seek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<std::io::Result<u64>> {
        let this = self.get_mut();
        let pos = match pos {
            SeekFrom::Start(pos) => pos,
            SeekFrom::End(pos) => this.len.saturating_add_signed(pos),
            SeekFrom::Current(pos) => this.pos.saturating_add_signed(pos),
        };
        this.state = Some(CombiState::Seeking(pos));
        ready!(this.poll_get(cx, pos, true))?;
        this.pos = pos;
        this.state.take();
        Poll::Ready(Ok(pos))
    }
}

struct Uploader {
    bundler_id: Uuid,
    tx_sub: Option<TxSubmission<UploadChunks<'static>>>,
    header: OwnedBlob,
    items: Vec<ProcessedItem>,
    ct: CancellationToken,
    _drop_guard: Option<DropGuard>,
}

impl Uploader {
    fn new(
        bundler_id: Uuid,
        tx_sub: TxSubmission<UploadChunks<'static>>,
        header: OwnedBlob,
        items: Vec<ProcessedItem>,
        ct: CancellationToken,
    ) -> Self {
        Self {
            bundler_id,
            tx_sub: Some(tx_sub),
            header,
            items,
            ct: ct.clone(),
            _drop_guard: Some(ct.drop_guard()),
        }
    }

    async fn run(&mut self) -> Result<(Vec<UploadedItem>, TxSubmission<TxSubmitted>), Arc<Error>> {
        let ct = self.ct.clone();
        let tx_sub = self.tx_sub.take().unwrap();

        self.items.iter_mut().for_each(|i| {
            let _ = i.status_tx.send(Ok(ItemStatus::Uploading {
                tx_id: tx_sub.tx_id().clone(),
                upload_start: SystemTime::now(),
            }));
        });

        let mut combinator = BundleItemCombinator::new(self.header.bytes(), self.items.iter_mut());
        tokio::select! {
            _ = ct.cancelled() => {
                // task cancelled
                Err(Arc::new(Error::Cancelled))
            }
            res = tx_sub.from_async_reader(&mut combinator) => {
                let tx_sub = match res {
                    Ok(tx_sub) => tx_sub,
                    Err((_, err)) => {
                        let err = Arc::new(Error::from(err));
                        self.items.iter_mut().for_each(|i| {
                            let _ = i.status_tx.send(Err(err.clone()));
                        });
                        return Err(err);
                    }
                };
                let now = SystemTime::now();
                let items = self.items.drain(..).map(|i| i.uploaded(tx_sub.tx_id().clone(), now.clone())).collect_vec();
                self._drop_guard.take().unwrap().disarm();
                Ok((items, tx_sub))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AsyncBundler;
    use ario_core::Gateway;
    use ario_core::bundle::{ArweaveScheme, BundleItemBuilder, V2BundleItemDataProcessor};
    use ario_core::jwk::Jwk;
    use ario_core::network::Network;
    use ario_core::wallet::Wallet;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    static FILE_1_PATH: &'static str = "./testdata/1mb.bin";
    static FILE_2_PATH: &'static str = "./testdata/rebar3";

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[ignore]
    #[tokio::test]
    async fn create_bundle() -> Result<(), anyhow::Error> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());
        let wallet_jwk = std::env::var("ARLOCAL_WALLET_JWK").unwrap();

        let client = crate::Client::builder()
            .enable_netwatch(false)
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .build()
            .await?;

        let json =
            tokio::fs::read_to_string(<PathBuf as AsRef<Path>>::as_ref(&PathBuf::from(wallet_jwk)))
                .await?;

        let jwk = Jwk::from_json(json.as_str())?;
        let wallet = Wallet::from_jwk(&jwk)?;

        let mut bundler_accepting = AsyncBundler::new(client.clone(), None);

        let mut file = tokio::fs::File::open(FILE_1_PATH).await?.compat();
        let data = V2BundleItemDataProcessor::try_from_async_reader(&mut file).await?;
        let verifier = data.verifier();

        let bundle_item_draft = BundleItemBuilder::v2()
            .tags(vec![("name1", "value1").into()])
            .data_upload(data)
            .draft()?;

        let _receipt1 = bundler_accepting
            .submit(
                wallet.sign_bundle_item_draft::<ArweaveScheme>(bundle_item_draft)?,
                verifier,
                file,
            )
            .await?;

        let mut file = tokio::fs::File::open(FILE_2_PATH).await?.compat();
        let data = V2BundleItemDataProcessor::try_from_async_reader(&mut file).await?;
        let verifier = data.verifier();

        let bundle_item_draft = BundleItemBuilder::v2()
            .tags(vec![("name2", "value2").into()])
            .data_upload(data)
            .draft()?;

        let _receipt2 = bundler_accepting
            .submit(
                wallet.sign_bundle_item_draft::<ArweaveScheme>(bundle_item_draft)?,
                verifier,
                file,
            )
            .await?;

        let bundler_signing = bundler_accepting.transition(None).await?;

        let mut tx_draft = bundler_signing.tx_draft();
        tx_draft.set_reward("100000")?;

        let tx_data_size = bundler_signing.data_size();

        let bundler_uploading = bundler_signing
            .transition(wallet.sign_tx_draft(tx_draft)?)
            .await?;

        let bundler_submitted = bundler_uploading.transition().await?;

        let (tx_id, block_height) = bundler_submitted.finalize().await?;

        println!("tx_id: {}, block_height: {}", tx_id, block_height);

        let tx = client.tx_by_id(&tx_id).await?.unwrap();

        assert_eq!(tx.data_item().unwrap().size(), tx_data_size);

        Ok(())
    }
}
