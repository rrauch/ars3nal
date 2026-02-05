use crate::tx::{Prepared, Status, Submitted as TxSubmitted, TxSubmission, UploadChunks};
use crate::{Client, tx};
use ario_core::BlockNumber;
use ario_core::blob::{Blob, OwnedBlob};
use ario_core::bundle::{
    AuthenticatedBundleItem, BundleItemAuthenticator, BundleItemBuilder, BundleItemDraft,
    BundleItemId, BundleType, V2BundleItemDataProcessor,
};
use ario_core::chunking::DefaultChunker;
use ario_core::data::{DataItem, ExternalDataItemAuthenticator};
use ario_core::tag::Tag;
use ario_core::tx::v2::TxDraft;
use ario_core::tx::{AuthenticatedTx, Reward, TxBuilder, TxId};
use async_stream::try_stream;
use bytes::{BufMut, BytesMut};
use futures_lite::io::Cursor;
use futures_lite::{
    AsyncRead, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, Stream, StreamExt, ready,
};
use itertools::Itertools;
use maybe_owned::MaybeOwnedMut;
use rangemap::RangeMap;
use std::collections::HashSet;
use std::io::{ErrorKind, SeekFrom};
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
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
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
    item: AuthenticatedBundleItem<'static>,
    authenticator: BundleItemAuthenticator<'static>,
    data_source: Box<dyn AsyncDataSource + 'static>,
    status_tx: watch::Sender<Result<ItemStatus, Arc<Error>>>,
    state: State,
}

impl<State> Item<State> {
    fn _state<Next>(self, next: Next) -> Item<Next> {
        Item {
            item: self.item,
            authenticator: self.authenticator,
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
        item: AuthenticatedBundleItem<'static>,
        authenticator: BundleItemAuthenticator<'static>,
        data_source: Box<dyn AsyncDataSource + 'static>,
        status_tx: watch::Sender<Result<ItemStatus, Arc<Error>>>,
    ) -> Self {
        Self {
            item,
            authenticator,
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
    ct: CancellationToken,
    state: State,
    _drop_guard: DropGuard,
}

pub struct AcceptingItems {
    item_tx: mpsc::Sender<UnprocessedItem>,
    item_ids: HashSet<BundleItemId>,
    bundler_app_name: Option<String>,
    estimated_data_size: u64,
    extra_tags: Option<Vec<Tag<'static>>>,
    processor_handle: JoinHandle<
        Result<
            (
                Vec<ProcessedItem>,
                OwnedBlob,
                ExternalDataItemAuthenticator<'static>,
            ),
            Arc<Error>,
        >,
    >,
}
pub struct Uploading {
    client: Client,
    tx_id: TxId,
    started: SystemTime,
    reward_paid: Reward,
    item_count: usize,
    data_size: u64,
    uploader_handle: JoinHandle<Result<(Vec<UploadedItem>, TxSubmission<TxSubmitted>), Arc<Error>>>,
}

pub struct Submitted {
    client: Client,
    tx_id: TxId,
    reward_paid: Reward,
    data_size: u64,
    upload_duration: Duration,
    items: Vec<UploadedItem>,
    tx_submission: TxSubmission<TxSubmitted>,
}

pub struct TxSigning {
    client: Client,
    header: OwnedBlob,
    items: Vec<ProcessedItem>,
    data_authenticator: ExternalDataItemAuthenticator<'static>,
    tx_draft: TxDraft<'static>,
    tx_submission: TxSubmission<Prepared>,
}

pub fn new_async_bundler(bundler_app_name: Option<String>) -> AsyncBundler<AcceptingItems> {
    AsyncBundler::new(bundler_app_name)
}

impl AsyncBundler<AcceptingItems> {
    pub fn new(bundler_app_name: Option<String>) -> Self {
        let id = Uuid::now_v7();
        let ct = CancellationToken::new();
        let (item_tx, item_rx) = mpsc::channel(10);

        let mut processor = Processor::new(id, item_rx, ct.clone());
        let processor_handle = tokio::spawn(async move { processor.run().await });

        let state = AcceptingItems {
            item_tx,
            item_ids: HashSet::new(),
            extra_tags: None,
            bundler_app_name,
            processor_handle,
            estimated_data_size: 0,
        };

        Self {
            id,
            _drop_guard: ct.clone().drop_guard(),
            ct,
            state,
        }
    }

    pub async fn submit<D: AsyncDataSource + 'static>(
        &mut self,
        item: AuthenticatedBundleItem<'static>,
        authenticator: BundleItemAuthenticator<'static>,
        data_source: D,
    ) -> Result<Receipt, Error> {
        if item.bundle_type() != BundleType::V2 {
            return Err(Error::UnsupportedVersion);
        }

        if authenticator.bundle_type() != BundleType::V2 {
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
        let item = UnprocessedItem::new(item, authenticator, Box::new(data_source), tx);
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

    pub fn set_extra_tags(&mut self, extra_tags: Vec<Tag<'static>>) {
        self.state.extra_tags = Some(extra_tags);
    }

    pub fn extra_tags(&self) -> Option<&Vec<Tag<'static>>> {
        self.state.extra_tags.as_ref()
    }

    async fn prepare_transition(
        mut self,
    ) -> Result<
        (
            Uuid,
            CancellationToken,
            DropGuard,
            Vec<ProcessedItem>,
            OwnedBlob,
            ExternalDataItemAuthenticator<'static>,
            Vec<Tag<'static>>,
        ),
        Arc<Error>,
    > {
        let processor_handle = self.state.processor_handle;
        drop(self.state.item_tx);
        let (items, header, data_authenticator) = processor_handle
            .await
            .map_err(|_| Arc::new(Error::Dead))??;

        if items.is_empty() {
            return Err(Arc::new(Error::EmptyBundle));
        }

        let mut tags = vec![
            ("Bundle-Version", "2.0.0").into(),
            ("Bundle-Format", "binary").into(),
        ];

        if let Some(name) = self.state.bundler_app_name.take() {
            tags.push(("Bundler-App-Name".to_string(), name).into());
        }

        if let Some(extra_tags) = self.state.extra_tags {
            tags.extend(extra_tags)
        }

        Ok((
            self.id,
            self.ct,
            self._drop_guard,
            items,
            header,
            data_authenticator,
            tags,
        ))
    }

    pub async fn into_nested(
        self,
    ) -> Result<
        (
            BundleItemDraft<'static>,
            BundleItemAuthenticator<'static>,
            Box<dyn BundleDataReader + 'static>,
        ),
        Arc<Error>,
    > {
        let (_, _, _, items, header, _, tags) = self.prepare_transition().await?;
        let mut combinator = BundleItemCombinator::new(header, items.into_iter());
        let data = V2BundleItemDataProcessor::try_from_async_reader(&mut combinator)
            .await
            .map_err(|e| Arc::new(e.into()))?;
        let authenticator = data.authenticator();

        let draft = BundleItemBuilder::v2()
            .tags(tags)
            .data_upload(data)
            .draft()
            .map_err(|e| Arc::new(Error::ItemError(e.to_string())))?;

        combinator
            .seek(SeekFrom::Start(0))
            .await
            .map_err(|e| Arc::new(Error::ItemError(e.to_string())))?;
        Ok((draft, authenticator, Box::new(combinator)))
    }

    pub async fn transition(self, client: Client) -> Result<AsyncBundler<TxSigning>, Arc<Error>> {
        let (id, ct, drop_guard, items, header, data_authenticator, tags) =
            self.prepare_transition().await?;

        // create a new tx
        let tx_submission = client.tx_begin().await.map_err(|e| Arc::new(e.into()))?;

        let tx_draft = TxBuilder::v2()
            .tags(tags)
            .reward(0)
            .map_err(|e| Arc::new(Error::Other(e.to_string())))?
            .tx_anchor(tx_submission.tx_anchor().clone())
            .data_upload(data_authenticator.data_item().clone().into())
            .draft();

        let state = TxSigning {
            client,
            header,
            items,
            data_authenticator,
            tx_draft,
            tx_submission,
        };

        Ok(AsyncBundler {
            id,
            ct,
            state,
            _drop_guard: drop_guard,
        })
    }
}

pub trait BundleDataReader: AsyncRead + AsyncSeek + Send + Sync + Unpin {
    fn len(&self) -> u64;
}
impl<'a> BundleDataReader for BundleItemCombinator<'a> {
    fn len(&self) -> u64 {
        self.len()
    }
}

impl AsyncBundler<TxSigning> {
    pub fn item_count(&self) -> usize {
        self.state.items.len()
    }

    pub fn data_size(&self) -> u64 {
        self.state.data_authenticator.data_item().data_size()
    }

    pub fn tx_draft(&self) -> TxDraft<'static> {
        self.state.tx_draft.clone()
    }

    pub async fn serialize(
        mut self,
        signed_tx: AuthenticatedTx<'_>,
        mut writer: impl AsyncWrite + Send + Unpin,
    ) -> Result<(), Error> {
        self.check(&signed_tx)?;
        let json = signed_tx.to_json_string()?;
        let json_len = json.as_bytes().len() as u64;
        writer.write_all(json_len.to_be_bytes().as_slice()).await?;
        writer.write_all(json.as_bytes()).await?;
        let data_len = signed_tx.data_item().map(|d| d.size()).unwrap_or(0);
        let mut combinator =
            BundleItemCombinator::new(self.state.header, self.state.items.iter_mut());
        let n = futures_lite::io::copy(&mut combinator, writer).await?;
        if n != signed_tx.data_item().unwrap().size() {
            Err(Error::InvalidDataLength {
                expected: data_len,
                actual: n,
            })?;
        }
        Ok(())
    }

    fn check(&self, signed_tx: &AuthenticatedTx<'_>) -> Result<(), Error> {
        let data_item = match signed_tx.data_item() {
            Some(DataItem::External(di)) => di,
            _ => return Err(Error::TxMismatch),
        };
        let data_authenticator = &self.state.data_authenticator;
        if data_item.data_size() != data_authenticator.data_item().data_size()
            || data_item.data_root() != data_authenticator.data_item().data_root()
        {
            return Err(Error::TxMismatch);
        }
        Ok(())
    }

    pub async fn transition(
        self,
        signed_tx: AuthenticatedTx<'_>,
    ) -> Result<AsyncBundler<Uploading>, Error> {
        self.check(&signed_tx)?;
        let data_size = self.state.data_authenticator.data_item().data_size();
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
                .data(self.state.data_authenticator.into())
                .map_err(|(_, e)| Error::from(e))?,
            self.state.header,
            self.state.items,
            self.ct.clone(),
        );
        let uploader_handle = tokio::spawn(async move { uploader.run().await });

        Ok(AsyncBundler {
            id: self.id,
            ct: self.ct,
            state: Uploading {
                client: self.state.client,
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
            ct: self.ct,
            state: Submitted {
                client: self.state.client,
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
            ExternalDataItemAuthenticator<'static>,
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
                    Ok((header, authenticator)) => {
                        // completed cleanly
                        // disarm drop_guard
                        self._drop_guard.take().unwrap().disarm();
                        Ok((processed_items, header, authenticator))
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
            AuthenticatedBundleItem::V2(v2) => v2
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
    ) -> Result<(OwnedBlob, ExternalDataItemAuthenticator<'static>), Error> {
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

        let mut combinator = BundleItemCombinator::new(header.borrow(), items.into_iter());
        let authenticator = ExternalDataItemAuthenticator::try_from_async_reader(
            &mut combinator,
            DefaultChunker::new(),
        )
        .await?;
        drop(combinator);
        Ok((header, authenticator))
    }
}

pub(crate) type BundleItemCombinator<'a> = ChainedReader<Box<dyn AsyncDataSource + 'a>>;

impl<'a> BundleItemCombinator<'a> {
    pub(crate) fn single_item(
        header: Blob<'a>,
        data: impl AsyncDataSource + 'a,
        data_len: u64,
    ) -> Self {
        let header_len = header.len() as u64;
        let header: Box<dyn AsyncDataSource + 'a> = Box::new(Cursor::new(header));
        let data = Box::new(data);

        Self::from_iter([(header, header_len), (data, data_len)])
    }

    fn new<I: Into<MaybeOwnedMut<'a, ProcessedItem>>>(
        header: Blob<'a>,
        items: impl Iterator<Item = I>,
    ) -> Self {
        let mut readers: Vec<(Box<dyn AsyncDataSource + 'a>, u64)> = vec![];

        let header_len = header.len() as u64;
        readers.push((Box::new(Cursor::new(header)), header_len));

        items.into_iter().for_each(|i| {
            let i = i.into();
            let header_len = i.state.header.len() as u64;
            let data_len = i.item.data_size();
            match i {
                MaybeOwnedMut::Owned(i) => {
                    readers.push((Box::new(Cursor::new(i.state.header)), header_len));
                    readers.push((i.data_source, data_len));
                }
                MaybeOwnedMut::Borrowed(i) => {
                    readers.push((Box::new(Cursor::new(i.state.header.borrow())), header_len));
                    readers.push((Box::new(i.data_source.as_mut()), data_len));
                }
            }
        });

        Self::from_iter(readers)
    }
}

pub(crate) struct ChainedReader<R> {
    readers: Vec<(R, u64)>,
    range_map: RangeMap<u64, usize>,
    total_length: u64,
    current_pos: u64,
    current_index: Option<usize>,
    must_seek: bool,
}

impl<R: AsyncRead + AsyncSeek + Unpin> FromIterator<(R, u64)> for ChainedReader<R> {
    fn from_iter<T: IntoIterator<Item = (R, u64)>>(iter: T) -> Self {
        let readers: Vec<_> = iter.into_iter().filter(|(_, len)| *len > 0).collect();

        let mut range_map = RangeMap::new();
        let mut offset = 0u64;
        for (i, (_, len)) in readers.iter().enumerate() {
            range_map.insert(offset..offset + len, i);
            offset += len;
        }

        Self {
            readers,
            range_map,
            total_length: offset,
            current_pos: 0,
            current_index: None,
            must_seek: true,
        }
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin> ChainedReader<R> {
    pub async fn try_from_iter<T: IntoIterator<Item = R>>(iter: T) -> Result<Self, std::io::Error> {
        let mut readers = vec![];
        for mut reader in iter.into_iter() {
            let len = reader.seek(SeekFrom::End(0)).await?;
            readers.push((reader, len));
        }

        Ok(Self::from_iter(readers))
    }
}

impl<R> ChainedReader<R> {
    #[inline]
    pub fn len(&self) -> u64 {
        self.total_length
    }

    fn find_reader_for_pos(&self, pos: u64) -> Option<(usize, u64)> {
        self.range_map.get_key_value(&pos).map(|(range, &index)| {
            let local_offset = pos - range.start;
            (index, local_offset)
        })
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin> AsyncRead for ChainedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;

        let Some((index, local_pos)) = this.find_reader_for_pos(this.current_pos) else {
            return Poll::Ready(Ok(0));
        };
        if this.current_index != Some(index) {
            // reader has changed
            this.must_seek = true;
            this.current_index = Some(index);
        }

        let (reader, len) = &mut this.readers[index];

        if this.must_seek {
            ready!(Pin::new(&mut *reader).poll_seek(cx, SeekFrom::Start(local_pos)))?;
            this.must_seek = false;
        }

        let remaining_in_reader = *len - local_pos;
        let max_read = (remaining_in_reader as usize).min(buf.len());
        let read_buf = &mut buf[..max_read];

        let n = ready!(Pin::new(reader).poll_read(cx, read_buf))?;

        if n == 0 {
            return Poll::Ready(Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "underlying reader returned EOF before declared length",
            )));
        }

        this.current_pos += n as u64;
        Poll::Ready(Ok(n))
    }
}

impl<R: AsyncSeek + Unpin> AsyncSeek for ChainedReader<R> {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        seek: SeekFrom,
    ) -> Poll<std::io::Result<u64>> {
        let this = &mut *self;

        let target: Option<u64> = match seek {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::End(offset) => {
                if offset >= 0 {
                    this.total_length.checked_add(offset as u64)
                } else {
                    this.total_length.checked_sub(offset.unsigned_abs())
                }
            }
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    this.current_pos.checked_add(offset as u64)
                } else {
                    this.current_pos.checked_sub(offset.unsigned_abs())
                }
            }
        };

        let Some(target) = target else {
            return Poll::Ready(Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "seek position overflow",
            )));
        };

        if target > this.total_length {
            return Poll::Ready(Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "seek past end",
            )));
        }

        this.current_pos = target;
        this.must_seek = true;
        Poll::Ready(Ok(target))
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

        let mut combinator = BundleItemCombinator::new(self.header.borrow(), self.items.iter_mut());
        tokio::select! {
            _ = ct.cancelled() => {
                // task cancelled
                Err(Arc::new(Error::Cancelled))
            }
            res = tx_sub.from_async_reader(&mut combinator) => {
                drop(combinator);
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
    use super::{AsyncBundler, ChainedReader};
    use ario_core::Gateway;
    use ario_core::bundle::{ArweaveScheme, BundleItemBuilder, V2BundleItemDataProcessor};
    use ario_core::jwk::Jwk;
    use ario_core::network::Network;
    use ario_core::wallet::Wallet;
    use futures_lite::io::Cursor;
    use futures_lite::{AsyncReadExt, AsyncSeekExt};
    use std::io::{ErrorKind, SeekFrom};
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    static FILE_1_PATH: &'static str = "./testdata/1mb.bin";
    static FILE_2_PATH: &'static str = "./testdata/rebar3";
    static FILE_3_PATH: &'static str = "./testdata/ZIKx8GszPodILJx3yOA1HBZ1Ma12gkEod_Lz2R2Idnk.tx";
    static FILE_4_PATH: &'static str = "./testdata/366659587055863.chunk2";

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

        let mut bundler_accepting = AsyncBundler::new(None);

        let mut file = tokio::fs::File::open(FILE_1_PATH).await?.compat();
        let data = V2BundleItemDataProcessor::try_from_async_reader(&mut file).await?;
        let authenticator = data.authenticator();

        let bundle_item_draft = BundleItemBuilder::v2()
            .tags(vec![("name1", "value1").into()])
            .data_upload(data)
            .draft()?;

        let _receipt1 = bundler_accepting
            .submit(
                wallet.sign_bundle_item_draft::<ArweaveScheme>(bundle_item_draft)?,
                authenticator,
                file,
            )
            .await?;

        let mut file = tokio::fs::File::open(FILE_2_PATH).await?.compat();
        let data = V2BundleItemDataProcessor::try_from_async_reader(&mut file).await?;
        let authenticator = data.authenticator();

        let bundle_item_draft = BundleItemBuilder::v2()
            .tags(vec![("name2", "value2").into()])
            .data_upload(data)
            .draft()?;

        let _receipt2 = bundler_accepting
            .submit(
                wallet.sign_bundle_item_draft::<ArweaveScheme>(bundle_item_draft)?,
                authenticator,
                file,
            )
            .await?;

        let bundler_signing = bundler_accepting.transition(client.clone()).await?;

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

    #[tokio::test]
    async fn empty_readers_vec() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::<Cursor<Vec<u8>>>::try_from_iter(std::iter::empty()).await?;

        assert_eq!(reader.len(), 0);

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).await?;
        assert_eq!(n, 0);

        let pos = reader.seek(SeekFrom::Start(0)).await?;
        assert_eq!(pos, 0);
        Ok(())
    }

    #[tokio::test]
    async fn single_reader_read_all() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::try_from_iter(vec![Cursor::new(b"hello")].into_iter()).await?;

        assert_eq!(reader.len(), 5);

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).await?;
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
        Ok(())
    }

    #[tokio::test]
    async fn multiple_readers_sequential_read() -> Result<(), anyhow::Error> {
        let mut reader = ChainedReader::try_from_iter(
            vec![
                Cursor::new(b"aaa"),
                Cursor::new(b"bbb"),
                Cursor::new(b"ccc"),
            ]
            .into_iter(),
        )
        .await?;

        assert_eq!(reader.len(), 9);

        let mut result = Vec::new();
        loop {
            let mut buf = [0u8; 2];
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            result.extend_from_slice(&buf[..n]);
        }
        assert_eq!(result, b"aaabbbccc");
        Ok(())
    }

    #[tokio::test]
    async fn zero_length_readers_filtered() -> Result<(), anyhow::Error> {
        let mut reader = ChainedReader::try_from_iter(
            vec![
                Cursor::new(b"".as_slice()),
                Cursor::new(b"abc".as_slice()),
                Cursor::new(b"".as_slice()),
                Cursor::new(b"def".as_slice()),
            ]
            .into_iter(),
        )
        .await?;

        assert_eq!(reader.len(), 6);

        let mut buf = [0u8; 10];
        let mut result = Vec::new();
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            result.extend_from_slice(&buf[..n]);
        }
        assert_eq!(result, b"abcdef");
        Ok(())
    }

    #[tokio::test]
    async fn seek_start() -> Result<(), anyhow::Error> {
        let mut reader = ChainedReader::try_from_iter(
            vec![Cursor::new(b"aaa"), Cursor::new(b"bbb")].into_iter(),
        )
        .await?;

        let pos = reader.seek(SeekFrom::Start(4)).await?;
        assert_eq!(pos, 4);

        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf).await?;

        assert_eq!(buf.as_slice(), b"bb");
        Ok(())
    }

    #[tokio::test]
    async fn seek_current_forward() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::try_from_iter(vec![Cursor::new(b"abcdef")].into_iter()).await?;

        reader.seek(SeekFrom::Start(2)).await?;
        let pos = reader.seek(SeekFrom::Current(2)).await?;
        assert_eq!(pos, 4);

        let mut buf = [0u8; 2];
        let n = reader.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"ef");
        Ok(())
    }

    #[tokio::test]
    async fn seek_current_backward() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::try_from_iter(vec![Cursor::new(b"abcdef")].into_iter()).await?;

        reader.seek(SeekFrom::Start(4)).await?;
        let pos = reader.seek(SeekFrom::Current(-2)).await?;
        assert_eq!(pos, 2);

        let mut buf = [0u8; 2];
        let n = reader.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"cd");
        Ok(())
    }

    #[tokio::test]
    async fn seek_end() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::try_from_iter(vec![Cursor::new(b"abcdef")].into_iter()).await?;

        let pos = reader.seek(SeekFrom::End(-2)).await?;
        assert_eq!(pos, 4);

        let mut buf = [0u8; 2];
        let n = reader.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"ef");
        Ok(())
    }

    #[tokio::test]
    async fn seek_end_zero() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::try_from_iter(vec![Cursor::new(b"abc")].into_iter()).await?;

        let pos = reader.seek(SeekFrom::End(0)).await?;
        assert_eq!(pos, 3);

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).await?;
        assert_eq!(n, 0);
        Ok(())
    }

    #[tokio::test]
    async fn seek_past_end_error() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::try_from_iter(vec![Cursor::new(b"abc")].into_iter()).await?;

        let result = reader.seek(SeekFrom::Start(4)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        Ok(())
    }

    #[tokio::test]
    async fn seek_before_start_error() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::try_from_iter(vec![Cursor::new(b"abc")].into_iter()).await?;

        let result = reader.seek(SeekFrom::Current(-1)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        Ok(())
    }

    #[tokio::test]
    async fn seek_back_and_forth() -> Result<(), anyhow::Error> {
        let mut reader = ChainedReader::try_from_iter(
            vec![
                Cursor::new(b"aaa"),
                Cursor::new(b"bbb"),
                Cursor::new(b"ccc"),
            ]
            .into_iter(),
        )
        .await?;

        let mut buf = [0u8; 1];

        reader.seek(SeekFrom::Start(7)).await?;
        reader.read(&mut buf).await?;
        assert_eq!(&buf, b"c");

        reader.seek(SeekFrom::Start(1)).await?;
        reader.read(&mut buf).await?;
        assert_eq!(&buf, b"a");

        reader.seek(SeekFrom::Start(4)).await?;
        reader.read(&mut buf).await?;
        assert_eq!(&buf, b"b");
        Ok(())
    }

    #[tokio::test]
    async fn read_across_boundary() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::try_from_iter(vec![Cursor::new(b"aa"), Cursor::new(b"bb")].into_iter())
                .await?;

        reader.seek(SeekFrom::Start(1)).await?;

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).await?;
        // Should only return up to end of first reader
        assert_eq!(&buf[..n], b"a");

        let n = reader.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"bb");
        Ok(())
    }

    #[tokio::test]
    async fn seek_to_exact_boundary() -> Result<(), anyhow::Error> {
        let mut reader = ChainedReader::try_from_iter(
            vec![Cursor::new(b"aaa"), Cursor::new(b"bbb")].into_iter(),
        )
        .await?;

        reader.seek(SeekFrom::Start(3)).await?;

        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf).await?;
        assert_eq!(buf.as_slice(), b"bbb");
        Ok(())
    }

    #[tokio::test]
    async fn unexpected_eof() -> Result<(), anyhow::Error> {
        // Lie about length - say 10 bytes but only have 3
        let mut reader =
            ChainedReader::from_iter(vec![(Cursor::new(b"abc".to_vec()), 10)].into_iter());

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).await?;
        assert_eq!(n, 3);

        let result = reader.read(&mut buf).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::UnexpectedEof);
        Ok(())
    }

    #[tokio::test]
    async fn seek_empty_reader_to_zero() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::<Cursor<Vec<u8>>>::try_from_iter(std::iter::empty()).await?;

        let pos = reader.seek(SeekFrom::Start(0)).await?;
        assert_eq!(pos, 0);

        let pos = reader.seek(SeekFrom::End(0)).await?;
        assert_eq!(pos, 0);

        let pos = reader.seek(SeekFrom::Current(0)).await?;
        assert_eq!(pos, 0);
        Ok(())
    }

    #[tokio::test]
    async fn seek_empty_reader_nonzero_error() -> Result<(), anyhow::Error> {
        let mut reader =
            ChainedReader::<Cursor<Vec<u8>>>::try_from_iter(std::iter::empty()).await?;

        let result = reader.seek(SeekFrom::Start(1)).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn larger_file_test() -> Result<(), anyhow::Error> {
        let expected_total_len = (tokio::fs::metadata(FILE_1_PATH).await?.len() * 2)
            + tokio::fs::metadata(FILE_2_PATH).await?.len()
            + tokio::fs::metadata(FILE_3_PATH).await?.len()
            + tokio::fs::metadata(FILE_4_PATH).await?.len();

        let readers = vec![
            tokio::fs::File::open(FILE_1_PATH).await?.compat(),
            tokio::fs::File::open(FILE_2_PATH).await?.compat(),
            tokio::fs::File::open(FILE_3_PATH).await?.compat(),
            tokio::fs::File::open(FILE_4_PATH).await?.compat(),
            tokio::fs::File::open(FILE_1_PATH).await?.compat(),
        ];

        let mut reader = ChainedReader::try_from_iter(readers).await?;
        assert_eq!(reader.len(), expected_total_len);

        let mut expected = Vec::with_capacity(expected_total_len as usize);
        expected.append(&mut tokio::fs::read(FILE_1_PATH).await?);
        expected.append(&mut tokio::fs::read(FILE_2_PATH).await?);
        expected.append(&mut tokio::fs::read(FILE_3_PATH).await?);
        expected.append(&mut tokio::fs::read(FILE_4_PATH).await?);
        expected.append(&mut tokio::fs::read(FILE_1_PATH).await?);

        let mut actual = Vec::with_capacity(reader.len() as usize);
        reader.read_to_end(&mut actual).await?;

        assert_eq!(expected, actual);

        Ok(())
    }
}
