use crate::api::RequestMethod::Post;
use crate::api::{Api, ApiRequest, ApiRequestBody, ContentType, ViaJson};
use crate::{Client, RawItemId, api};
use ario_core::base64::{TryFromBase64, TryFromBase64Error};
use ario_core::{BlockId, BlockIdError, BlockNumber, Gateway, ItemId, tx};
use async_stream::try_stream;
use bytesize::ByteSize;
use chrono::{DateTime, Utc};
pub use cynic::QueryBuilder as GraphQlQueryBuilder;
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::str::FromStr;
use thiserror::Error;

use crate::graphql::ConversionError::{ByteSizeError, InvalidTimestamp};
use ario_core::MaybeOwned;
use ario_core::base64::{Base64Error, FromBase64, ToBase64};
use ario_core::blob::{AsBlob, Blob};
use ario_core::bundle::{BundleAnchor, BundleAnchorError, BundleItemId, BundleItemIdError};
use ario_core::money::{AR, Money, MoneyError, Winston};
use ario_core::tag::Tag;
use ario_core::tx::{QuantityError, Reward, RewardError, TxAnchor, TxAnchorError, TxId, TxIdError};
use ario_core::wallet::{WalletAddress, WalletAddressError};
use cynic::queries::{IsFieldType, SelectionBuilder};
use cynic::schema::HasField;
use cynic::{Operation, OperationBuilder, QueryFragment, QueryVariablesFields};
use derive_where::derive_where;
use futures_lite::Stream;

#[cynic::schema("arweave")]
mod schema {}

#[derive(Error, Debug)]
pub enum GraphQlError {
    #[error(transparent)]
    Tx(#[from] GraphQlTxError),
    #[error("graphql error: {0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum GraphQlTxError {
    #[error("Winston and AR amounts do not match: '{winston}' Winston != '{ar}' AR")]
    AmountNotEqual {
        winston: Money<Winston>,
        ar: Money<AR>,
    },
    #[error(transparent)]
    RewardError(#[from] RewardError),
    #[error(transparent)]
    QuantityError(#[from] QuantityError),
    #[error(transparent)]
    ConversionError(#[from] ConversionError),
}

#[derive(Error, Debug)]
pub enum ConversionError {
    #[error(transparent)]
    TxIdError(#[from] TxIdError),
    #[error(transparent)]
    BlockIdError(#[from] BlockIdError),
    #[error(transparent)]
    BundleItemIdError(#[from] BundleItemIdError),
    #[error("invalid bundled in id value")]
    BundledInIdError,
    #[error(transparent)]
    TxAnchorError(#[from] TxAnchorError),
    #[error(transparent)]
    BundleAnchorError(#[from] BundleAnchorError),
    #[error(transparent)]
    WalletAddressError(#[from] WalletAddressError),
    #[error(transparent)]
    MoneyError(#[from] MoneyError),
    #[error(transparent)]
    RewardError(#[from] RewardError),
    #[error("invalid byte size: {0}")]
    ByteSizeError(String),
    #[error(transparent)]
    TxSignatureOwnerError(#[from] tx::SignatureOwnerError),
    #[error(transparent)]
    Base64Error(#[from] Base64Error),
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(i64),
}

impl Api {
    async fn graphql_query<
        Q: QueryFragment<SchemaType = schema::Query> + for<'de> Deserialize<'de>,
    >(
        &self,
        gateway: &Gateway,
        query: Operation<Q>,
    ) -> Result<Option<Q>, api::Error> {
        let req = ApiRequest::builder()
            .endpoint(gateway.join("./graphql").map_err(api::Error::InvalidUrl)?)
            .request_method(Post)
            .max_response_len(ByteSize::mib(1))
            .body(
                ApiRequestBody::builder()
                    .content_type(ContentType::Json)
                    .payload((&query).try_into()?)
                    .build(),
            )
            .build();

        let resp = self
            .send_api_request::<ViaJson<cynic::GraphQlResponse<Q>>>(req)
            .await?
            .0;

        if let Some(mut errors) = resp.errors {
            if !errors.is_empty() {
                return Err(GraphQlError::Other(errors.drain(..).next().unwrap().message).into());
            }
        }

        Ok(resp.data)
    }
}

impl Client {
    #[inline]
    pub fn query_transactions<'a>(
        &'a self,
        tx_query: TxQuery<'a>,
    ) -> impl Stream<Item = Result<TxQueryItem, super::Error>> + Send + Unpin {
        self.query_transactions_with_fields::<MinimalTxResponse>(tx_query)
    }
    pub fn query_transactions_with_fields<'a, Fields: TxQueryFieldSelector + Send>(
        &'a self,
        tx_query: TxQuery<'a>,
    ) -> impl Stream<Item = Result<TxQueryItem, super::Error>> + Send + Unpin {
        self._query_transactions::<RawTx<Fields>>(tx_query)
    }

    fn _query_transactions<
        T: QueryFragment<VariablesFields = ()> + Debug + for<'de> Deserialize<'de> + Send,
    >(
        &self,
        tx_query: TxQuery<'_>,
    ) -> Pin<Box<dyn Stream<Item = Result<TxQueryItem, super::Error>> + Send + '_>>
    where
        <T as QueryFragment>::SchemaType: IsFieldType<schema::Transaction>,
        TxQueryItem: TryFrom<T, Error: Into<GraphQlTxError>>,
    {
        let per_page = tx_query
            .results_per_page
            .unwrap_or(NonZeroUsize::new(1000).unwrap())
            .get();
        let mut variables = TxQueryVariables::from(&tx_query);

        let mut batch_result = VecDeque::with_capacity(per_page);
        let mut cursor = None;
        let mut eof = false;
        Box::pin(try_stream! {
            loop {
                while let Some(entry) = batch_result.pop_front() {
                    yield entry;
                }

                if eof {
                    return;
                }
                variables.after = cursor.take();

                let query = OperationBuilder::<GraphQlTxQuery<T>, TxQueryVariables>::query()
                    .with_variables(variables.clone())
                    .build_with_variables_inlined()
                    .expect("builder to succeed");

                match self
                    .with_gw(async |gw| {
                        self.0
                            .api
                            .graphql_query(gw, query)
                            .await
                    })
                    .await?
                    .map(|q| q.transactions)
                    .flatten()
                {
                    Some(tc) => {
                        eof = !tc.page_info.map(|p| p.has_next_page).flatten().unwrap_or(true);
                        tc.edges.into_iter().try_for_each(|e| {
                            cursor = e.cursor;
                            let item = TxQueryItem::try_from(e.node).map_err(|e| api::Error::GraphQlError(GraphQlError::Tx(e.into())))?;
                            batch_result.push_back(item);
                            Ok::<(), super::Error>(())
                        })?;
                    }
                    None => {
                        // eof reached
                        eof = true;
                    },
                }
            }
        })
    }
}

#[derive(Debug, Clone, bon::Builder)]
pub struct TxQuery<'a> {
    filter_criteria: TxQueryFilterCriteria<'a>,
    #[builder(into)]
    max_results: Option<NonZeroUsize>,
    #[builder(into)]
    results_per_page: Option<NonZeroUsize>,
    #[builder(default)]
    sort_order: SortOrder,
}

#[derive(Debug, Clone)]
pub enum TxQueryId<'a> {
    ItemId(MaybeOwned<'a, ItemId>),
    Unknown(MaybeOwned<'a, RawItemId>),
}

impl<'a> From<&'a ItemId> for TxQueryId<'a> {
    fn from(value: &'a ItemId) -> Self {
        Self::ItemId(value.into())
    }
}

impl<'a> From<ItemId> for TxQueryId<'a> {
    fn from(value: ItemId) -> Self {
        Self::ItemId(value.into())
    }
}

impl From<TxId> for TxQueryId<'static> {
    fn from(value: TxId) -> Self {
        Self::ItemId(ItemId::Tx(value).into())
    }
}

impl From<BundleItemId> for TxQueryId<'static> {
    fn from(value: BundleItemId) -> Self {
        Self::ItemId(ItemId::BundleItem(value).into())
    }
}

impl<'a> From<&'a BundledInId> for TxQueryId<'a> {
    fn from(value: &'a BundledInId) -> Self {
        Self::Unknown((&value.0).into())
    }
}

impl From<BundledInId> for TxQueryId<'static> {
    fn from(value: BundledInId) -> Self {
        Self::Unknown(value.0.into())
    }
}

impl<'a> From<&'a RawItemId> for TxQueryId<'a> {
    fn from(value: &'a RawItemId) -> Self {
        Self::Unknown(value.into())
    }
}

impl From<RawItemId> for TxQueryId<'static> {
    fn from(value: RawItemId) -> Self {
        Self::Unknown(value.into())
    }
}

impl<'a> Display for TxQueryId<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ItemId(item) => Display::fmt(item, f),
            Self::Unknown(bytes) => {
                let base64 = bytes.as_blob().to_base64();
                f.write_str(base64.as_str())
            }
        }
    }
}

#[derive(Debug, Clone, bon::Builder)]
pub struct TxQueryFilterCriteria<'a> {
    #[builder(with = |iter: impl IntoIterator<Item: Into<TxQueryId<'a>>>| {
            iter.into_iter().map(|v| v.into()).collect()
        }, default)]
    ids: Vec<TxQueryId<'a>>,
    #[builder(with = |iter: impl IntoIterator<Item: Into<MaybeOwned<'a, WalletAddress>>>| {
            iter.into_iter().map(|v| v.into()).collect()
        }, default)]
    owners: Vec<MaybeOwned<'a, WalletAddress>>,
    #[builder(with = |iter: impl IntoIterator<Item: Into<MaybeOwned<'a, WalletAddress>>>| {
            iter.into_iter().map(|v| v.into()).collect()
        }, default)]
    recipients: Vec<MaybeOwned<'a, WalletAddress>>,
    #[builder(with = |iter: impl IntoIterator<Item: Into<TagFilter<'a>>>| {
            iter.into_iter().map(|v| v.into()).collect()
        }, default)]
    tags: Vec<TagFilter<'a>>,
    #[builder(with = |iter: impl IntoIterator<Item: Into<MaybeOwned<'a, TxId>>>| {
            iter.into_iter().map(|v| v.into()).collect()
        }, default)]
    bundled_in: Vec<MaybeOwned<'a, TxId>>,
    block_range: Option<BlockRange>,
}

#[derive(cynic::Enum, Copy, Debug, Clone)]
#[cynic(graphql_type = "SortOrder")]
pub enum SortOrder {
    #[cynic(rename = "HEIGHT_ASC")]
    HeightAscending,
    #[cynic(rename = "HEIGHT_DESC")]
    HeightDescending,
}

impl Default for SortOrder {
    fn default() -> Self {
        Self::HeightDescending
    }
}

#[derive(Debug, Clone)]
pub struct BlockRange {
    pub start: BlockNumber,
    pub end: BlockNumber,
}

#[derive(cynic::Enum, Debug, Clone, Copy, PartialEq, Eq)]
#[cynic(graphql_type = "TagOperator")]
pub enum TagOperator {
    #[cynic(rename = "EQ")]
    Equal,
    #[cynic(rename = "NEQ")]
    NotEqual,
}

impl Default for TagOperator {
    fn default() -> Self {
        Self::Equal
    }
}

#[derive(Debug, Clone, bon::Builder)]
pub struct TagFilter<'a> {
    #[builder(into)]
    name: Cow<'a, str>,
    #[builder(with = |iter: impl IntoIterator<Item: Into<Cow<'a, str>>>| {
            iter.into_iter().map(|v| v.into()).collect()
        }, default)]
    values: Vec<Cow<'a, str>>,
    #[builder(default)]
    operator: TagOperator,
}

#[derive(cynic::InputObject, Debug, Clone)]
#[cynic(graphql_type = "TagFilter")]
struct RawTagFilter {
    name: String,
    values: Vec<String>,
    op: TagOperator,
}

impl<'a> From<TagFilter<'a>> for RawTagFilter {
    fn from(value: TagFilter<'a>) -> Self {
        Self {
            name: value.name.into_owned(),
            values: value.values.into_iter().map(|v| v.into_owned()).collect(),
            op: value.operator.into(),
        }
    }
}

#[derive(cynic::QueryVariables, cynic::QueryVariableLiterals, Debug, Clone)]
struct TxQueryVariables {
    #[cynic(skip_serializing_if = "Option::is_none")]
    ids: Option<Vec<cynic::Id>>,
    #[cynic(skip_serializing_if = "Option::is_none")]
    owners: Option<Vec<String>>,
    #[cynic(skip_serializing_if = "Option::is_none")]
    recipients: Option<Vec<String>>,
    #[cynic(rename = "bundledIn", skip_serializing_if = "Option::is_none")]
    bundled_in: Option<Vec<cynic::Id>>,
    #[cynic(skip_serializing_if = "Option::is_none")]
    block_range: Option<RawBlockFilter>,
    #[cynic(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<RawTagFilter>>,
    #[cynic(skip_serializing_if = "Option::is_none")]
    after: Option<String>,
    #[cynic(skip_serializing_if = "Option::is_none")]
    first: Option<i32>,
    sort_order: SortOrder,
}

#[derive(cynic::InputObject, Debug, Clone)]
#[cynic(graphql_type = "BlockFilter")]
struct RawBlockFilter {
    min: i32,
    max: i32,
}

impl From<BlockRange> for RawBlockFilter {
    fn from(value: BlockRange) -> Self {
        Self {
            min: *value.start as i32,
            max: *value.end as i32,
        }
    }
}

impl<'a> From<&'a TxQuery<'a>> for TxQueryVariables {
    fn from(value: &'a TxQuery<'a>) -> Self {
        Self {
            ids: if value.filter_criteria.ids.is_empty() {
                None
            } else {
                Some(
                    value
                        .filter_criteria
                        .ids
                        .iter()
                        .map(|v| cynic::Id::new(v.to_string()))
                        .collect(),
                )
            },
            owners: if value.filter_criteria.owners.is_empty() {
                None
            } else {
                Some(
                    value
                        .filter_criteria
                        .owners
                        .iter()
                        .map(|v| v.to_string())
                        .collect(),
                )
            },
            recipients: if value.filter_criteria.recipients.is_empty() {
                None
            } else {
                Some(
                    value
                        .filter_criteria
                        .recipients
                        .iter()
                        .map(|v| v.to_string())
                        .collect(),
                )
            },
            bundled_in: if value.filter_criteria.bundled_in.is_empty() {
                None
            } else {
                Some(
                    value
                        .filter_criteria
                        .bundled_in
                        .iter()
                        .map(|v| cynic::Id::new(v.to_string()))
                        .collect(),
                )
            },
            tags: if value.filter_criteria.tags.is_empty() {
                None
            } else {
                Some(
                    value
                        .filter_criteria
                        .tags
                        .iter()
                        .map(|v| v.clone().into())
                        .collect(),
                )
            },
            block_range: value.filter_criteria.block_range.clone().map(|v| v.into()),
            first: value.results_per_page.map(|v| v.get() as i32),
            sort_order: value.sort_order,
            after: None,
        }
    }
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(graphql_type = "Bundle")]
struct RawBundle {
    id: cynic::Id,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(graphql_type = "Owner")]
struct RawOwner {
    key: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(graphql_type = "Amount")]
struct RawAmount {
    winston: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(graphql_type = "Block")]
struct RawBlock {
    id: cynic::Id,
    timestamp: i32,
    height: i32,
    previous: cynic::Id,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(graphql_type = "MetaData")]
struct RawMetadata {
    size: String,
    #[cynic(rename = "type")]
    content_type: Option<String>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(graphql_type = "Tag")]
struct RawTag {
    name: String,
    value: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(graphql_type = "Query", variables = "TxQueryVariables")]
struct GraphQlTxQuery<T: QueryFragment<VariablesFields = ()> + Debug>
where
    <T as QueryFragment>::SchemaType: IsFieldType<schema::Transaction>,
{
    #[arguments(ids: $ids, owners: $owners, recipients: $recipients, tags: $tags, bundledIn: $bundled_in, block: $block_range, first: $first, sort: $sort_order, after: $after
    )]
    transactions: Option<TransactionConnection<T>>,
}

#[derive(cynic::QueryFragment, Debug)]
struct TransactionConnection<T: QueryFragment<VariablesFields = ()> + Debug>
where
    <T as QueryFragment>::SchemaType: IsFieldType<schema::Transaction>,
{
    #[cynic(rename = "pageInfo")]
    page_info: Option<PageInfo>,
    edges: Vec<TransactionEdge<T>>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(graphql_type = "TransactionEdge")]
struct TransactionEdge<T: QueryFragment<VariablesFields = ()> + Debug>
where
    <T as QueryFragment>::SchemaType: IsFieldType<schema::Transaction>,
{
    cursor: Option<String>,
    node: T,
}

#[derive(cynic::QueryFragment, Debug)]
struct PageInfo {
    #[cynic(rename = "hasNextPage")]
    has_next_page: Option<bool>,
}

trait QueryFieldSelector {
    type SchemaType;
    type VariablesFields: QueryVariablesFields;

    fn query(builder: SelectionBuilder<'_, Self::SchemaType, Self::VariablesFields>);
}

trait TxQueryFieldSelector:
    QueryFieldSelector<SchemaType = schema::Transaction, VariablesFields = ()>
{
}

impl<T> TxQueryFieldSelector for T where
    T: QueryFieldSelector<SchemaType = schema::Transaction, VariablesFields = ()>
{
}

pub type MinimalTxResponse =
    WithTxResponseFields<false, false, false, false, false, false, false, false>;
pub type FullTxResponse = WithTxResponseFields<true, true, true, true, true, true, true, true>;

pub struct WithTxResponseFields<
    const ANCHOR: bool,
    const RECIPIENT: bool,
    const OWNER_SIGNATURE: bool,
    const FEE: bool,
    const QUANTITY: bool,
    const METADATA: bool,
    const TAGS: bool,
    const BLOCK: bool,
>;

impl<
    const ANCHOR: bool,
    const RECIPIENT: bool,
    const OWNER_SIGNATURE: bool,
    const FEE: bool,
    const QUANTITY: bool,
    const METADATA: bool,
    const TAGS: bool,
    const BLOCK: bool,
> QueryFieldSelector
    for WithTxResponseFields<
        ANCHOR,
        RECIPIENT,
        OWNER_SIGNATURE,
        FEE,
        QUANTITY,
        METADATA,
        TAGS,
        BLOCK,
    >
{
    type SchemaType = schema::Transaction;
    type VariablesFields = ();

    fn query(builder: SelectionBuilder<'_, schema::Transaction, ()>) {
        tx_query_select_fields(
            ANCHOR,
            RECIPIENT,
            OWNER_SIGNATURE,
            FEE,
            QUANTITY,
            METADATA,
            TAGS,
            BLOCK,
            builder,
        );
    }
}

fn tx_query_select_fields(
    anchor: bool,
    recipient: bool,
    owner_signature: bool,
    fee: bool,
    quantity: bool,
    metadata: bool,
    tags: bool,
    block: bool,
    mut builder: SelectionBuilder<'_, schema::Transaction, ()>,
) {
    fn select_scalar_field<
        Field: cynic::schema::Field,
        ScalarType: cynic::schema::IsScalar<<Field as cynic::schema::Field>::Type>,
    >(
        builder: &mut SelectionBuilder<'_, schema::Transaction, ()>,
    ) where
        schema::Transaction: HasField<Field>,
        <ScalarType as cynic::schema::IsScalar<<Field as cynic::schema::Field>::Type>>::SchemaType:
            IsFieldType<<schema::Transaction as HasField<Field>>::Type>,
    {
        builder.select_field::<Field, ScalarType::SchemaType>();
    }

    fn select_query_fragment<
        Field: cynic::schema::Field,
        QueryFragment: cynic::QueryFragment<VariablesFields = ()>,
    >(
        builder: &mut SelectionBuilder<'_, schema::Transaction, ()>,
    ) where
        schema::Transaction: HasField<Field>,
        <QueryFragment as cynic::QueryFragment>::SchemaType:
            IsFieldType<<schema::Transaction as HasField<Field>>::Type>,
    {
        let mut field_builder =
            builder.select_field::<Field, <QueryFragment as cynic::QueryFragment>::SchemaType>();
        <QueryFragment as cynic::QueryFragment>::query(field_builder.select_children());
    }

    type Field = schema::__fields::Transaction::id;
    builder.select_field::<Field, <Field as cynic::schema::Field>::Type>();

    if anchor {
        select_scalar_field::<schema::__fields::Transaction::anchor, String>(&mut builder);
    }

    if owner_signature {
        select_query_fragment::<schema::__fields::Transaction::owner, RawOwner>(&mut builder);
        select_scalar_field::<schema::__fields::Transaction::signature, String>(&mut builder);
    }

    if recipient {
        select_scalar_field::<schema::__fields::Transaction::recipient, String>(&mut builder);
    }

    if fee {
        select_query_fragment::<schema::__fields::Transaction::fee, RawAmount>(&mut builder);
    }

    if quantity {
        select_query_fragment::<schema::__fields::Transaction::quantity, RawAmount>(&mut builder);
    }

    if metadata {
        select_query_fragment::<schema::__fields::Transaction::data, RawMetadata>(&mut builder);
    }

    if tags {
        select_query_fragment::<schema::__fields::Transaction::tags, Vec<RawTag>>(&mut builder);
    }

    if block {
        select_query_fragment::<schema::__fields::Transaction::block, Option<RawBlock>>(
            &mut builder,
        );
    }

    select_query_fragment::<schema::__fields::Transaction::bundledIn, Option<RawBundle>>(
        &mut builder,
    );
}

#[derive_where(Debug, Deserialize)]
struct RawTx<S: TxQueryFieldSelector> {
    id: cynic::Id,
    anchor: Option<String>,
    signature: Option<String>,
    recipient: Option<String>,
    owner: Option<RawOwner>,
    fee: Option<RawAmount>,
    quantity: Option<RawAmount>,
    data: Option<RawMetadata>,
    tags: Option<Vec<RawTag>>,
    block: Option<RawBlock>,
    #[serde(rename = "bundledIn")]
    bundled_in: Option<RawBundle>,
    #[serde(skip)]
    _phantom: PhantomData<S>,
}

#[derive(Debug, Clone)]
pub struct Tx {
    pub id: TxId,
    pub anchor: Option<TxAnchor>,
    pub signature: Option<tx::Signature<'static>>,
    pub recipient: Option<WalletAddress>,
    pub owner: Option<tx::Owner<'static>>,
    pub fee: Option<Reward>,
    pub quantity: Option<Money<Winston>>,
    pub data_size: Option<ByteSize>,
    pub content_type: Option<String>,
    pub tags: Vec<Tag<'static>>,
    pub block: Option<Block>,
}

#[derive(Debug, Clone)]
pub struct BundleItem {
    pub id: BundleItemId,
    pub anchor: Option<BundleAnchor>,
    pub data_size: Option<ByteSize>,
    pub content_type: Option<String>,
    pub tags: Vec<Tag<'static>>,
    pub block: Option<Block>,
    pub bundled_in: BundledInId,
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct BundledInId(RawItemId);

impl TryFrom<&RawBundle> for BundledInId {
    type Error = ConversionError;

    fn try_from(value: &RawBundle) -> Result<Self, Self::Error> {
        let bytes = Blob::try_from_base64(value.id.inner().as_bytes()).map_err(|e| match e {
            TryFromBase64Error::Base64DecodingError(base64) => ConversionError::Base64Error(base64),
            TryFromBase64Error::OtherError(_) => unreachable!(),
        })?;
        Ok(BundledInId(
            bytes
                .try_into()
                .map_err(|_| ConversionError::BundledInIdError)?,
        ))
    }
}

#[derive(Debug, Clone)]
pub enum TxQueryItem {
    Tx(Tx),
    BundleItem(BundleItem),
}

impl TxQueryItem {
    #[inline]
    pub fn id(&self) -> ItemId {
        match self {
            Self::Tx(tx) => ItemId::Tx(tx.id.clone()),
            Self::BundleItem(bundle_item) => ItemId::BundleItem(bundle_item.id.clone()),
        }
    }

    pub(crate) fn into_id(self) -> ItemId {
        match self {
            Self::Tx(tx) => ItemId::Tx(tx.id),
            Self::BundleItem(bundle_item) => ItemId::BundleItem(bundle_item.id),
        }
    }

    #[inline]
    pub fn data_size(&self) -> Option<ByteSize> {
        match self {
            Self::Tx(tx) => tx.data_size,
            Self::BundleItem(bundle_item) => bundle_item.data_size,
        }
    }

    #[inline]
    pub fn content_type(&self) -> Option<&String> {
        match self {
            Self::Tx(tx) => tx.content_type.as_ref(),
            Self::BundleItem(bundle_item) => bundle_item.content_type.as_ref(),
        }
    }

    #[inline]
    pub fn tags(&self) -> &Vec<Tag<'static>> {
        match self {
            Self::Tx(tx) => &tx.tags,
            Self::BundleItem(bundle_item) => &bundle_item.tags,
        }
    }

    #[inline]
    pub fn block(&self) -> Option<&Block> {
        match self {
            Self::Tx(tx) => tx.block.as_ref(),
            Self::BundleItem(bundle_item) => bundle_item.block.as_ref(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub id: BlockId,
    pub timestamp: DateTime<Utc>,
    pub height: BlockNumber,
    pub previous: BlockId,
}

impl TryFrom<RawBlock> for Block {
    type Error = ConversionError;

    fn try_from(value: RawBlock) -> Result<Self, Self::Error> {
        Ok(Self {
            id: BlockId::from_str(value.id.inner())?,
            timestamp: DateTime::from_timestamp(value.timestamp as i64, 0)
                .ok_or(InvalidTimestamp(value.timestamp as i64))?,
            height: BlockNumber::from_inner(value.height as u64),
            previous: BlockId::from_str(value.previous.inner())?,
        })
    }
}

impl<S: TxQueryFieldSelector> TryFrom<RawTx<S>> for TxQueryItem {
    type Error = ConversionError;

    fn try_from(value: RawTx<S>) -> Result<Self, Self::Error> {
        let data_size = value
            .data
            .as_ref()
            .filter(|v| !v.size.is_empty())
            .map(|v| {
                u64::from_str(v.size.as_str())
                    .map(|v| ByteSize::b(v))
                    .map_err(|e| ByteSizeError(e.to_string()))
            })
            .transpose()?
            .filter(|v| v.as_u64() != 0);

        let content_type = value
            .data
            .filter(|v| match v.content_type.as_ref() {
                Some(v) => !v.is_empty(),
                None => false,
            })
            .map(|v| v.content_type)
            .flatten();

        let tags = value
            .tags
            .unwrap_or(vec![])
            .into_iter()
            .filter(|t| !t.name.is_empty())
            .map(|t| Tag::from((t.name, t.value)))
            .collect();

        let block = value.block.map(|v| Block::try_from(v)).transpose()?;

        Ok(if let Some(bundled_in) = &value.bundled_in {
            // bundle item
            // there isn't enough information available to reliably detect the signature / owner type
            Self::BundleItem(BundleItem {
                id: BundleItemId::from_str(value.id.inner())?,
                anchor: value
                    .anchor
                    .filter(|v| !v.is_empty())
                    .map(|v| BundleAnchor::from_str(v.as_str()))
                    .transpose()?,
                data_size,
                content_type,
                tags,
                block,
                bundled_in: bundled_in.try_into()?,
            })
        } else {
            // plain tx
            let (signature, owner) = match (&value.owner, &value.signature) {
                (Some(owner), Some(signature)) => {
                    let raw_owner = owner.key.try_from_base64()?;
                    let raw_signature = signature.try_from_base64()?;
                    tx::Signature::from_raw_autodetect(raw_owner, raw_signature)
                        .map(|(s, o)| (Some(s), Some(o)))?
                }
                _ => (None, None),
            };

            Self::Tx(Tx {
                id: TxId::from_str(value.id.inner())?,
                anchor: value
                    .anchor
                    .filter(|v| !v.is_empty())
                    .map(|v| TxAnchor::from_str(v.as_str()))
                    .transpose()?,
                signature,
                recipient: value
                    .recipient
                    .filter(|v| !v.is_empty())
                    .map(|v| WalletAddress::from_str(v.as_str()))
                    .transpose()?,
                owner,
                fee: value
                    .fee
                    .filter(|v| !v.winston.is_empty())
                    .map(|v| Reward::from_str(v.winston.as_str()))
                    .transpose()?,
                quantity: value
                    .quantity
                    .filter(|v| !v.winston.is_empty())
                    .map(|v| Money::<Winston>::from_str(v.winston.as_str()))
                    .transpose()?
                    .filter(|v| !v.is_zero()),
                data_size,
                content_type,
                tags,
                block,
            })
        })
    }
}

impl<S: TxQueryFieldSelector> cynic::QueryFragment for RawTx<S> {
    type SchemaType = schema::Transaction;
    type VariablesFields = ();
    const TYPE: Option<&'static str> = Some("Transaction");

    fn query(builder: SelectionBuilder<'_, schema::Transaction, ()>) {
        S::query(builder)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::{FullTxResponse, TxQuery, TxQueryFilterCriteria, TxQueryItem};
    use ario_core::Gateway;
    use ario_core::network::Network;
    use futures_lite::StreamExt;
    use std::str::FromStr;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[ignore]
    #[tokio::test]
    async fn tx_query_live() -> anyhow::Result<()> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());

        let client = crate::Client::builder()
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .enable_netwatch(false)
            .build()
            .await?;

        let tx_query = TxQuery::builder()
            .filter_criteria(
                TxQueryFilterCriteria::builder()
                    //.ids([TxId::from_str(
                    //    "pN4sJr5CEuJzt2qPT9_hVlagEcHAStaTWo5HWcH1YWg",
                    //)?])
                    .build(),
            )
            .build();

        let mut stream = client.query_transactions_with_fields::<FullTxResponse>(tx_query);

        while let Some(item) = stream.try_next().await? {
            match item {
                TxQueryItem::Tx(tx) => {
                    println!("tx: {:?}", tx);
                }
                TxQueryItem::BundleItem(bundle_item) => {
                    println!("bundle_item: {:?}", bundle_item);
                }
            }
        }

        Ok(())
    }
}
