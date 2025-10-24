use anyhow::bail;
use arfs::{ArFs, File, Inode, VfsPath};
use ario_core::base64::{FromBase64, ToBase64};
use ario_core::crypto::hash::Blake3;
use futures_lite::{AsyncReadExt, AsyncSeekExt};
use itertools::{Either, Itertools};
use s3s::auth::Credentials;
use s3s::dto::{
    Bucket, BucketName, CommonPrefix, ContentType, ETag, GetObjectInput, GetObjectOutput,
    HeadBucketInput, HeadBucketOutput, HeadObjectInput, HeadObjectOutput, KeyCount, LastModified,
    ListBucketsInput, ListBucketsOutput, ListObjectsInput, ListObjectsOutput, ListObjectsV2Input,
    ListObjectsV2Output, MaxKeys, Object, ObjectKey, ObjectStorageClass, Owner, Size,
    StreamingBlob,
};
use s3s::{S3, S3Error, S3ErrorCode, S3Request, S3Response, S3Result, s3_error};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::str::FromStr;
use std::time::SystemTime;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::io::ReaderStream;

#[repr(transparent)]
pub struct ArS3 {
    buckets: HashMap<BucketName, ArFs>,
}

impl ArS3 {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::default(),
        }
    }

    pub fn insert(&mut self, bucket_name: impl AsRef<str>, arfs: ArFs) -> anyhow::Result<()> {
        let bucket_name = bucket_name.as_ref().to_string();
        if self.buckets.contains_key(bucket_name.as_str()) {
            bail!("bucket {} already in use", bucket_name);
        }
        self.buckets.insert(bucket_name, arfs);
        Ok(())
    }

    fn arfs(
        &self,
        bucket_name: &BucketName,
        _credentials: Option<&Credentials>,
    ) -> Result<&ArFs, S3Error> {
        self.buckets.get(bucket_name).ok_or(s3_error!(NoSuchBucket))
    }

    fn as_object(&self, arfs: &ArFs, file: &File) -> Object {
        let key_str = file.path().as_ref();
        let key = key_str.strip_prefix("/").unwrap_or(key_str);
        let owner = file.pinned_owner().unwrap_or_else(|| arfs.owner());
        let etag = if let Some(location) = file.data_location() {
            let mut etag_hasher = Blake3::new();
            etag_hasher.update("s3_object_etag\n".as_bytes());
            etag_hasher.update(location.to_string().as_bytes());
            etag_hasher.update(file.size().as_u64().to_be_bytes().as_slice());
            etag_hasher.update("\ns3_object_etag".as_bytes());
            Some(ETag::Strong(etag_hasher.finalize().to_hex().to_string()))
        } else {
            None
        };

        Object {
            checksum_algorithm: None,
            checksum_type: None,
            e_tag: etag,
            key: Some(key.to_string()),
            last_modified: Some(SystemTime::from(file.last_modified().clone()).into()),
            owner: Some(Owner {
                display_name: None,
                id: Some(owner.to_string()),
            }),
            restore_status: None,
            size: Some(file.size().as_u64() as Size),
            storage_class: Some(ObjectStorageClass::from_static(
                ObjectStorageClass::STANDARD,
            )),
        }
    }

    async fn get_object(
        &self,
        arfs: &ArFs,
        key: &ObjectKey,
        known_etag: Option<&ETag>,
        known_last_modified: Option<&LastModified>,
    ) -> Result<(Object, File), S3Error> {
        let path = VfsPath::try_from(format!("/{}", key.as_str()).as_str())
            .map_err(|e| S3Error::internal_error(e))?;

        let inode = arfs
            .vfs()
            .inode_by_path(&path)
            .await
            .map_err(|e| S3Error::internal_error(e))?
            .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchKey))?;

        let file = match inode {
            Inode::File(file) => file,
            _ => Err(S3Error::new(S3ErrorCode::NoSuchKey))?,
        };

        let object = self.as_object(arfs, &file);

        match (object.e_tag.as_ref(), known_etag) {
            (Some(e1), Some(e2)) if e1 == e2 => {
                // not modified
                return Err(S3Error::new(S3ErrorCode::NotModified));
            }
            _ => {}
        }

        match (object.last_modified.as_ref(), known_last_modified) {
            (Some(l1), Some(l2)) if l1 == l2 => {
                // not modified
                return Err(S3Error::new(S3ErrorCode::NotModified));
            }
            _ => {}
        }

        Ok((object, file))
    }
}

fn fmt_content_range(start: u64, end_inclusive: u64, size: u64) -> String {
    format!("bytes {start}-{end_inclusive}/{size}")
}

#[async_trait::async_trait]
impl S3 for ArS3 {
    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        let input = req.input;

        let arfs = self.arfs(&input.bucket, req.credentials.as_ref())?;

        let (object, file) = self
            .get_object(
                arfs,
                &input.key,
                input
                    .if_none_match
                    .as_ref()
                    .map(|s| ETag::parse_http_header(s.as_bytes()).ok())
                    .flatten()
                    .as_ref(),
                input.if_modified_since.as_ref(),
            )
            .await?;

        let file_len = file.size().as_u64();

        let (seek_pos, content_length, content_range) = match input.range {
            None => (0, file_len, None),
            Some(range) => {
                let file_range = range.check(file_len)?;
                let content_length = file_range.end - file_range.start;
                let content_range =
                    fmt_content_range(file_range.start, file_range.end - 1, file_len);
                (file_range.start, content_length, Some(content_range))
            }
        };

        let mut reader = arfs.vfs().read_file(&file).await.map_err(|e| {
            tracing::error!(error = %e);
            S3Error::internal_error(e)
        })?;

        reader
            .seek(SeekFrom::Start(seek_pos))
            .await
            .map_err(|e| S3Error::internal_error(e))?;

        let reader = reader.take(content_length);

        let body = ReaderStream::with_capacity(reader.compat(), 32 * 1024);

        let output = GetObjectOutput {
            accept_ranges: Some("bytes".to_string()),
            body: Some(StreamingBlob::wrap(body)),
            content_length: Some(content_length as i64),
            content_range,
            content_type: Some(
                ContentType::from_str(file.content_type().as_ref())
                    .map_err(|e| S3Error::internal_error(e))?,
            ),
            e_tag: object.e_tag,
            last_modified: object.last_modified,
            ..Default::default()
        };

        Ok(S3Response::new(output))
    }

    async fn list_buckets(
        &self,
        _req: S3Request<ListBucketsInput>,
    ) -> S3Result<S3Response<ListBucketsOutput>> {
        let mut output = ListBucketsOutput::default();

        let buckets: Vec<_> = self
            .buckets
            .iter()
            .map(|(name, arfs)| {
                let mut bucket = Bucket::default();
                bucket.name = Some(name.clone());
                bucket.creation_date = Some(SystemTime::from(arfs.created_at().clone()).into());
                bucket
            })
            .collect();

        output.buckets = Some(buckets);
        Ok(S3Response::new(output))
    }

    async fn list_objects(
        &self,
        mut req: S3Request<ListObjectsInput>,
    ) -> S3Result<S3Response<ListObjectsOutput>> {
        let marker = req.input.marker.take();
        let mut v2_req: S3Request<ListObjectsV2Input> = req.map_input(Into::into);
        if let Some(marker) = marker {
            v2_req.input.continuation_token = Some(marker);
        }
        let v2_resp = self.list_objects_v2(v2_req).await?;
        Ok(v2_resp.map_output(|v2| ListObjectsOutput {
            contents: v2.contents,
            common_prefixes: v2.common_prefixes,
            delimiter: v2.delimiter,
            encoding_type: v2.encoding_type,
            name: v2.name,
            prefix: v2.prefix,
            max_keys: v2.max_keys,
            is_truncated: v2.is_truncated,
            marker: v2.continuation_token,
            next_marker: v2.next_continuation_token,
            ..Default::default()
        }))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        let input = req.input;

        let arfs = self.arfs(&input.bucket, req.credentials.as_ref())?;

        let max_keys = input.max_keys.as_ref().map(|m| *m as usize).unwrap_or(1000);
        let start_after = match input.continuation_token.as_ref() {
            Some(token) => Some(
                String::from_utf8(
                    token
                        .try_from_base64()
                        .map_err(|e| S3Error::internal_error(e))?
                        .to_vec(),
                )
                .map_err(|e| S3Error::internal_error(e))?,
            ),
            None => input.start_after.as_ref().map(|s| s.clone()),
        };

        let (inodes, has_more) = arfs
            .vfs()
            .find(
                input.prefix.as_ref().map(|p| p.as_str()),
                input.delimiter.as_ref().map(|d| d.as_str()),
                start_after.as_ref().map(|s| s.as_str()),
                max_keys,
            )
            .await
            .map_err(|e| S3Error::internal_error(e))?;

        let (contents, common_prefixes): (Vec<_>, Vec<_>) =
            inodes.into_iter().partition_map(|inode| match inode {
                Inode::File(file) => Either::Left(self.as_object(&arfs, &file)),
                other => Either::Right({
                    let str = other.path().as_ref();
                    CommonPrefix {
                        prefix: Some(format!("{}/", str.strip_prefix("/").unwrap_or(str))),
                    }
                }),
            });

        let next_continuation_token = if has_more {
            contents
                .last()
                .map(|o| o.key.as_ref().map(|k| k.as_str().as_bytes().to_base64()))
                .flatten()
        } else {
            None
        };

        let common_prefixes = if common_prefixes.is_empty() {
            None
        } else {
            Some(common_prefixes)
        };

        let key_count = contents.len();

        let contents = if contents.is_empty() {
            None
        } else {
            Some(contents)
        };

        let output = ListObjectsV2Output {
            common_prefixes,
            contents,
            is_truncated: Some(has_more),
            key_count: Some(key_count as KeyCount),
            max_keys: Some(max_keys as MaxKeys),
            prefix: input.prefix,
            delimiter: input.delimiter,
            start_after: input.start_after,
            name: Some(input.bucket),
            continuation_token: input.continuation_token,
            next_continuation_token,
            ..Default::default()
        };

        Ok(S3Response::new(output))
    }

    async fn head_bucket(
        &self,
        req: S3Request<HeadBucketInput>,
    ) -> S3Result<S3Response<HeadBucketOutput>> {
        if !self.buckets.contains_key(&req.input.bucket) {
            return Err(S3Error::new(S3ErrorCode::NoSuchBucket));
        }
        Ok(S3Response::new(HeadBucketOutput::default()))
    }

    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        let input = req.input;

        let arfs = self.arfs(&input.bucket, req.credentials.as_ref())?;

        let (object, file) = self
            .get_object(
                arfs,
                &input.key,
                input
                    .if_none_match
                    .as_ref()
                    .map(|s| ETag::parse_http_header(s.as_bytes()).ok())
                    .flatten()
                    .as_ref(),
                input.if_modified_since.as_ref(),
            )
            .await?;

        let output = HeadObjectOutput {
            accept_ranges: Some("bytes".to_string()),
            content_length: object.size,
            content_type: Some(
                ContentType::from_str(file.content_type().as_ref())
                    .map_err(|e| S3Error::internal_error(e))?,
            ),
            e_tag: object.e_tag,
            last_modified: object.last_modified,
            ..Default::default()
        };

        Ok(S3Response::new(output))
    }
}
