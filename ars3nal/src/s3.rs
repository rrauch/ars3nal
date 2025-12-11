use anyhow::bail;
use arfs::{ArFs, File, Inode, VfsPath};
use ario_core::base64::{FromBase64, ToBase64};
use ario_core::crypto::hash::Blake3;
use ct_codecs::{Base64, Decoder};
use futures_lite::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, StreamExt};
use itertools::{Either, Itertools};
use s3s::auth::Credentials;
use s3s::checksum::ChecksumHasher;
use s3s::crypto::{Checksum, Md5};
use s3s::dto::{
    Bucket, BucketName, ChecksumAlgorithm, ChecksumCRC32, ChecksumCRC32C, ChecksumCRC64NVME,
    ChecksumSHA1, ChecksumSHA256, CommonPrefix, ContentType, ETag, GetBucketLocationInput,
    GetBucketLocationOutput, GetObjectInput, GetObjectOutput, HeadBucketInput, HeadBucketOutput,
    HeadObjectInput, HeadObjectOutput, KeyCount, LastModified, ListBucketsInput, ListBucketsOutput,
    ListObjectsInput, ListObjectsOutput, ListObjectsV2Input, ListObjectsV2Output, MaxKeys,
    Metadata, Object, ObjectKey, ObjectStorageClass, Owner, PutObjectInput, PutObjectOutput, Size,
    StreamingBlob,
};
use s3s::{S3, S3Error, S3ErrorCode, S3Request, S3Response, S3Result, TrailingHeaders, s3_error};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::str::FromStr;
use std::time::SystemTime;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::io::ReaderStream;

const MAX_UPLOAD_SIZE: u64 = 1024 * 1024 * 1024 * 5; // 5GiB

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

    fn to_metadata(&self, file: &File) -> Option<Metadata> {
        let metadata = file
            .extra_attributes()
            .into_iter()
            .filter_map(|(k, v)| {
                // filter out non-string values
                if let Ok(v) = String::from_utf8(v.to_vec()) {
                    Some((k.to_string(), v))
                } else {
                    None
                }
            })
            .collect::<Metadata>();
        if metadata.is_empty() {
            None
        } else {
            Some(metadata)
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

    async fn put_file_object(
        &self,
        req: S3Request<PutObjectInput>,
        arfs: &ArFs,
        expected_content_len: Option<u64>,
    ) -> S3Result<PutObjectOutput> {
        let mut input = req.input;
        let (mut checksum_hasher, mut checksum_values) = checksum_hasher(&mut input)?;
        let Some(mut body) = input.body else {
            return Err(s3_error!(IncompleteBody));
        };

        let path = VfsPath::try_from(format!("/{}", input.key.as_str()).as_str())
            .map_err(|e| S3Error::internal_error(e))?;

        let (dir, name) = match path.split() {
            (Some(dir), Some(name)) => (dir, name),
            _ => Err(S3Error::new(S3ErrorCode::InvalidArgument))?,
        };

        let content_type = input
            .content_type
            .as_ref()
            .map(|c| arfs::ContentType::from_str(c.essence_str()))
            .transpose()
            .map_err(|e| S3Error::internal_error(e))?;

        let mut fh = arfs
            .vfs()
            .create_file(&dir, &name, None, content_type, true, true)
            .await
            .map_err(|e| S3Error::internal_error(e))?;

        let mut actual_content_len = 0u64;
        let mut md5_hasher = Md5::new();

        while let Some(bytes) = body
            .try_next()
            .await
            .map_err(|e| S3Error::with_source(S3ErrorCode::InternalError, e))?
        {
            md5_hasher.update(bytes.as_ref());
            checksum_hasher.update(bytes.as_ref());
            fh.write_all(bytes.as_ref())
                .await
                .map_err(|e| S3Error::internal_error(e))?;
            actual_content_len += bytes.len() as u64;

            if actual_content_len > MAX_UPLOAD_SIZE {
                return Err(s3_error!(EntityTooLarge));
            }
        }

        if let Some(len) = expected_content_len {
            if actual_content_len != len {
                return Err(s3_error!(BadDigest, "content_length mismatch"));
            }
        }

        let md5 = md5_hasher.finalize();
        let checksum = checksum_hasher.finalize();

        if let Some(content_md5) = input.content_md5 {
            let expected = Base64::decode_to_vec(&content_md5, None)
                .map_err(|e| S3Error::internal_error(e))?;

            if md5.as_slice() != expected.as_slice() {
                return Err(s3_error!(BadDigest, "content_md5 mismatch"));
            }
        }

        if let Some(trailers) = &req.trailing_headers {
            update_checksum_values(trailers, &mut checksum_values)?;
        }

        checksum_values.compare(&checksum)?;

        let file = fh
            .finalize()
            .await
            .map_err(|e| S3Error::internal_error(e))?;

        let object = self.as_object(arfs, &file);

        Ok(PutObjectOutput {
            e_tag: object.e_tag,
            size: object.size,
            ..Default::default()
        })
    }
}

fn fmt_content_range(start: u64, end_inclusive: u64, size: u64) -> String {
    format!("bytes {start}-{end_inclusive}/{size}")
}

fn check_storage_class(input: &PutObjectInput) -> Result<(), S3Error> {
    if let Some(ref storage_class) = input.storage_class {
        let is_valid = ["STANDARD", "REDUCED_REDUNDANCY"].contains(&storage_class.as_str());
        if !is_valid {
            return Err(s3_error!(InvalidStorageClass));
        }
    }
    Ok(())
}

#[derive(Default)]
struct Checksums {
    crc32: Option<ChecksumCRC32>,
    crc32c: Option<ChecksumCRC32C>,
    crc64_nvme: Option<ChecksumCRC64NVME>,
    sha1: Option<ChecksumSHA1>,
    sha256: Option<ChecksumSHA256>,
}

impl Checksums {
    fn compare(&self, calculated: &s3s::dto::Checksum) -> S3Result<()> {
        if self.crc32.is_some() && calculated.checksum_crc32 != self.crc32 {
            return Err(s3_error!(BadDigest, "checksum_crc32 mismatch",));
        }
        if self.crc32c.is_some() && calculated.checksum_crc32c != self.crc32c {
            return Err(s3_error!(BadDigest, "checksum_crc32c mismatch"));
        }
        if self.sha1.is_some() && calculated.checksum_sha1 != self.sha1 {
            return Err(s3_error!(BadDigest, "checksum_sha1 mismatch"));
        }
        if self.sha256.is_some() && calculated.checksum_sha256 != self.sha256 {
            return Err(s3_error!(BadDigest, "checksum_sha256 mismatch"));
        }
        if self.crc64_nvme.is_some() && calculated.checksum_crc64nvme != self.crc64_nvme {
            return Err(s3_error!(BadDigest, "checksum_crc64nvme mismatch"));
        }
        Ok(())
    }
}

fn checksum_hasher(input: &mut PutObjectInput) -> Result<(ChecksumHasher, Checksums), S3Error> {
    let mut checksum_hasher: ChecksumHasher = Default::default();
    let mut checksum_values = Checksums::default();

    if let Some(checksum) = input.checksum_crc32.take() {
        checksum_values.crc32 = Some(checksum);
        checksum_hasher.crc32 = Some(Default::default());
    }
    if let Some(checksum) = input.checksum_crc32c.take() {
        checksum_values.crc32c = Some(checksum);
        checksum_hasher.crc32c = Some(Default::default());
    }
    if let Some(checksum) = input.checksum_sha1.take() {
        checksum_values.sha1 = Some(checksum);
        checksum_hasher.sha1 = Some(Default::default());
    }
    if let Some(checksum) = input.checksum_sha256.take() {
        checksum_values.sha256 = Some(checksum);
        checksum_hasher.sha256 = Some(Default::default());
    }
    if let Some(checksum) = input.checksum_crc64nvme.take() {
        checksum_values.crc64_nvme = Some(checksum);
        checksum_hasher.crc64nvme = Some(Default::default());
    }
    if let Some(alg) = &input.checksum_algorithm {
        match alg.as_str() {
            ChecksumAlgorithm::CRC32 => checksum_hasher.crc32 = Some(Default::default()),
            ChecksumAlgorithm::CRC32C => checksum_hasher.crc32c = Some(Default::default()),
            ChecksumAlgorithm::SHA1 => checksum_hasher.sha1 = Some(Default::default()),
            ChecksumAlgorithm::SHA256 => checksum_hasher.sha256 = Some(Default::default()),
            ChecksumAlgorithm::CRC64NVME => checksum_hasher.crc64nvme = Some(Default::default()),
            _ => return Err(s3_error!(NotImplemented, "Unsupported checksum algorithm")),
        }
    }
    Ok((checksum_hasher, checksum_values))
}

fn update_checksum_values(
    trailers: &TrailingHeaders,
    checksum_values: &mut Checksums,
) -> S3Result<()> {
    if let Some(trailers) = trailers.take() {
        if let Some(crc32) = trailers.get("x-amz-checksum-crc32") {
            checksum_values.crc32 = Some(
                crc32
                    .to_str()
                    .map_err(|_| s3_error!(InvalidArgument))?
                    .to_owned(),
            );
        }
        if let Some(crc32c) = trailers.get("x-amz-checksum-crc32c") {
            checksum_values.crc32c = Some(
                crc32c
                    .to_str()
                    .map_err(|_| s3_error!(InvalidArgument))?
                    .to_owned(),
            );
        }
        if let Some(sha1) = trailers.get("x-amz-checksum-sha1") {
            checksum_values.sha1 = Some(
                sha1.to_str()
                    .map_err(|_| s3_error!(InvalidArgument))?
                    .to_owned(),
            );
        }
        if let Some(sha256) = trailers.get("x-amz-checksum-sha256") {
            checksum_values.sha256 = Some(
                sha256
                    .to_str()
                    .map_err(|_| s3_error!(InvalidArgument))?
                    .to_owned(),
            );
        }
        if let Some(crc64nvme) = trailers.get("x-amz-checksum-crc64nvme") {
            checksum_values.crc64_nvme = Some(
                crc64nvme
                    .to_str()
                    .map_err(|_| s3_error!(InvalidArgument))?
                    .to_owned(),
            );
        }
    }

    Ok(())
}

#[async_trait::async_trait]
impl S3 for ArS3 {
    async fn get_bucket_location(
        &self,
        req: S3Request<GetBucketLocationInput>,
    ) -> S3Result<S3Response<GetBucketLocationOutput>> {
        let input = req.input;
        let _ = self.arfs(&input.bucket, req.credentials.as_ref())?;
        Ok(S3Response::new(GetBucketLocationOutput {
            location_constraint: None,
        }))
    }

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

        let metadata = self.to_metadata(&file);

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
            metadata,
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

        let metadata = self.to_metadata(&file);

        let output = HeadObjectOutput {
            accept_ranges: Some("bytes".to_string()),
            content_length: object.size,
            content_type: Some(
                ContentType::from_str(file.content_type().as_ref())
                    .map_err(|e| S3Error::internal_error(e))?,
            ),
            e_tag: object.e_tag,
            last_modified: object.last_modified,
            metadata,
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

    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        let input = &req.input;
        check_storage_class(&input)?;
        let arfs = self.arfs(&input.bucket, req.credentials.as_ref())?;
        let content_length = input.content_length.map(|cl| cl as u64);
        if input.key.ends_with('/') {
            // directory
            if let Some(len) = content_length {
                if len > 0 {
                    return Err(s3_error!(
                        UnexpectedContent,
                        "Unexpected content_length when creating a directory object."
                    ));
                }
            }
            if input.body.is_some() {
                return Err(s3_error!(
                    UnexpectedContent,
                    "Unexpected request body when creating a directory object."
                ));
            }
            todo!()
        } else {
            // file
            Ok(S3Response::new(
                self.put_file_object(req, arfs, content_length).await?,
            ))
        }
    }
}
