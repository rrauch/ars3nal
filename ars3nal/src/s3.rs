use anyhow::bail;
use arfs::ArFs;
use s3s::auth::Credentials;
use s3s::dto::{
    Bucket, BucketName, HeadBucketInput, HeadBucketOutput, ListBucketsInput, ListBucketsOutput,
    ListObjectsInput, ListObjectsOutput, ListObjectsV2Input, ListObjectsV2Output,
};
use s3s::{S3, S3Error, S3ErrorCode, S3Request, S3Response, S3Result, s3_error};
use std::collections::HashMap;
use std::time::SystemTime;

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
}

#[async_trait::async_trait]
impl S3 for ArS3 {
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
        req: S3Request<ListObjectsInput>,
    ) -> S3Result<S3Response<ListObjectsOutput>> {
        let v2_resp = self.list_objects_v2(req.map_input(Into::into)).await?;
        Err(s3_error!(NotImplemented))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        let input = req.input;

        let arfs = self.arfs(&input.bucket, req.credentials.as_ref())?;

        Err(s3_error!(NotImplemented))
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
}
