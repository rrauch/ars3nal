use anyhow::{anyhow, bail};
use indexmap::IndexMap;
use itertools::Itertools;
use s3s::access::{S3Access, S3AccessContext};
use s3s::auth::{Credentials, S3Auth, SecretKey};
use s3s::path::S3Path;
use s3s::{S3Result, s3_error};
use s3s_policy::model::{
    ActionRule, Effect, Policy as S3Policy, Principal as S3Principal, PrincipalRule, ResourceRule,
};
use s3s_policy::pattern::PatternSet;
use std::collections::HashMap;
use std::iter;
use std::str::FromStr;
use std::string::ToString;
use std::sync::{Arc, LazyLock, Mutex};

static DEFAULT_POLICY: LazyLock<Policy> = LazyLock::new(|| {
    from_json(
        r#"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowBasicReading",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:GetObjectAttributes"
      ],
      "Resource": "*"
    }
  ]
}
"#,
    )
    .expect("default policy to be valid json")
});

static WILDCARD: LazyLock<[String; 1]> = LazyLock::new(|| [String::from_str("*").unwrap()]);
const DEFAULT_PRINCIPAL: S3Principal = S3Principal::Wildcard;

#[derive(Clone)]
struct Policy {
    statements: Vec<Statement>,
}

#[derive(Clone)]
struct Statement {
    effect: Effect,
    actions: Rule,
    principals: Rule,
    resources: Vec<(Rule, Rule, bool)>,
}

impl Statement {
    fn apply(&self, ctx: &Context<'_>) -> ApplicationResult {
        if !self.actions.matches(ctx.policy_action()) {
            return ApplicationResult::NotApplicable;
        }

        let principal = ctx.principal.map(|p| p.as_ref()).unwrap_or("");
        if !self.principals.matches(principal) {
            return ApplicationResult::NotApplicable;
        }

        let (bucket, key) = match ctx.s3_path {
            S3Path::Root => ("", ""),
            S3Path::Bucket { bucket } => (bucket.as_ref(), ""),
            S3Path::Object { bucket, key } => (bucket.as_ref(), key.as_ref()),
        };

        let mut resource_match = false;
        for (bucket_rule, key_rule, is_not) in &self.resources {
            let matches = bucket_rule.matches(bucket) && key_rule.matches(key);
            let matches = if *is_not { !matches } else { matches };
            if matches {
                resource_match = true;
                break;
            }
        }

        if !resource_match {
            return ApplicationResult::NotApplicable;
        }

        match self.effect {
            Effect::Allow => ApplicationResult::Allow,
            Effect::Deny => ApplicationResult::Deny,
        }
    }
}

enum ApplicationResult {
    Allow,
    Deny,
    NotApplicable,
}

struct Context<'a> {
    s3_path: &'a S3Path,
    s3_op: &'a str,
    principal: Option<&'a Principal>,
}

impl<'a> Context<'a> {
    /// Maps `s3_op` to policy action (where applicable)
    fn policy_action(&self) -> &'a str {
        match self.s3_op {
            // Service Level
            "ListBuckets" => "ListAllMyBuckets",

            // Bucket Listing / Existence
            "ListObjects" | "ListObjectsV2" | "HeadBucket" => "ListBucket",
            "ListObjectVersions" => "ListBucketVersions",
            "ListMultipartUploads" => "ListBucketMultipartUploads",

            // Object Read
            "HeadObject" | "SelectObjectContent" => "GetObject",
            "ListParts" => "ListMultipartUploadParts",

            // Object Write (Multipart & Copy map to PutObject on destination)
            "CopyObject"
            | "CreateMultipartUpload"
            | "UploadPart"
            | "UploadPartCopy"
            | "CompleteMultipartUpload" => "PutObject",

            // Batch Delete
            "DeleteObjects" => "DeleteObject",

            // Lifecycle
            "GetBucketLifecycleConfiguration" => "GetLifecycleConfiguration",
            "PutBucketLifecycleConfiguration" | "DeleteBucketLifecycle" => {
                "PutLifecycleConfiguration"
            }

            // Replication
            "GetBucketReplication" => "GetReplicationConfiguration",
            "PutBucketReplication" | "DeleteBucketReplication" => "PutReplicationConfiguration",

            // Encryption
            "GetBucketEncryption" => "GetEncryptionConfiguration",
            "PutBucketEncryption" | "DeleteBucketEncryption" => "PutEncryptionConfiguration",

            // Accelerate
            "GetBucketAccelerateConfiguration" => "GetAccelerateConfiguration",
            "PutBucketAccelerateConfiguration" => "PutAccelerateConfiguration",

            // Analytics
            "GetBucketAnalyticsConfiguration" => "GetAnalyticsConfiguration",
            "PutBucketAnalyticsConfiguration" | "DeleteBucketAnalyticsConfiguration" => {
                "PutAnalyticsConfiguration"
            }

            // Inventory
            "GetBucketInventoryConfiguration" => "GetInventoryConfiguration",
            "PutBucketInventoryConfiguration" | "DeleteBucketInventoryConfiguration" => {
                "PutInventoryConfiguration"
            }

            // Metrics
            "GetBucketMetricsConfiguration" => "GetMetricsConfiguration",
            "PutBucketMetricsConfiguration" | "DeleteBucketMetricsConfiguration" => {
                "PutMetricsConfiguration"
            }

            // Intelligent Tiering
            "GetBucketIntelligentTieringConfiguration" => "GetIntelligentTieringConfiguration",
            "PutBucketIntelligentTieringConfiguration"
            | "DeleteBucketIntelligentTieringConfiguration" => "PutIntelligentTieringConfiguration",

            // --- Other Mismatches ---

            // CORS (Action uses CAPS, Delete maps to Put)
            "GetBucketCors" => "GetBucketCORS",
            "PutBucketCors" | "DeleteBucketCors" => "PutBucketCORS",

            // Tagging (Delete maps to Put)
            "DeleteBucketTagging" => "PutBucketTagging",

            // Public Access Block (API is generic, Action is specific to Bucket)
            "GetPublicAccessBlock" => "GetBucketPublicAccessBlock",
            "PutPublicAccessBlock" | "DeletePublicAccessBlock" => "PutBucketPublicAccessBlock",

            // Object Lock (Action adds 'Bucket' prefix)
            "GetObjectLockConfiguration" => "GetBucketObjectLockConfiguration",
            "PutObjectLockConfiguration" => "PutBucketObjectLockConfiguration",

            // Default: Return the input (e.g., GetObject, PutObject, CreateBucket, DeleteBucket, PutBucketPolicy)
            other => other,
        }
    }
}

impl<'a> From<(&'a S3AccessContext<'a>, Option<&'a Principal>)> for Context<'a> {
    fn from((ctx, principal): (&'a S3AccessContext<'a>, Option<&'a Principal>)) -> Self {
        Self {
            s3_op: ctx.s3_op().name(),
            s3_path: ctx.s3_path(),
            principal,
        }
    }
}

#[derive(Clone)]
struct Rule {
    pattern: Arc<PatternSet>,
    is_not: bool,
}

impl Rule {
    fn matches(&self, input: impl AsRef<str>) -> bool {
        let result = self.pattern.is_match(input.as_ref());
        if self.is_not { !result } else { result }
    }
}

fn parse_action_rule(rule: &ActionRule) -> anyhow::Result<Rule> {
    let (actions, is_not) = match rule {
        ActionRule::Action(a) => (a, false),
        ActionRule::NotAction(a) => (a, true),
    };
    Ok(Rule {
        pattern: Arc::new(PatternSet::new(
            actions
                .as_slice()
                .unwrap_or(WILDCARD.as_slice())
                .into_iter()
                .map(|s| s.as_str())
                .map(|s| {
                    if s == "*" || s.starts_with("s3:") {
                        Ok(s.strip_prefix("s3:").unwrap_or(s))
                    } else {
                        Err(anyhow!(
                            "invalid action: only 's3:' types and '*' are supported"
                        ))
                    }
                })
                .collect::<anyhow::Result<Vec<_>>>()?,
        )?),
        is_not,
    })
}

fn parse_principal_rule(rule: Option<&PrincipalRule>) -> anyhow::Result<Rule> {
    let (principals, is_not) = match rule {
        Some(PrincipalRule::Principal(p)) => (p, false),
        Some(PrincipalRule::NotPrincipal(p)) => (p, true),
        None => (&DEFAULT_PRINCIPAL, false),
    };
    Ok(Rule {
        pattern: Arc::new(PatternSet::new(match principals {
            S3Principal::Wildcard => vec!["*"],
            S3Principal::Map(map) => {
                for key in map.keys() {
                    if key.as_str() != "AWS" {
                        bail!("invalid principal: only 'AWS' principals are supported");
                    }
                }
                map.values()
                    .into_iter()
                    .map(|v| v.as_slice())
                    .flatten()
                    .map(|s| s.as_str())
                    .collect_vec()
            }
        })?),
        is_not,
    })
}

fn parse_resource_rule(rule: &ResourceRule) -> anyhow::Result<Vec<(Rule, Rule, bool)>> {
    let (resources, is_not) = match rule {
        ResourceRule::Resource(r) => (r, false),
        ResourceRule::NotResource(r) => (r, true),
    };
    Ok(resources
        .as_slice()
        .unwrap_or(WILDCARD.as_slice())
        .into_iter()
        .map(|s| s.as_str())
        .map(|s| match s {
            "*" => Ok(("*", "*")),
            s if s.starts_with("arn:aws:s3:::") => {
                let s = s.strip_prefix("arn:aws:s3:::").unwrap();
                if let Some((bucket, path)) = s.split_once('/') {
                    Ok((bucket, path))
                } else {
                    Ok((s, "*"))
                }
            }
            _ => Err(anyhow!(
                "invalid resource: only 'arn:aws:s3:::' resources and '*' are supported"
            )),
        })
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .fold(IndexMap::new(), |mut acc, (k, v)| {
            let vec = acc.entry(k).or_insert_with(Vec::new);
            if !vec.contains(&v) {
                vec.push(v);
            }
            acc
        })
        .into_iter()
        .map(|(k, v)| -> anyhow::Result<_> {
            Ok((
                Rule {
                    pattern: Arc::new(PatternSet::new(iter::once(k))?),
                    is_not: false,
                },
                Rule {
                    pattern: Arc::new(PatternSet::new(v)?),
                    is_not: false,
                },
                is_not,
            ))
        })
        .collect::<anyhow::Result<Vec<(_, _, bool)>>>()?)
}

fn from_json<S: AsRef<str>>(json: S) -> anyhow::Result<Policy> {
    let policy: S3Policy = serde_json::from_str(json.as_ref())?;
    let mut statements = vec![];
    for statement in policy.statement.as_slice() {
        if statement.condition.is_some() {
            bail!("Conditions in policy-statements are currently unsupported");
        }

        statements.push(Statement {
            actions: parse_action_rule(&statement.action)?,
            principals: parse_principal_rule(statement.principal.as_ref())?,
            resources: parse_resource_rule(&statement.resource)?,
            effect: statement.effect.clone(),
        })
    }

    Ok(Policy { statements })
}

#[repr(transparent)]
struct Principal(String);

impl AsRef<str> for Principal {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

struct User {
    access_key: String,
    secret_key: SecretKey,
    principal: Principal,
}

#[derive(Clone)]
pub struct Auth {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    users: HashMap<String, User>,
    default_policy: Policy,
    bucket_policies: HashMap<String, Policy>,
}

impl Inner {
    fn user_by_access_key(&self, access_key: &str) -> S3Result<&User> {
        match self.users.get(access_key) {
            None => Err(s3_error!(NotSignedUp, "Access Key invalid or unknown")),
            Some(user) => Ok(user),
        }
    }
}

impl Auth {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                users: HashMap::default(),
                default_policy: DEFAULT_POLICY.clone(),
                bucket_policies: HashMap::default(),
            })),
        }
    }

    pub fn set_default_policy(&self, new_policy_json: impl AsRef<str>) -> anyhow::Result<()> {
        let policy = from_json(new_policy_json)?;
        let mut lock = self.inner.lock().expect("lock to not be poisoned");
        lock.default_policy = policy;
        Ok(())
    }

    pub fn insert_bucket_policy(
        &self,
        bucket_name: impl AsRef<str>,
        new_policy_json: impl AsRef<str>,
    ) -> anyhow::Result<()> {
        let policy = from_json(new_policy_json)?;
        let mut lock = self.inner.lock().expect("lock to not be poisoned");
        lock.bucket_policies
            .insert(bucket_name.as_ref().to_string(), policy);
        Ok(())
    }

    pub fn insert_user(
        &self,
        access_key: impl ToString,
        secret_key: impl Into<SecretKey>,
        principal: impl ToString,
    ) {
        let access_key = access_key.to_string();
        let user = User {
            access_key: access_key.clone(),
            secret_key: secret_key.into(),
            principal: Principal(principal.to_string()),
        };
        let mut lock = self.inner.lock().expect("lock to not be poisoned");
        lock.users.insert(access_key, user);
    }
}

#[async_trait::async_trait]
impl S3Auth for Auth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        let lock = self.inner.lock().expect("lock to not be poisoned");
        lock.user_by_access_key(access_key)
            .map(|user| user.secret_key.clone())
    }
}

#[async_trait::async_trait]
impl S3Access for Auth {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        let lock = self.inner.lock().expect("lock to not be poisoned");
        let principal = if let Some(credentials) = cx.credentials() {
            Some(
                &lock
                    .user_by_access_key(credentials.access_key.as_str())?
                    .principal,
            )
        } else {
            None
        };
        let policy = lock
            .bucket_policies
            .get(cx.s3_path().get_bucket_name().unwrap_or(""))
            .unwrap_or(&lock.default_policy);
        let cx: &S3AccessContext<'_> = cx;
        let ctx = (cx, principal).into();
        check_policy(policy, &ctx)
    }
}

/// Evaluates policy statements using AWS-compatible logic: any explicit Deny wins immediately,
/// otherwise requires at least one explicit Allow (implicit deny if none found).
fn check_policy(policy: &Policy, ctx: &Context<'_>) -> S3Result<()> {
    let mut has_allow = false;

    for statement in &policy.statements {
        match statement.apply(ctx) {
            ApplicationResult::Deny => {
                return Err(s3_error!(AccessDenied, "Access Denied by Policy"));
            }
            ApplicationResult::Allow => {
                has_allow = true;
            }
            ApplicationResult::NotApplicable => continue,
        }
    }

    if has_allow {
        Ok(())
    } else {
        Err(s3_error!(AccessDenied, "Access Denied"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3s_policy::model::{
        ActionRule, OneOrMore, Principal as S3Principal, PrincipalRule, ResourceRule,
        WildcardOneOrMore,
    };
    use std::ops::Deref;

    fn one_or_more(input: Vec<&str>) -> OneOrMore<String> {
        match input.len() {
            1 => OneOrMore::One(input.get(0).unwrap().to_string()),
            _ => OneOrMore::More(input.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn wc_one_more(input: Vec<&str>) -> WildcardOneOrMore<String> {
        match input.len() {
            0 => WildcardOneOrMore::Wildcard,
            1 => WildcardOneOrMore::One(input.get(0).unwrap().to_string()),
            _ => WildcardOneOrMore::More(input.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn action(actions: Vec<&str>) -> ActionRule {
        ActionRule::Action(wc_one_more(actions))
    }

    fn not_action(actions: Vec<&str>) -> ActionRule {
        ActionRule::NotAction(wc_one_more(actions))
    }

    fn principal_aws(principals: Vec<&str>) -> PrincipalRule {
        let mut map = IndexMap::new();
        map.insert("AWS".to_string(), one_or_more(principals));
        PrincipalRule::Principal(S3Principal::Map(map))
    }

    fn not_principal_aws(principals: Vec<&str>) -> PrincipalRule {
        let mut map = IndexMap::new();
        map.insert("AWS".to_string(), one_or_more(principals));
        PrincipalRule::NotPrincipal(S3Principal::Map(map))
    }

    fn resource(resources: Vec<&str>) -> ResourceRule {
        ResourceRule::Resource(wc_one_more(resources))
    }

    fn not_resource(resources: Vec<&str>) -> ResourceRule {
        ResourceRule::NotResource(wc_one_more(resources))
    }

    fn create_credentials(access_key: &str) -> Credentials {
        Credentials {
            access_key: access_key.to_string(),
            secret_key: SecretKey::from("".to_string()),
        }
    }

    #[test]
    fn test_parse_action_rule_simple() {
        let rule = parse_action_rule(&action(vec!["s3:GetObject"])).unwrap();
        assert!(rule.matches("GetObject"));
        assert!(!rule.matches("PutObject"));
        assert!(!rule.is_not);
    }

    #[test]
    fn test_parse_action_rule_wildcard() {
        let rule = parse_action_rule(&action(vec!["*"])).unwrap();
        assert!(rule.matches("GetObject"));
        assert!(rule.matches("PutObject"));
        assert!(rule.matches("DeleteObject"));
        assert!(!rule.is_not);
    }

    #[test]
    fn test_parse_action_rule_pattern() {
        let rule = parse_action_rule(&action(vec!["s3:Get*"])).unwrap();
        assert!(rule.matches("GetObject"));
        assert!(rule.matches("GetObjectAttributes"));
        assert!(!rule.matches("PutObject"));
        assert!(!rule.is_not);
    }

    #[test]
    fn test_parse_action_rule_multiple() {
        let rule = parse_action_rule(&action(vec!["s3:GetObject", "s3:PutObject"])).unwrap();
        assert!(rule.matches("GetObject"));
        assert!(rule.matches("PutObject"));
        assert!(!rule.matches("DeleteObject"));
        assert!(!rule.is_not);
    }

    #[test]
    fn test_parse_action_rule_not_action() {
        let rule = parse_action_rule(&not_action(vec!["s3:DeleteObject"])).unwrap();
        assert!(rule.matches("GetObject"));
        assert!(rule.matches("PutObject"));
        assert!(!rule.matches("DeleteObject"));
        assert!(rule.is_not);
    }

    #[test]
    fn test_parse_action_rule_invalid_prefix() {
        let result = parse_action_rule(&action(vec!["ec2:DescribeInstances"]));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_action_rule_no_prefix() {
        let rule = parse_action_rule(&action(vec!["s3:GetObject"])).unwrap();
        assert!(rule.matches("GetObject"));
        assert!(!rule.matches("PutObject"));
    }

    #[test]
    fn test_parse_principal_rule_wildcard() {
        let rule =
            parse_principal_rule(Some(&PrincipalRule::Principal(S3Principal::Wildcard))).unwrap();
        assert!(rule.matches("arn:aws:iam::123456789012:user/alice"));
        assert!(rule.matches("bob"));
        assert!(rule.matches(""));
        assert!(!rule.is_not);
    }

    #[test]
    fn test_parse_principal_rule_aws_single() {
        let rule = parse_principal_rule(Some(&principal_aws(vec![
            "arn:aws:iam::123456789012:user/alice",
        ])))
        .unwrap();
        assert!(rule.matches("arn:aws:iam::123456789012:user/alice"));
        assert!(!rule.matches("arn:aws:iam::123456789012:user/bob"));
        assert!(!rule.is_not);
    }

    #[test]
    fn test_parse_principal_rule_aws_multiple() {
        let rule = parse_principal_rule(Some(&principal_aws(vec![
            "arn:aws:iam::123456789012:user/alice",
            "arn:aws:iam::123456789012:user/bob",
        ])))
        .unwrap();
        assert!(rule.matches("arn:aws:iam::123456789012:user/alice"));
        assert!(rule.matches("arn:aws:iam::123456789012:user/bob"));
        assert!(!rule.matches("arn:aws:iam::123456789012:user/charlie"));
        assert!(!rule.is_not);
    }

    #[test]
    fn test_parse_principal_rule_aws_pattern() {
        let rule = parse_principal_rule(Some(&principal_aws(vec![
            "arn:aws:iam::123456789012:user/*",
        ])))
        .unwrap();
        assert!(rule.matches("arn:aws:iam::123456789012:user/alice"));
        assert!(rule.matches("arn:aws:iam::123456789012:user/bob"));
        assert!(!rule.matches("arn:aws:iam::123456789012:role/admin"));
        assert!(!rule.is_not);
    }

    #[test]
    fn test_parse_principal_rule_not_principal() {
        let rule = parse_principal_rule(Some(&not_principal_aws(vec![
            "arn:aws:iam::123456789012:user/alice",
        ])))
        .unwrap();
        assert!(!rule.matches("arn:aws:iam::123456789012:user/alice"));
        assert!(rule.matches("arn:aws:iam::123456789012:user/bob"));
        assert!(rule.is_not);
    }

    #[test]
    fn test_parse_principal_rule_none_defaults_to_wildcard() {
        let rule = parse_principal_rule(None).unwrap();
        assert!(rule.matches("anyone"));
        assert!(!rule.is_not);
    }

    #[test]
    fn test_parse_principal_rule_invalid_type() {
        let mut map = IndexMap::new();
        map.insert("Service".to_string(), one_or_more(vec!["s3.amazonaws.com"]));
        let result = parse_principal_rule(Some(&PrincipalRule::Principal(S3Principal::Map(map))));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_resource_rule_wildcard() {
        let rules = parse_resource_rule(&resource(vec!["*"])).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].0.matches("my-bucket"));
        assert!(rules[0].1.matches("my-key"));
        assert!(!rules[0].0.is_not);
        assert!(!rules[0].1.is_not);
    }

    #[test]
    fn test_parse_resource_rule_bucket_only() {
        let rules = parse_resource_rule(&resource(vec!["arn:aws:s3:::my-bucket"])).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].0.matches("my-bucket"));
        assert!(!rules[0].0.matches("other-bucket"));
        assert!(rules[0].1.matches("any-key"));
    }

    #[test]
    fn test_parse_resource_rule_bucket_and_key() {
        let rules =
            parse_resource_rule(&resource(vec!["arn:aws:s3:::my-bucket/path/to/object"])).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].0.matches("my-bucket"));
        assert!(rules[0].1.matches("path/to/object"));
        assert!(!rules[0].1.matches("other/path"));
    }

    #[test]
    fn test_parse_resource_rule_bucket_with_wildcard_key() {
        let rules = parse_resource_rule(&resource(vec!["arn:aws:s3:::my-bucket/*"])).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].0.matches("my-bucket"));
        assert!(rules[0].1.matches("any/key/here"));
    }

    #[test]
    fn test_parse_resource_rule_multiple_resources_same_bucket() {
        let rules = parse_resource_rule(&resource(vec![
            "arn:aws:s3:::my-bucket/public/*",
            "arn:aws:s3:::my-bucket/shared/*",
        ]))
        .unwrap();
        assert_eq!(rules.len(), 1); // Should consolidate to one bucket rule
        assert!(rules[0].0.matches("my-bucket"));
        // Should match either pattern
        assert!(rules[0].1.matches("public/file.txt"));
        assert!(rules[0].1.matches("shared/data.json"));
        assert!(!rules[0].1.matches("private/secret.txt"));
    }

    #[test]
    fn test_parse_resource_rule_multiple_buckets() {
        let rules = parse_resource_rule(&resource(vec![
            "arn:aws:s3:::bucket-a/*",
            "arn:aws:s3:::bucket-b/*",
        ]))
        .unwrap();
        assert_eq!(rules.len(), 2);
        // Order might vary, so check both exist
        let has_bucket_a = rules.iter().any(|(b, _, _)| b.matches("bucket-a"));
        let has_bucket_b = rules.iter().any(|(b, _, _)| b.matches("bucket-b"));
        assert!(has_bucket_a);
        assert!(has_bucket_b);
    }

    #[test]
    fn test_parse_resource_rule_pattern_in_bucket() {
        let rules = parse_resource_rule(&resource(vec!["arn:aws:s3:::my-*"])).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].0.matches("my-bucket"));
        assert!(rules[0].0.matches("my-other-bucket"));
        assert!(!rules[0].0.matches("your-bucket"));
    }

    #[test]
    fn test_parse_resource_rule_not_resource() {
        let rules = parse_resource_rule(&not_resource(vec!["arn:aws:s3:::my-bucket/*"])).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].2);
        assert!(rules[0].2);
    }

    #[test]
    fn test_parse_resource_rule_invalid_format() {
        let result = parse_resource_rule(&resource(vec!["invalid-resource"]));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_resource_rule_deduplication() {
        let rules = parse_resource_rule(&resource(vec![
            "arn:aws:s3:::my-bucket/path/*",
            "arn:aws:s3:::my-bucket/path/*", // duplicate
        ]))
        .unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_basic_read_only_policy() {
        let policy = from_json(
            r#"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowListBuckets",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:ListBucket"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowReadPublicBucket",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectAttributes"
      ],
      "Resource": "arn:aws:s3:::public-bucket/*"
    }
  ]
}
"#,
        )
        .expect("policy to be valid json");

        // Test: Anonymous can list all buckets
        let ctx = Context {
            s3_path: &S3Path::Root,
            s3_op: "ListBuckets",
            principal: None,
        };

        assert!(check_policy(&policy, &ctx).is_ok());

        // Test: Anonymous can list a bucket
        let ctx = Context {
            s3_path: &S3Path::Bucket {
                bucket: "any-bucket".into(),
            },
            s3_op: "ListObjectsV2",
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        // Test: Anonymous can read from public-bucket
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "public-bucket".into(),
                key: "file.txt".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        // Test: Anonymous cannot read from other buckets
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "private-bucket".into(),
                key: "file.txt".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_err());

        // Test: Anonymous cannot write to public-bucket
        let ctx = Context {
            s3_op: "PutObject",
            s3_path: &S3Path::Object {
                bucket: "public-bucket".into(),
                key: "file.txt".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_err());

        // Test: Anonymous can get object attributes from public-bucket
        let ctx = Context {
            s3_op: "GetObjectAttributes",
            s3_path: &S3Path::Object {
                bucket: "public-bucket".into(),
                key: "data.json".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_ok());
    }

    #[test]
    fn test_user_specific_permissions() {
        let policy = from_json(
            r#"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAliceFullAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:user/alice"]
      },
      "Action": "*",
      "Resource": "arn:aws:s3:::alice-bucket/*"
    },
    {
      "Sid": "AllowBobReadOnly",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:user/bob"]
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::shared-bucket",
        "arn:aws:s3:::shared-bucket/*"
      ]
    }
  ]
}
"#,
        )
        .expect("policy to be valid json");

        let alice = Principal("arn:aws:iam::123456789012:user/alice".to_string());
        let bob = Principal("arn:aws:iam::123456789012:user/bob".to_string());
        let charlie = Principal("arn:aws:iam::123456789012:user/charlie".to_string());

        // Test: Alice has full access to alice-bucket
        let ctx = Context {
            s3_op: "PutObject",
            s3_path: &S3Path::Object {
                bucket: "alice-bucket".into(),
                key: "file.txt".into(),
            },
            principal: Some(&alice),
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "alice-bucket".into(),
                key: "file.txt".into(),
            },
            principal: Some(&alice),
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        let ctx = Context {
            s3_op: "DeleteObject",
            s3_path: &S3Path::Object {
                bucket: "alice-bucket".into(),
                key: "file.txt".into(),
            },
            principal: Some(&alice),
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        // Test: Alice cannot access other buckets
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "shared-bucket".into(),
                key: "file.txt".into(),
            },
            principal: Some(&alice),
        };
        assert!(check_policy(&policy, &ctx).is_err());

        // Test: Bob can read from shared-bucket
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "shared-bucket".into(),
                key: "data.txt".into(),
            },
            principal: Some(&bob),
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        let ctx = Context {
            s3_op: "ListObjectsV2",
            s3_path: &S3Path::Bucket {
                bucket: "shared-bucket".into(),
            },
            principal: Some(&bob),
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        // Test: Bob cannot write to shared-bucket
        let ctx = Context {
            s3_op: "PutObject",
            s3_path: &S3Path::Object {
                bucket: "shared-bucket".into(),
                key: "new-file.txt".into(),
            },
            principal: Some(&bob),
        };
        assert!(check_policy(&policy, &ctx).is_err());

        // Test: Charlie has no access
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "shared-bucket".into(),
                key: "file.txt".into(),
            },
            principal: Some(&charlie),
        };
        assert!(check_policy(&policy, &ctx).is_err());

        // Test: Anonymous has no access
        let ctx = Context {
            s3_op: "ListBuckets",
            s3_path: &S3Path::Root,
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_err());
    }

    #[test]
    fn test_pattern_matching() {
        let policy = from_json(
            r#"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowWildcardActions",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:List*",
      "Resource": "*"
    },
    {
      "Sid": "AllowPrefixedObjects",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:user/developer"]
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::dev-bucket/projects/*/src/*"
    },
    {
      "Sid": "DenyDeleteOnProduction",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:Delete*",
      "Resource": "arn:aws:s3:::prod-bucket/*"
    }
  ]
}
"#,
        )
        .expect("policy to be valid json");

        let developer = Principal("arn:aws:iam::123456789012:user/developer".to_string());

        // Test: Wildcard action matching - anyone can list
        let ctx = Context {
            s3_op: "ListBuckets",
            s3_path: &S3Path::Root,
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        let ctx = Context {
            s3_op: "ListObjectsV2",
            s3_path: &S3Path::Bucket {
                bucket: "any-bucket".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        // Test: Non-list operations are denied for anonymous
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "any-bucket".into(),
                key: "file.txt".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_err());

        // Test: Developer can access prefixed paths in dev-bucket
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "dev-bucket".into(),
                key: "projects/myapp/src/main.rs".into(),
            },
            principal: Some(&developer),
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        let ctx = Context {
            s3_op: "PutObject",
            s3_path: &S3Path::Object {
                bucket: "dev-bucket".into(),
                key: "projects/webapp/src/index.js".into(),
            },
            principal: Some(&developer),
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        let ctx = Context {
            s3_op: "DeleteObject",
            s3_path: &S3Path::Object {
                bucket: "dev-bucket".into(),
                key: "projects/api/src/handler.go".into(),
            },
            principal: Some(&developer),
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        // Test: Developer cannot access non-matching paths
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "dev-bucket".into(),
                key: "config.yml".into(),
            },
            principal: Some(&developer),
        };
        assert!(check_policy(&policy, &ctx).is_err());

        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "dev-bucket".into(),
                key: "projects/myapp/docs/readme.md".into(),
            },
            principal: Some(&developer),
        };
        assert!(check_policy(&policy, &ctx).is_err());

        // Test: Delete operations are denied on prod-bucket for everyone (explicit deny)
        let ctx = Context {
            s3_op: "DeleteObject",
            s3_path: &S3Path::Object {
                bucket: "prod-bucket".into(),
                key: "important-file.txt".into(),
            },
            principal: Some(&developer),
        };
        assert!(check_policy(&policy, &ctx).is_err());

        let ctx = Context {
            s3_op: "DeleteBucket",
            s3_path: &S3Path::Bucket {
                bucket: "prod-bucket".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_err());

        // Test: Other operations on prod-bucket are allowed if matched
        let ctx = Context {
            s3_op: "ListObjectsV2",
            s3_path: &S3Path::Bucket {
                bucket: "prod-bucket".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_ok());
    }

    #[test]
    fn test_not_rules() {
        // -----------------------------------------------------------------------
        // SCENARIO 1: NotAction
        // Logic: Allow everything EXCEPT Delete.
        // -----------------------------------------------------------------------
        let policy_not_action = from_json(
            r#"
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "AllowAllExceptDelete",
          "Effect": "Allow",
          "Principal": { "AWS": ["arn:aws:iam::123456789012:user/restricted-user"] },
          "NotAction": [ "s3:DeleteObject", "s3:DeleteBucket" ],
          "Resource": "arn:aws:s3:::restricted-bucket/*"
        }
      ]
    }
    "#,
        )
        .expect("valid policy");

        let restricted_user =
            Principal("arn:aws:iam::123456789012:user/restricted-user".to_string());

        // 1. GetObject: Should be Allowed (Matches Principal, Matches Resource, Action is NOT in NotAction)
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "restricted-bucket".into(),
                key: "file.txt".into(),
            },
            principal: Some(&restricted_user),
        };
        assert!(
            check_policy(&policy_not_action, &ctx).is_ok(),
            "NotAction: GetObject should be allowed"
        );

        // 2. DeleteObject: Should be Denied (Implicit) because the Allow statement is skipped when Action matches NotAction
        let ctx = Context {
            s3_op: "DeleteObject",
            s3_path: &S3Path::Object {
                bucket: "restricted-bucket".into(),
                key: "file.txt".into(),
            },
            principal: Some(&restricted_user),
        };
        assert!(
            check_policy(&policy_not_action, &ctx).is_err(),
            "NotAction: DeleteObject should be implicitly denied"
        );

        // -----------------------------------------------------------------------
        // SCENARIO 2: NotPrincipal
        // Logic: Allow everyone EXCEPT Admin.
        // -----------------------------------------------------------------------
        let policy_not_principal = from_json(
            r#"
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "AllowAllExceptAdmin",
          "Effect": "Allow",
          "NotPrincipal": { "AWS": ["arn:aws:iam::123456789012:user/admin"] },
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::public-data/*"
        }
      ]
    }
    "#,
        )
        .expect("valid policy");

        let admin = Principal("arn:aws:iam::123456789012:user/admin".to_string());
        let regular_user = Principal("arn:aws:iam::123456789012:user/regular".to_string());

        // 1. Regular User: Should be Allowed (Principal is NOT admin)
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "public-data".into(),
                key: "data.csv".into(),
            },
            principal: Some(&regular_user),
        };
        assert!(
            check_policy(&policy_not_principal, &ctx).is_ok(),
            "NotPrincipal: Regular user should be allowed"
        );

        // 2. Admin: Should be Denied (Implicit) because the Allow statement is skipped
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "public-data".into(),
                key: "data.csv".into(),
            },
            principal: Some(&admin),
        };
        assert!(
            check_policy(&policy_not_principal, &ctx).is_err(),
            "NotPrincipal: Admin should be implicitly denied"
        );

        // -----------------------------------------------------------------------
        // SCENARIO 3: NotResource (The Perimeter)
        // Logic: Explicitly DENY anything that is NOT within the secure folder.
        // We add an ALLOW statement to prove that the Deny doesn't block valid requests.
        // -----------------------------------------------------------------------
        let policy_not_resource = from_json(
            r#"
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "AllowEverything",
          "Effect": "Allow",
          "Principal": "*",
          "Action": "*",
          "Resource": "*"
        },
        {
          "Sid": "DenyUnlessSecure",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "*",
          "NotResource": "arn:aws:s3:::secure-bucket/public/*"
        }
      ]
    }
    "#,
        )
        .expect("valid policy");

        // 1. Accessing the Secure Folder: Should be Allowed
        // Logic: Statement 1 Allows. Statement 2 (Deny) does NOT apply because the resource matches the NotResource exception.
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "secure-bucket".into(),
                key: "public/safe.txt".into(),
            },
            principal: Some(&regular_user),
        };
        assert!(
            check_policy(&policy_not_resource, &ctx).is_ok(),
            "NotResource: Access to exception path should be allowed"
        );

        // 2. Accessing Different Folder in Same Bucket: Should be Denied
        // Logic: Statement 1 Allows. Statement 2 (Deny) APPLIES because 'private/...' != 'public/...'. Deny overrides Allow.
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "secure-bucket".into(),
                key: "private/secret.txt".into(),
            },
            principal: Some(&regular_user),
        };
        assert!(
            check_policy(&policy_not_resource, &ctx).is_err(),
            "NotResource: Access to non-exception path should be denied"
        );

        // 3. Accessing Different Bucket: Should be Denied
        // Logic: Statement 1 Allows. Statement 2 (Deny) APPLIES because 'other-bucket' != 'secure-bucket'.
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "other-bucket".into(),
                key: "file.txt".into(),
            },
            principal: Some(&regular_user),
        };
        assert!(
            check_policy(&policy_not_resource, &ctx).is_err(),
            "NotResource: Access to other bucket should be denied"
        );
    }

    #[test]
    fn test_default_policy() {
        let policy = DEFAULT_POLICY.deref();

        // Test: Anonymous can list buckets
        let ctx = Context {
            s3_op: "ListBuckets",
            s3_path: &S3Path::Root,
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        // Test: Anonymous can read objects
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "any-bucket".into(),
                key: "any-file.txt".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        // Test: Anonymous cannot write
        let ctx = Context {
            s3_op: "PutObject",
            s3_path: &S3Path::Object {
                bucket: "any-bucket".into(),
                key: "new-file.txt".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_err());

        // Test: Anonymous cannot delete
        let ctx = Context {
            s3_op: "DeleteObject",
            s3_path: &S3Path::Object {
                bucket: "any-bucket".into(),
                key: "file.txt".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_err());
    }

    #[test]
    fn test_invalid_policy_rejection() {
        // Test condition rejection
        let policy_with_condition = r#"
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "*",
        "Condition": {
          "IpAddress": {
            "aws:SourceIp": "192.168.1.0/24"
          }
        }
      }]
    }
    "#;
        assert!(from_json(policy_with_condition).is_err());

        // Test invalid principal type
        let policy_with_invalid_principal = r#"
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {
          "Service": ["ec2.amazonaws.com"]
        },
        "Action": "s3:GetObject",
        "Resource": "*"
      }]
    }
    "#;
        assert!(from_json(policy_with_invalid_principal).is_err());

        // Test invalid action prefix
        let policy_with_invalid_action = r#"
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "ec2:DescribeInstances",
        "Resource": "*"
      }]
    }
    "#;
        assert!(from_json(policy_with_invalid_action).is_err());
    }

    #[test]
    fn test_explicit_deny_overrides_allow() {
        let policy_json = r#"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::protected-bucket/*"
    }
  ]
}
"#;
        let policy = from_json(policy_json).expect("valid policy");

        // Allow should work for non-delete operations
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "protected-bucket".into(),
                key: "file.txt".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_ok());

        // Explicit deny should override allow
        let ctx = Context {
            s3_op: "DeleteObject",
            s3_path: &S3Path::Object {
                bucket: "protected-bucket".into(),
                key: "file.txt".into(),
            },
            principal: None,
        };
        assert!(check_policy(&policy, &ctx).is_err());
    }

    #[test]
    fn test_implicit_deny_when_no_allow() {
        let policy_json = r#"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": ["arn:aws:iam::123456789012:user/alice"]
      },
      "Action": "s3:GetObject",
      "Resource": "*"
    }
  ]
}
"#;
        let policy = from_json(policy_json).expect("valid policy");

        let bob = Principal("arn:aws:iam::123456789012:user/bob".to_string());

        // Bob should be implicitly denied (no matching allow)
        let ctx = Context {
            s3_op: "GetObject",
            s3_path: &S3Path::Object {
                bucket: "bucket".into(),
                key: "file.txt".into(),
            },
            principal: Some(&bob),
        };
        assert!(check_policy(&policy, &ctx).is_err());
    }
}
