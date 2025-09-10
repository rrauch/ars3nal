use crate::blob::{AsBlob, Blob, OwnedBlob};
use crate::bundle::TagError;
use crate::tag::{Tag, TagName, TagValue};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_avro_fast::Schema;
use std::ops::Deref;
use std::sync::LazyLock;

pub(crate) static AVRO_SCHEMA: LazyLock<Schema> = LazyLock::new(|| {
    r#"
{
  "type": "array",
  "items": {
    "type": "record",
    "name": "Tag",
    "fields": [
      { "name": "name", "type": "bytes" },
      { "name": "value", "type": "bytes" }
    ]
  }
}
"#
    .parse()
    .expect("Failed to parse avro schema")
});

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AvroTag<'a> {
    #[serde(borrow)]
    name: Blob<'a>,
    #[serde(borrow)]
    value: Blob<'a>,
}

impl<'a> From<AvroTag<'a>> for Tag<'a> {
    fn from(value: AvroTag<'a>) -> Self {
        Tag::new(
            TagName::new_from_inner(value.name),
            TagValue::new_from_inner(value.value),
        )
    }
}

impl<'a> From<&'a Tag<'a>> for AvroTag<'a> {
    fn from(tag: &'a Tag<'a>) -> Self {
        AvroTag {
            name: tag.name.as_blob(),
            value: tag.value.as_blob(),
        }
    }
}

pub fn from_avro(input: &[u8]) -> Result<Vec<Tag<'static>>, TagError> {
    if input.is_empty() {
        return Ok(vec![]);
    }
    Ok(
        serde_avro_fast::from_datum_slice::<Vec<AvroTag<'_>>>(input, AVRO_SCHEMA.deref())?
            .into_iter()
            .map(|t| Tag::from(t).into_owned())
            .collect_vec(),
    )
}

pub fn to_avro<'a>(iter: impl IntoIterator<Item = &'a Tag<'a>>) -> Result<OwnedBlob, TagError> {
    let tags = iter.into_iter().map(|t| AvroTag::from(t)).collect_vec();
    if tags.is_empty() {
        return Ok(OwnedBlob::Slice(b"".as_slice()));
    }
    Ok(serde_avro_fast::to_datum_vec(
        &tags,
        &mut serde_avro_fast::ser::SerializerConfig::new(AVRO_SCHEMA.deref()),
    )?
    .into())
}
