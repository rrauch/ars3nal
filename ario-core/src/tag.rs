use crate::blob::{Blob, TypedBlob};
use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher};

#[derive(Debug, Clone, PartialEq)]
pub struct Tag<'a> {
    pub name: TagName<'a>,
    pub value: TagValue<'a>,
}

impl<'a> Tag<'a> {
    pub fn new(name: TagName<'a>, value: TagValue<'a>) -> Self {
        Self { name, value }
    }

    pub fn into_owned(self) -> Tag<'static> {
        Tag {
            name: self.name.into_owned(),
            value: self.value.into_owned(),
        }
    }
}

pub struct TagNameKind;
pub type TagName<'a> = TypedBlob<'a, TagNameKind>;

impl<'a> TagName<'a> {
    pub fn as_str(&'a self) -> Option<&'a str> {
        std::str::from_utf8(self.0.as_ref()).ok()
    }
}

pub struct TagValueKind;
pub type TagValue<'a> = TypedBlob<'a, TagValueKind>;

impl<'a> TagValue<'a> {
    pub fn as_str(&'a self) -> Option<&'a str> {
        std::str::from_utf8(self.0.as_ref()).ok()
    }
}

impl<'a> From<(Blob<'a>, Blob<'a>)> for Tag<'a> {
    fn from((k, v): (Blob<'a>, Blob<'a>)) -> Self {
        Self {
            name: TagName::new_from_inner(k),
            value: TagValue::new_from_inner(v),
        }
    }
}

impl DeepHashable for Tag<'_> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::list([self.name.deep_hash(), self.value.deep_hash()])
    }
}

impl Hashable for Tag<'_> {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.name.feed(hasher);
        self.value.feed(hasher);
    }
}
