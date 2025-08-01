use crate::blob::Blob;
use crate::crypto::hash::{Digest, Hasher, HasherExt};
use bytes::Bytes;
use uuid::Uuid;

pub(crate) trait DeepHashable {
    fn deep_hash<H: Hasher>(&self) -> Digest<H>;
    fn blob<H: Hasher, B: AsRef<[u8]> + ?Sized>(buf: &B) -> Digest<H> {
        let buf = buf.as_ref();
        let tag_digest = H::digest(format!("blob{}", buf.len()).as_bytes());
        let data_digest = H::digest(buf);
        H::digest_from_iter(vec![tag_digest.as_slice(), data_digest.as_slice()].into_iter())
    }
    fn list<H: Hasher, C: Into<Vec<Digest<H>>>>(children: C) -> Digest<H> {
        let children = children.into();
        let mut acc_digest = H::digest(format!("list{}", children.len()).as_bytes());
        for c in children {
            acc_digest = H::digest_from_iter(vec![acc_digest.as_slice(), c.as_slice()].into_iter());
        }
        acc_digest
    }
}

impl<'a> DeepHashable for Blob<'a> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.bytes().deep_hash()
    }
}

impl DeepHashable for Uuid {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_bytes().as_slice().deep_hash()
    }
}

impl<'a> DeepHashable for &'a [u8] {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(self)
    }
}

impl<const N: usize> DeepHashable for [u8; N] {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_slice().deep_hash()
    }
}

impl DeepHashable for String {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_bytes().deep_hash()
    }
}

impl<'a> DeepHashable for &'a str {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.as_bytes().deep_hash()
    }
}

impl<'a, T> DeepHashable for &'a T
where
    T: DeepHashable,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        T::deep_hash(self)
    }
}

impl<T> DeepHashable for Option<T>
where
    T: DeepHashable,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        if let Some(this) = &self {
            this.deep_hash()
        } else {
            Self::blob(&[])
        }
    }
}

impl<T> DeepHashable for Vec<T>
where
    T: DeepHashable,
{
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::list(self.iter().map(|t| t.deep_hash()).collect::<Vec<_>>())
    }
}

impl<H: Hasher> DeepHashable for Digest<H> {
    fn deep_hash<H2: Hasher>(&self) -> Digest<H2> {
        self.as_slice().deep_hash()
    }
}

impl DeepHashable for Bytes {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        Self::blob(self)
    }
}

impl DeepHashable for u64 {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        // numbers have to be serialized to strings!
        self.to_string().deep_hash()
    }
}

impl DeepHashable for u32 {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        // numbers have to be serialized to strings!
        self.to_string().deep_hash()
    }
}
