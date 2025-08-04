use crate::chunking::TypedChunk;
use crate::crypto::hash::{Hasher, Sha256};

pub struct ExternalDataKind;
pub type ChunkedData<H: Hasher> = TypedChunk<ExternalDataKind, H>;
pub type DefaultChunkedData = ChunkedData<Sha256>;
