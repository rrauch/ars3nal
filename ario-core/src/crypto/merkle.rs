use crate::crypto::hash::{Digest, Hashable, HashableExt, Hasher, Sha256, TypedDigest};
use crate::typed::{FromInner, Typed};
use bytemuck::TransparentWrapper;
use bytes::{Bytes, BytesMut};
use derive_where::derive_where;
use ringbuf::LocalRb;
use ringbuf::consumer::Consumer;
use ringbuf::producer::Producer;
use ringbuf::storage::Heap;
use ringbuf::traits::Observer;
use std::cmp::min;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::{LazyLock, Mutex};

static ZERO_BYTES: LazyLock<ZeroBytes> = LazyLock::new(|| ZeroBytes::new());

pub type ArweaveMerkleTreeBuilder = MerkleTreeBuilder<Sha256, 32, { 256 * 1024 }, { 32 * 1024 }>;
pub type ArweaveMerkleRootId = MerkleRootId<Sha256>;

pub struct MerkleNodeIdKind;
pub type NodeId<H: Hasher> = TypedDigest<MerkleNodeIdKind, H>;

pub struct MerkleRootKind;
pub type MerkleRootId<H: Hasher> = Typed<MerkleRootKind, NodeId<H>>;

#[derive_where(Clone, Debug, PartialEq)]
pub struct MerkleTree<
    H: Hasher,
    const NOTE_SIZE: usize,
    const MAX_CHUNK_SIZE: usize,
    const MIN_CHUNK_SIZE: usize,
> {
    root: Node<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>,
}

impl<H: Hasher, const NOTE_SIZE: usize, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize>
    MerkleTree<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>
{
    pub fn root_id(&self) -> &MerkleRootId<H> {
        MerkleRootId::wrap_ref(self.root.id())
    }
}

#[derive_where(Clone, Debug, PartialEq)]
pub enum Node<
    H: Hasher,
    const NOTE_SIZE: usize,
    const MAX_CHUNK_SIZE: usize,
    const MIN_CHUNK_SIZE: usize,
> {
    Leaf(Leaf<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>),
    Branch(Branch<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>),
}

impl<H: Hasher, const NOTE_SIZE: usize, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize>
    Node<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>
{
    fn id(&self) -> &NodeId<H> {
        match self {
            Node::Leaf(leaf) => &leaf.id,
            Node::Branch(branch) => &branch.id,
        }
    }

    fn max_offset(&self) -> u64 {
        match self {
            Node::Leaf(leaf) => leaf.chunk.offset.end,
            Node::Branch(branch) => branch.max,
        }
    }
}

#[derive_where(Clone, Debug, PartialEq)]
pub struct Leaf<
    H: Hasher,
    const NOTE_SIZE: usize,
    const MAX_CHUNK_SIZE: usize,
    const MIN_CHUNK_SIZE: usize,
> {
    id: NodeId<H>,
    chunk: Chunk<H, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>,
}

impl<H: Hasher, const NOTE_SIZE: usize, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize>
    Leaf<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>
{
    fn from_chunk(chunk: Chunk<H, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>) -> Self {
        let mut id_hasher = H::new();
        chunk.data_hash.digest::<H>().feed(&mut id_hasher);
        to_note_hash::<H, NOTE_SIZE>(chunk.offset.end).feed(&mut id_hasher);
        let id = id_hasher.finalize();
        Self {
            id: NodeId::from_inner(id),
            chunk,
        }
    }
}

fn to_note_hash<H: Hasher, const NOTE_SIZE: usize>(value: u64) -> Digest<H> {
    let mut hasher = H::new();
    let zeros = ZERO_BYTES.get(NOTE_SIZE - 8);
    hasher.update(zeros.as_ref());
    let be_u64 = value.to_be_bytes();
    hasher.update(&be_u64);
    hasher.finalize()
}

#[derive_where(Clone, Debug, PartialEq)]
pub struct Chunk<H: Hasher, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize> {
    data_hash: Digest<H>,
    offset: Range<u64>,
}

#[derive_where(Clone, Debug, PartialEq)]
pub struct Branch<
    H: Hasher,
    const NOTE_SIZE: usize,
    const MAX_CHUNK_SIZE: usize,
    const MIN_CHUNK_SIZE: usize,
> {
    id: NodeId<H>,
    left: Box<Node<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>>,
    right: Box<Node<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>>,
    note: u64, // Split point (left child's max offset)
    max: u64,  // Right child's max offset
}

impl<H: Hasher, const NOTE_SIZE: usize, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize>
    Branch<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>
{
    fn new(
        left: Node<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>,
        right: Node<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>,
    ) -> Self {
        let left_id = left.id().clone();
        let left_max = left.max_offset();
        let right_id = right.id().clone();
        let right_max = right.max_offset();

        // The note is the left child's max offset (split point)
        let note = left_max;
        let max = right_max;

        // Compute branch ID: hash(left_id || right_id || note_hash)
        let mut id_hasher = H::new();
        left_id.digest::<H>().feed(&mut id_hasher);
        right_id.digest::<H>().feed(&mut id_hasher);
        to_note_hash::<H, NOTE_SIZE>(note).feed(&mut id_hasher);
        let id = id_hasher.finalize();

        Self {
            id: NodeId::from_inner(id),
            left: Box::new(left),
            right: Box::new(right),
            note,
            max,
        }
    }
}

pub struct MerkleTreeBuilder<
    H: Hasher,
    const NOTE_SIZE: usize,
    const MAX_CHUNK_SIZE: usize,
    const MIN_CHUNK_SIZE: usize,
> {
    hasher: H,
    current_chunk_start_offset: u64,
    total_bytes_processed: u64,
    buf: LocalRb<Heap<u8>>,
    chunks: Vec<Chunk<H, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>>,
}

impl<H: Hasher, const NOTE_SIZE: usize, const MAX_CHUNK_SIZE: usize, const MIN_CHUNK_SIZE: usize>
    MerkleTreeBuilder<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>
{
    pub fn new() -> Self {
        assert!(MAX_CHUNK_SIZE > 0, "MAX_CHUNK_SIZE must be greater than 0.");
        assert!(MIN_CHUNK_SIZE > 0, "MIN_CHUNK_SIZE must be greater than 0.");
        assert!(
            MIN_CHUNK_SIZE <= MAX_CHUNK_SIZE,
            "MIN_CHUNK_SIZE must be <= MAX_CHUNK_SIZE."
        );
        let buf = LocalRb::new(MAX_CHUNK_SIZE + MIN_CHUNK_SIZE + 1);
        Self {
            hasher: H::new(),
            current_chunk_start_offset: 0,
            total_bytes_processed: 0,
            buf,
            chunks: Vec::new(),
        }
    }

    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        let mut input_slice = input.as_ref();

        while !input_slice.is_empty() {
            if self.buf.is_full() {
                self.process_chunk(false);
                continue;
            }

            let to_copy = input_slice.len().min(self.buf.vacant_len());
            let num_bytes = self.buf.push_slice(&input_slice[..to_copy]);
            input_slice = &input_slice[num_bytes..];
        }
    }

    fn process_chunk(&mut self, is_final: bool) {
        let buffered_len = self.buf.occupied_len();

        if buffered_len == 0 {
            return;
        }

        let chunk_len = if is_final {
            if buffered_len > MAX_CHUNK_SIZE {
                // split the remaining data more evenly
                (buffered_len + 1) / 2
            } else {
                buffered_len
            }
        } else {
            min(MAX_CHUNK_SIZE, self.buf.occupied_len())
        };
        assert!(chunk_len <= MAX_CHUNK_SIZE);

        let mut remaining = chunk_len;
        let (mut sl1, mut sl2) = self.buf.as_slices();

        while remaining > 0 {
            if !sl1.is_empty() {
                let to_process = sl1.len().min(remaining);
                self.hasher.update(&sl1[..to_process]);
                sl1 = &sl1[to_process..];
                remaining -= to_process;
            } else if !sl2.is_empty() {
                let to_process = sl2.len().min(remaining);
                self.hasher.update(&sl2[..to_process]);
                sl2 = &sl2[to_process..];
                remaining -= to_process;
            } else {
                break;
            }
        }

        let processed = chunk_len - remaining;
        assert!(processed > 0);

        // finalize the chunk
        let data_hash = std::mem::replace(&mut self.hasher, H::new()).finalize();
        let end_offset = self.current_chunk_start_offset + processed as u64;

        self.chunks.push(Chunk {
            data_hash,
            offset: self.current_chunk_start_offset..end_offset,
        });

        // Safety: advance read index by `processed` bytes
        unsafe {
            self.buf.advance_read_index(processed);
        }
        self.current_chunk_start_offset = end_offset;
        self.total_bytes_processed += processed as u64;
    }

    pub fn finalize(mut self) -> MerkleTree<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE> {
        // Process any remaining data
        while self.buf.occupied_len() > 0 {
            self.process_chunk(true);
        }
        let mut nodes = self
            .chunks
            .into_iter()
            .map(|c| {
                Node::Leaf(Leaf::<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>::from_chunk(c))
            })
            .collect::<Vec<_>>();

        if nodes.is_empty() {
            todo!()
        }

        // Build tree bottom-up
        while nodes.len() > 1 {
            let mut next_layer = Vec::new();
            let mut iter = nodes.into_iter();

            while let Some(left) = iter.next() {
                match iter.next() {
                    Some(right) => {
                        // We have a pair - create a branch
                        let branch = Branch::new(left, right);
                        next_layer.push(Node::Branch(branch));
                    }
                    None => {
                        // Odd node out - carry it up unchanged
                        next_layer.push(left);
                    }
                }
            }

            nodes = next_layer;
        }
        assert_eq!(nodes.len(), 1);

        MerkleTree {
            root: nodes.into_iter().next().unwrap(),
        }
    }
}

struct ZeroBytes {
    map: Mutex<HashMap<usize, Bytes>>,
}

impl ZeroBytes {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::default()),
        }
    }

    fn get(&self, len: usize) -> Bytes {
        let mut lock = self.map.lock().expect("lock not to be poisoned");
        if !lock.contains_key(&len) {
            lock.insert(len, BytesMut::zeroed(len).freeze());
        }
        lock.get(&len).unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::merkle::ArweaveMerkleTreeBuilder;

    static ONE_MB: &'static [u8] = include_bytes!("../../testdata/1mb.bin");

    #[test]
    fn merkle_tree_builder() -> anyhow::Result<()> {
        let mut tree_builder = ArweaveMerkleTreeBuilder::new();
        tree_builder.update(ONE_MB);
        let tree = tree_builder.finalize();

        let expected_root_id = [
            13, 66, 76, 111, 151, 198, 191, 18, 129, 188, 244, 243, 122, 39, 159, 246, 73, 77, 231,
            100, 200, 2, 138, 245, 233, 31, 171, 188, 172, 188, 68, 16,
        ];

        assert_eq!(tree.root_id().as_slice(), expected_root_id);

        Ok(())
    }
}
