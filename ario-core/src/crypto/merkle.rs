use crate::crypto::hash::{Digest, Hashable, HashableExt, Hasher, Sha256, TypedDigest};
use crate::typed::{FromInner, Typed};
use bytemuck::TransparentWrapper;
use derive_where::derive_where;
use ringbuf::LocalRb;
use ringbuf::consumer::Consumer;
use ringbuf::producer::Producer;
use ringbuf::storage::Heap;
use ringbuf::traits::Observer;
use std::cmp::min;
use std::ops::Range;

pub type DefaultMerkleTreeBuilder = MerkleTreeBuilder<Sha256, 32, { 256 * 1024 }, { 32 * 1024 }>;
pub type DefaultMerkleRoot = MerkleRoot<Sha256, 32, { 256 * 1024 }, { 32 * 1024 }>;

pub struct MerkleNodeIdKind;
pub type NodeId<
    H: Hasher,
    const NOTE_SIZE: usize,
    const MAX_CHUNK_SIZE: usize,
    const MIN_CHUNK_SIZE: usize,
> = TypedDigest<MerkleNodeIdKind, H>;

pub struct MerkleRootKind;
pub type MerkleRoot<
    H: Hasher,
    const NOTE_SIZE: usize,
    const MAX_CHUNK_SIZE: usize,
    const MIN_CHUNK_SIZE: usize,
> = Typed<MerkleRootKind, NodeId<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>>;

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
    pub fn root(&self) -> &MerkleRoot<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE> {
        MerkleRoot::wrap_ref(self.root.id())
    }

    pub fn num_chunks(&self) -> usize {
        self.root.num_chunks()
    }

    pub fn max_offset(&self) -> u64 {
        self.root.max_offset()
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
    fn id(&self) -> &NodeId<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE> {
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

    fn num_chunks(&self) -> usize {
        match self {
            Node::Leaf(leaf) => match leaf.is_empty() {
                true => 0,
                false => 1,
            },
            Node::Branch(branch) => branch.num_chunks(),
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
    id: NodeId<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>,
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

    fn empty() -> Self {
        let empty_chunk = Chunk {
            data_hash: H::new().finalize(),
            offset: 0..0,
        };

        Self::from_chunk(empty_chunk)
    }

    fn is_empty(&self) -> bool {
        self.chunk.offset.is_empty()
    }
}

fn to_note_hash<H: Hasher, const NOTE_SIZE: usize>(value: u64) -> Digest<H> {
    let mut hasher = H::new();
    let zeros = [0u8; NOTE_SIZE];
    hasher.update(&zeros[..NOTE_SIZE - 8]);
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
    id: NodeId<H, NOTE_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE>,
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

        // Compute branch ID: hash(hash(left_id) || hash(right_id) || hash(note))
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

    fn num_chunks(&self) -> usize {
        self.left.num_chunks() + self.right.num_chunks()
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
        let buf = LocalRb::new(MAX_CHUNK_SIZE + MIN_CHUNK_SIZE);
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
            let empty = Leaf::empty();
            nodes.push(Node::Leaf(empty.clone()));
            nodes.push(Node::Leaf(empty));
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

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::crypto::merkle::DefaultMerkleTreeBuilder;

    static ONE_MB: &'static [u8] = include_bytes!("../../testdata/1mb.bin");
    static TX_EVEN_DATA: &'static [u8] =
        include_bytes!("../../testdata/OX63odH91fXS4hN506rYC_WUo8mWC5M3xuBymLhSKSw.data");
    static TX_ODD_DATA: &'static [u8] =
        include_bytes!("../../testdata/trtu91u1kRVDrZI6WvWVxU3uvEjJRZcls2WSZvYJyBc.data");

    #[test]
    fn merkle_tree_builder() -> anyhow::Result<()> {
        let mut tree_builder = DefaultMerkleTreeBuilder::new();
        tree_builder.update(ONE_MB);
        let tree = tree_builder.finalize();

        let expected_root_id = [
            13, 66, 76, 111, 151, 198, 191, 18, 129, 188, 244, 243, 122, 39, 159, 246, 73, 77, 231,
            100, 200, 2, 138, 245, 233, 31, 171, 188, 172, 188, 68, 16,
        ];

        assert_eq!(tree.root().as_slice(), expected_root_id);
        assert_eq!(tree.num_chunks(), 8);
        assert_eq!(tree.max_offset(), 1901762);

        Ok(())
    }

    #[test]
    fn merkle_tree_builder_even() -> anyhow::Result<()> {
        let mut tree_builder = DefaultMerkleTreeBuilder::new();
        tree_builder.update(TX_EVEN_DATA);
        let tree = tree_builder.finalize();

        assert_eq!(
            tree.root().to_base64(),
            "Q7ug4JF3yjKW4COQ7Aqyr6zJW0seFn4ue5XRMxygsSU"
        );

        assert_eq!(tree.max_offset(), 330871);
        assert_eq!(tree.num_chunks(), 2);

        Ok(())
    }

    #[test]
    fn merkle_tree_builder_odd() -> anyhow::Result<()> {
        let mut tree_builder = DefaultMerkleTreeBuilder::new();
        tree_builder.update(TX_ODD_DATA);
        let tree = tree_builder.finalize();

        assert_eq!(
            tree.root().to_base64(),
            "ikHHDmOhqnZ5qsNZ7SOoofuaG66A5yRLsTvacad2NMg"
        );

        assert_eq!(tree.max_offset(), 683821);
        assert_eq!(tree.num_chunks(), 3);

        Ok(())
    }

    #[test]
    fn small_final_chunk() -> anyhow::Result<()> {
        let data = vec![0; 256 * 1024 + 1];
        let expected = "br1Vtl3TS_NGWdHmYqBh3-MxrlckoluHCZGmUZk-dJc";

        let mut tree_builder = DefaultMerkleTreeBuilder::new();
        tree_builder.update(&data);
        let tree = tree_builder.finalize();

        assert_eq!(tree.root().to_base64(), expected);
        assert_eq!(tree.num_chunks(), 2);
        assert_eq!(tree.max_offset(), data.len() as u64);

        Ok(())
    }

    #[test]
    fn empty_tree() -> anyhow::Result<()> {
        let tree_builder = DefaultMerkleTreeBuilder::new();
        let empty_tree = tree_builder.finalize();
        assert_eq!(empty_tree.max_offset(), 0);
        assert_eq!(empty_tree.num_chunks(), 0);

        // todo: check against reference implementation
        let expected = "U6L6PiJ70MHXS7ZQ-ctkdhVoZFBsdbFCyqZDfdW6k-s";

        assert_eq!(empty_tree.root().to_base64(), expected);

        Ok(())
    }
}
