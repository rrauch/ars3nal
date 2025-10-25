use crate::blob::{AsBlob, Blob};
use crate::chunking::{
    Chunk, ChunkInfo, ChunkMap, Chunker, DefaultChunker, IntoMaybeOwnedChunk, MaybeOwnedChunk,
};
use crate::crypto::hash::{Digest, Hashable, HashableExt, Hasher, Sha256};
use crate::crypto::{Output, OutputLen};
use crate::typed::{FromInner, Typed, WithSerde};
use bytemuck::TransparentWrapper;
use bytes::{Buf, Bytes, BytesMut};
use derive_where::derive_where;
use rangemap::RangeMap;
use std::iter;
use std::marker::PhantomData;
use std::ops::Range;
use thiserror::Error;

pub type DefaultMerkleRoot = MerkleRoot<Sha256, DefaultChunker, 32>;
pub type DefaultMerkleTree<'a> = MerkleTree<'a, Sha256, DefaultChunker, 32>;

struct MerkleNodeIdKind;
type NodeId<H: Hasher, C: Chunker, const NOTE_SIZE: usize, T = MerkleNodeIdKind> =
    Typed<(T, C, PhantomData<[(); NOTE_SIZE]>), Digest<H>>;

impl<H: Hasher, C: Chunker, const NOTE_SIZE: usize, T> WithSerde for NodeId<H, C, NOTE_SIZE, T> {}

pub struct MerkleRootKind;
pub type MerkleRoot<H: Hasher, C: Chunker, const NOTE_SIZE: usize> =
    NodeId<H, C, NOTE_SIZE, MerkleRootKind>;

impl<H: Hasher, C: Chunker, const NOTE_SIZE: usize> MerkleRoot<H, C, NOTE_SIZE> {
    const HASH_SIZE: usize = <<H::Output as Output>::Len as OutputLen>::USIZE;
    const CHUNK_OUTPUT_SIZE: usize = <<C::Output as ChunkInfo>::Len>::USIZE;
    const LEAF_PROOF_LEN: usize = { Self::HASH_SIZE + NOTE_SIZE };
    const BRANCH_PROOF_LEN: usize = { Self::HASH_SIZE * 2 + NOTE_SIZE };

    pub fn authenticate_data(
        &self,
        data: &mut impl Buf,
        proof: &Proof<H, C, NOTE_SIZE>,
    ) -> Result<(), ProofError> {
        let len = (proof.offset.end - proof.offset.start) as usize;
        if data.remaining() != len {
            return Err(ProofError::InvalidDataLength {
                expected: len,
                actual: data.remaining(),
            });
        }
        let chunk = C::single_chunk(data, proof.offset.start);
        self.authenticate_chunk(&chunk, proof)
    }

    fn authenticate_chunk(
        &self,
        chunk: &Chunk<C>,
        proof: &Proof<H, C, NOTE_SIZE>,
    ) -> Result<(), ProofError> {
        if &proof.offset != chunk.offset() {
            return Err(ProofError::IncorrectOffset {
                expected: proof.offset.clone(),
                actual: chunk.offset().clone(),
            });
        }

        let (branches, leaf) = proof
            .proof
            .split_at(proof.proof.len() - Self::LEAF_PROOF_LEN);

        let branch_proofs = branches
            .chunks(Self::BRANCH_PROOF_LEN)
            .map(|b| BranchProof::try_from(b, Self::HASH_SIZE, NOTE_SIZE))
            .collect::<Result<Vec<_>, ProofError>>()?;

        let mut expected_id = self.0.as_slice();

        // path validation
        for proof in &branch_proofs {
            let mut hasher = H::new();
            proof.left_id.digest::<H>().feed(&mut hasher);
            proof.right_id.digest::<H>().feed(&mut hasher);
            proof.note.digest::<H>().feed(&mut hasher);
            let id = hasher.finalize();

            if id.as_slice() != expected_id {
                return Err(ProofError::AuthenticationFailed);
            }

            expected_id = if proof.offset() >= chunk.offset().end {
                proof.left_id
            } else {
                proof.right_id
            };
        }

        // leaf validation
        let proof = LeafProof::try_from(leaf, Self::CHUNK_OUTPUT_SIZE, NOTE_SIZE)?;

        let mut hasher = H::new();
        chunk.output().digest::<H>().feed(&mut hasher);
        let note = to_note::<NOTE_SIZE>(chunk.offset().end);
        note.digest::<H>().feed(&mut hasher);
        let id = hasher.finalize();

        if id.as_slice() != expected_id {
            return Err(ProofError::AuthenticationFailed);
        }

        if chunk.output().as_blob().bytes() != proof.chunk_output {
            return Err(ProofError::AuthenticationFailed);
        }

        if note.as_slice() != proof.note {
            return Err(ProofError::AuthenticationFailed);
        }

        Ok(())
    }
}

struct BranchProof<'a> {
    left_id: &'a [u8],
    right_id: &'a [u8],
    note: &'a [u8],
}

impl<'a> BranchProof<'a> {
    fn try_from(data: &'a [u8], id_len: usize, note_len: usize) -> Result<Self, ProofError> {
        let expected = (id_len * 2) + note_len;
        let actual = data.len();
        if actual != expected {
            return Err(ProofError::InvalidProofLength { expected, actual });
        }
        Ok(Self {
            left_id: &data[..id_len],
            right_id: &data[id_len..(id_len * 2)],
            note: &data[(id_len * 2)..],
        })
    }

    fn offset(&self) -> u64 {
        let u64_be_bytes = &self.note[self.note.len() - 8..];
        u64::from_be_bytes(
            u64_be_bytes
                .try_into()
                .expect("u64 be conversion should never fail"),
        )
    }
}

struct LeafProof<'a> {
    chunk_output: &'a [u8],
    note: &'a [u8],
}

impl<'a> LeafProof<'a> {
    fn try_from(
        data: &'a [u8],
        chunk_output_len: usize,
        note_len: usize,
    ) -> Result<Self, ProofError> {
        let expected = chunk_output_len + note_len;
        let actual = data.len();
        if actual != expected {
            return Err(ProofError::InvalidProofLength { expected, actual });
        }
        Ok(Self {
            chunk_output: &data[..chunk_output_len],
            note: &data[chunk_output_len..],
        })
    }
}

#[derive(Error, Debug, Clone)]
pub enum ProofError {
    #[error("invalid proof length: expected '{expected}' but found '{actual}'")]
    InvalidProofLength { expected: usize, actual: usize },
    #[error("invalid data length: expected '{expected}' but found '{actual}'")]
    InvalidDataLength { expected: usize, actual: usize },
    #[error("incorrect offset: expected '{expected:?}' but found '{actual:?}'")]
    IncorrectOffset {
        expected: Range<u64>,
        actual: Range<u64>,
    },
    #[error("authentication failed")]
    AuthenticationFailed,
}

impl<H: Hasher, C: Chunker, const NOTE_SIZE: usize> ChunkMap for MerkleTree<'_, H, C, NOTE_SIZE>
where
    <H as Hasher>::Output: Unpin,
    <C as Chunker>::Output: Unpin,
    C: Send + Sync + Unpin,
{
    fn len(&self) -> usize {
        self.num_chunks()
    }

    fn size(&self) -> u64 {
        self.root.chunks().map(|r| r.end - r.start).sum()
    }

    fn max_chunk_size() -> usize
    where
        Self: Sized,
    {
        C::max_chunk_size()
    }

    fn chunk_at(&self, pos: u64) -> Option<Range<u64>> {
        self.proof(pos).map(|p| p.offset.clone())
    }

    fn iter(&self) -> Box<dyn Iterator<Item = Range<u64>> + '_> {
        Box::new(self.root.chunks().into_iter().map(|r| r.clone()))
    }
}

#[derive_where(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MerkleTree<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> {
    root: Node<'a, H, C, NOTE_SIZE>,
    proofs: RangeMap<u64, Proof<'static, H, C, NOTE_SIZE>>,
}

impl<H: Hasher, C: Chunker, const NOTE_SIZE: usize> MerkleTree<'_, H, C, NOTE_SIZE> {
    pub fn root(&self) -> &MerkleRoot<H, C, NOTE_SIZE> {
        MerkleRoot::wrap_ref(self.root.id())
    }

    pub fn num_chunks(&self) -> usize {
        self.root.num_chunks()
    }

    pub fn chunks(&self) -> impl Iterator<Item = &Range<u64>> {
        self.root.chunks()
    }

    pub fn offset(&self) -> &Range<u64> {
        self.root.offset()
    }

    pub fn proof(&self, offset: u64) -> Option<&Proof<'_, H, C, NOTE_SIZE>> {
        self.proofs.get(&offset)
    }
}

impl<'a, H: Hasher, C: Chunker, I: IntoMaybeOwnedChunk<'a, C>, const NOTE_SIZE: usize>
    FromIterator<I> for MerkleTree<'a, H, C, NOTE_SIZE>
{
    fn from_iter<T: IntoIterator<Item = I>>(iter: T) -> Self {
        let mut nodes = iter
            .into_iter()
            .map(|c| Node::Leaf(Leaf::<H, C, NOTE_SIZE>::from_chunk(c)))
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

        let root = nodes.into_iter().next().expect("root to exist");

        let proofs = if root.is_empty() {
            RangeMap::default()
        } else {
            generate_proofs::<H, C, NOTE_SIZE>(&root)
                .into_iter()
                .map(|p| (p.offset.clone(), p))
                .collect()
        };

        Self { root, proofs }
    }
}

#[derive_where(Clone, Debug, PartialEq, Serialize, Deserialize)]
enum Node<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> {
    Leaf(Leaf<'a, H, C, NOTE_SIZE>),
    Branch(Branch<'a, H, C, NOTE_SIZE>),
}

impl<H: Hasher, C: Chunker, const NOTE_SIZE: usize> Node<'_, H, C, NOTE_SIZE> {
    fn id(&self) -> &NodeId<H, C, NOTE_SIZE> {
        match self {
            Node::Leaf(leaf) => &leaf.id,
            Node::Branch(branch) => &branch.id,
        }
    }

    fn offset(&self) -> &Range<u64> {
        match self {
            Node::Leaf(leaf) => leaf.chunk.offset(),
            Node::Branch(branch) => &branch.offset,
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

    fn chunks(&self) -> impl Iterator<Item = &Range<u64>> {
        let iter: Box<dyn Iterator<Item = &Range<u64>>> = match self {
            Node::Leaf(leaf) => match leaf.is_empty() {
                true => Box::new(iter::empty()),
                false => Box::new(iter::once(leaf.chunk.offset())),
            },
            Node::Branch(branch) => Box::new(branch.chunks()),
        };
        iter
    }

    fn is_empty(&self) -> bool {
        self.num_chunks() == 0
    }
}

#[derive_where(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Leaf<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> {
    id: NodeId<H, C, NOTE_SIZE>,
    #[serde(with = "serde_arrays")]
    note: [u8; NOTE_SIZE],
    chunk: MaybeOwnedChunk<'a, C>,
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> Leaf<'a, H, C, NOTE_SIZE> {
    fn from_chunk<I: IntoMaybeOwnedChunk<'a, C>>(chunk: I) -> Self {
        let chunk = chunk.into();
        let note = to_note::<NOTE_SIZE>(chunk.offset().end);
        let mut id_hasher = H::new();
        chunk.output().digest::<H>().feed(&mut id_hasher);
        note.digest::<H>().feed(&mut id_hasher);
        let id = id_hasher.finalize();
        Self {
            id: NodeId::from_inner(id),
            note,
            chunk,
        }
    }

    fn empty() -> Self {
        let empty_chunk = Chunk::new(C::empty(), 0..0);

        Self::from_chunk(empty_chunk)
    }

    fn is_empty(&self) -> bool {
        self.chunk.is_empty()
    }
}

fn to_note<const NOTE_SIZE: usize>(value: u64) -> [u8; NOTE_SIZE] {
    let mut note = [0u8; NOTE_SIZE];
    let start_idx = NOTE_SIZE.saturating_sub(8);
    note[start_idx..].copy_from_slice(&value.to_be_bytes());
    note
}

#[derive_where(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Branch<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> {
    id: NodeId<H, C, NOTE_SIZE>,
    left: Box<Node<'a, H, C, NOTE_SIZE>>,
    right: Box<Node<'a, H, C, NOTE_SIZE>>,
    offset: Range<u64>, // Left child's min offset - Right child's max offset
    #[serde(with = "serde_arrays")]
    note: [u8; NOTE_SIZE],
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> Branch<'a, H, C, NOTE_SIZE> {
    fn new(left: Node<'a, H, C, NOTE_SIZE>, right: Node<'a, H, C, NOTE_SIZE>) -> Self {
        // Compute branch ID: hash(hash(left_id) || hash(right_id) || hash(note))
        let mut id_hasher = H::new();
        left.id().digest::<H>().feed(&mut id_hasher);
        right.id().digest::<H>().feed(&mut id_hasher);

        // The note is the left child's max offset (split point)
        let note = to_note::<NOTE_SIZE>(left.offset().end);
        note.digest::<H>().feed(&mut id_hasher);

        let id = id_hasher.finalize();

        Self {
            id: NodeId::from_inner(id),
            offset: left.offset().start..right.offset().end,
            left: Box::new(left),
            right: Box::new(right),
            note,
        }
    }

    fn num_chunks(&self) -> usize {
        self.left.num_chunks() + self.right.num_chunks()
    }

    fn chunks(&self) -> impl Iterator<Item = &Range<u64>> {
        self.left.chunks().chain(self.right.chunks())
    }
}

fn generate_proofs<H: Hasher, C: Chunker, const NOTE_SIZE: usize>(
    root: &Node<H, C, NOTE_SIZE>,
) -> impl IntoIterator<Item = Proof<'static, H, C, NOTE_SIZE>> {
    let mut proofs = Vec::new();
    let mut stack = Vec::new();
    stack.push((root, Bytes::new()));

    while let Some((node, partial_proof)) = stack.pop() {
        match node {
            Node::Leaf(leaf) => {
                let mut proof = BytesMut::from(partial_proof);
                proof.extend_from_slice(leaf.chunk.output().as_blob().bytes());
                proof.extend_from_slice(&leaf.note);
                proofs.push(Proof::new(
                    leaf.chunk.offset().clone(),
                    proof.freeze().into(),
                ))
            }
            Node::Branch(branch) => {
                let mut partial_proof = BytesMut::from(partial_proof);
                partial_proof.extend_from_slice(branch.left.id().as_slice());
                partial_proof.extend_from_slice(branch.right.id().as_slice());
                partial_proof.extend_from_slice(&branch.note);
                let partial_proof = partial_proof.freeze();

                stack.push((&branch.left, partial_proof.clone()));
                stack.push((&branch.right, partial_proof));
            }
        }
    }

    proofs
}

pub type DefaultProof<'a> = Proof<'a, Sha256, DefaultChunker, 32>;

#[derive_where(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> {
    offset: Range<u64>,
    proof: Blob<'a>,
    _phantom: PhantomData<(H, C)>,
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> AsBlob for Proof<'a, H, C, NOTE_SIZE> {
    fn as_blob(&self) -> Blob<'_> {
        self.proof.as_blob()
    }
}

impl<'a, H: Hasher, C: Chunker, const NOTE_SIZE: usize> Proof<'a, H, C, NOTE_SIZE> {
    // todo: should not be public
    pub fn new(offset: Range<u64>, proof: Blob<'a>) -> Self {
        Self {
            offset,
            proof,
            _phantom: PhantomData,
        }
    }

    pub fn offset(&self) -> &Range<u64> {
        &self.offset
    }
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::chunking::{ChunkerExt, DefaultChunker, MaybeOwnedChunk};
    use crate::crypto::merkle::DefaultMerkleTree;
    use std::io::Cursor;

    static ONE_MB: &'static [u8] = include_bytes!("../../testdata/1mb.bin");
    static REBAR3: &'static [u8] = include_bytes!("../../testdata/rebar3");
    static TX_EVEN_DATA: &'static [u8] =
        include_bytes!("../../testdata/OX63odH91fXS4hN506rYC_WUo8mWC5M3xuBymLhSKSw.data");
    static TX_ODD_DATA: &'static [u8] =
        include_bytes!("../../testdata/trtu91u1kRVDrZI6WvWVxU3uvEjJRZcls2WSZvYJyBc.data");

    #[test]
    fn merkle_tree_builder() -> anyhow::Result<()> {
        let tree = DefaultMerkleTree::from_iter(
            DefaultChunker::new().single_input(&mut Cursor::new(ONE_MB)),
        );

        let expected_root_id = [
            13, 66, 76, 111, 151, 198, 191, 18, 129, 188, 244, 243, 122, 39, 159, 246, 73, 77, 231,
            100, 200, 2, 138, 245, 233, 31, 171, 188, 172, 188, 68, 16,
        ];

        assert_eq!(tree.root().as_slice(), expected_root_id);
        assert_eq!(tree.num_chunks(), 8);
        assert_eq!(*tree.offset(), 0..1901762);
        assert_eq!(tree.proofs.len(), tree.num_chunks());
        assert_eq!(tree.proofs.gaps(&tree.root.offset()).count(), 0);

        Ok(())
    }

    #[test]
    fn merkle_tree_builder_even() -> anyhow::Result<()> {
        let tree = DefaultMerkleTree::from_iter(
            DefaultChunker::new().single_input(&mut Cursor::new(TX_EVEN_DATA)),
        );

        assert_eq!(
            tree.root().to_base64(),
            "Q7ug4JF3yjKW4COQ7Aqyr6zJW0seFn4ue5XRMxygsSU"
        );

        assert_eq!(*tree.offset(), 0..330871);
        assert_eq!(tree.num_chunks(), 2);
        assert_eq!(tree.proofs.len(), tree.num_chunks());
        assert_eq!(tree.proofs.gaps(&tree.root.offset()).count(), 0);

        Ok(())
    }

    #[test]
    fn merkle_tree_builder_odd() -> anyhow::Result<()> {
        let tree = DefaultMerkleTree::from_iter(
            DefaultChunker::new().single_input(&mut Cursor::new(TX_ODD_DATA)),
        );

        assert_eq!(
            tree.root().to_base64(),
            "ikHHDmOhqnZ5qsNZ7SOoofuaG66A5yRLsTvacad2NMg"
        );

        assert_eq!(*tree.offset(), 0..683821);
        assert_eq!(tree.num_chunks(), 3);
        assert_eq!(tree.proofs.len(), tree.num_chunks());
        assert_eq!(tree.proofs.gaps(&tree.root.offset()).count(), 0);

        Ok(())
    }

    #[test]
    fn small_final_chunk() -> anyhow::Result<()> {
        let data = vec![0; 256 * 1024 + 1];
        let expected = "br1Vtl3TS_NGWdHmYqBh3-MxrlckoluHCZGmUZk-dJc";

        let tree = DefaultMerkleTree::from_iter(
            DefaultChunker::new().single_input(&mut Cursor::new(&data)),
        );

        assert_eq!(tree.root().to_base64(), expected);
        assert_eq!(tree.num_chunks(), 2);
        assert_eq!(*tree.offset(), 0..data.len() as u64);
        assert_eq!(tree.proofs.len(), tree.num_chunks());
        assert_eq!(tree.proofs.gaps(&tree.root.offset()).count(), 0);

        Ok(())
    }

    #[test]
    fn empty_tree() -> anyhow::Result<()> {
        let empty_tree =
            DefaultMerkleTree::from_iter(DefaultChunker::new().single_input(&mut Cursor::new(&[])));
        assert_eq!(*empty_tree.offset(), 0..0);
        assert_eq!(empty_tree.num_chunks(), 0);

        // todo: check against reference implementation
        let expected = "U6L6PiJ70MHXS7ZQ-ctkdhVoZFBsdbFCyqZDfdW6k-s";

        assert_eq!(empty_tree.root().to_base64(), expected);
        assert_eq!(empty_tree.proofs.len(), empty_tree.num_chunks());
        assert_eq!(empty_tree.proofs.gaps(&empty_tree.root.offset()).count(), 0);

        Ok(())
    }

    #[test]
    fn test_valid_root() -> anyhow::Result<()> {
        let tree = DefaultMerkleTree::from_iter(
            DefaultChunker::new().single_input(&mut Cursor::new(REBAR3)),
        );

        assert_eq!(
            tree.root().to_base64(),
            "t-GCOnjPWxdox950JsrFMu3nzOE4RktXpMcIlkqSUTw"
        );
        Ok(())
    }

    #[test]
    fn generate_proof() -> anyhow::Result<()> {
        let tree = DefaultMerkleTree::from_iter(
            DefaultChunker::new().single_input(&mut Cursor::new(REBAR3)),
        );

        assert_eq!(tree.proofs.len(), tree.num_chunks());
        assert_eq!(tree.proofs.gaps(&tree.root.offset()).count(), 0);
        assert_eq!(
            tree.proof(0).unwrap().proof.to_base64(),
            "7EAC9FsACQRwe4oIzu7Mza9KjgWKT4toYxDYGjWrCdp0QgsrYS6AueMJ_rM6ZEGslGqjUekzD3WSe7B5_fwipgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAnH6dASdQCigcL43lp0QclqBaSncF4TspuvxoFbn2L18EXpQrP1wkbwdIjSSWQQRt_F31yNvxtc09KkPFtzMKAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAIHiHU9QwOImFzjqSlfxkJJCtSbAox6TbbFhQvlEapSgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAA"
        );

        Ok(())
    }

    #[test]
    fn verify_chunks() -> anyhow::Result<()> {
        let chunks = DefaultChunker::new().single_input(&mut Cursor::new(ONE_MB));
        let tree = DefaultMerkleTree::from_iter(chunks.iter().map(|c| MaybeOwnedChunk::from(c)));
        let root = tree.root();

        for chunk in &chunks {
            let proof = tree.proof(chunk.offset().start).unwrap();
            root.authenticate_chunk(chunk, proof)?;
        }

        Ok(())
    }
}
