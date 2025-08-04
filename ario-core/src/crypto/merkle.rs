use crate::blob::Blob;
use crate::chunking::Chunk;
use crate::crypto::hash::{Hashable, HashableExt, Hasher, Sha256, TypedDigest};
use crate::typed::{FromInner, Typed};
use bytemuck::TransparentWrapper;
use bytes::{Bytes, BytesMut};
use derive_where::derive_where;
use rangemap::RangeMap;
use std::ops::Range;

pub type DefaultMerkleRoot = MerkleRoot<Sha256, 32>;
pub type DefaultMerkleTree = MerkleTree<Sha256, 32>;

pub struct MerkleNodeIdKind;
pub type NodeId<H: Hasher, const NOTE_SIZE: usize> = TypedDigest<MerkleNodeIdKind, H>;

pub struct MerkleRootKind;
pub type MerkleRoot<H: Hasher, const NOTE_SIZE: usize> =
    Typed<MerkleRootKind, NodeId<H, NOTE_SIZE>>;

#[derive_where(Clone, Debug, PartialEq)]
pub struct MerkleTree<H: Hasher, const NOTE_SIZE: usize> {
    root: Node<H, NOTE_SIZE>,
    proofs: RangeMap<u64, Proof<'static>>,
}

impl<H: Hasher, const NOTE_SIZE: usize> MerkleTree<H, NOTE_SIZE> {
    pub fn root(&self) -> &MerkleRoot<H, NOTE_SIZE> {
        MerkleRoot::wrap_ref(self.root.id())
    }

    pub fn num_chunks(&self) -> usize {
        self.root.num_chunks()
    }

    pub fn offset(&self) -> &Range<u64> {
        self.root.offset()
    }

    pub fn proof(&self, offset: u64) -> Option<&Proof> {
        self.proofs.get(&offset)
    }
}

impl<H: Hasher, const NOTE_SIZE: usize> FromIterator<Chunk<H>> for MerkleTree<H, NOTE_SIZE> {
    fn from_iter<T: IntoIterator<Item = Chunk<H>>>(iter: T) -> Self {
        let mut nodes = iter
            .into_iter()
            .map(|c| Node::Leaf(Leaf::<H, NOTE_SIZE>::from_chunk(c)))
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
            generate_proofs::<H, NOTE_SIZE>(&root)
                .into_iter()
                .map(|p| (p.offset.clone(), p))
                .collect()
        };

        Self { root, proofs }
    }
}

#[derive_where(Clone, Debug, PartialEq)]
pub enum Node<H: Hasher, const NOTE_SIZE: usize> {
    Leaf(Leaf<H, NOTE_SIZE>),
    Branch(Branch<H, NOTE_SIZE>),
}

impl<H: Hasher, const NOTE_SIZE: usize> Node<H, NOTE_SIZE> {
    fn id(&self) -> &NodeId<H, NOTE_SIZE> {
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

    fn is_empty(&self) -> bool {
        self.num_chunks() == 0
    }
}

#[derive_where(Clone, Debug, PartialEq)]
pub struct Leaf<H: Hasher, const NOTE_SIZE: usize> {
    id: NodeId<H, NOTE_SIZE>,
    note: [u8; NOTE_SIZE],
    chunk: Chunk<H>,
}

impl<H: Hasher, const NOTE_SIZE: usize> Leaf<H, NOTE_SIZE> {
    fn from_chunk(chunk: Chunk<H>) -> Self {
        let note = to_note::<NOTE_SIZE>(chunk.offset().end);
        let mut id_hasher = H::new();
        chunk.data_hash().digest::<H>().feed(&mut id_hasher);
        note.digest::<H>().feed(&mut id_hasher);
        let id = id_hasher.finalize();
        Self {
            id: NodeId::from_inner(id),
            note,
            chunk,
        }
    }

    fn empty() -> Self {
        let empty_chunk = Chunk::new(H::new().finalize(), 0, 0);

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

#[derive_where(Clone, Debug, PartialEq)]
pub struct Branch<H: Hasher, const NOTE_SIZE: usize> {
    id: NodeId<H, NOTE_SIZE>,
    left: Box<Node<H, NOTE_SIZE>>,
    right: Box<Node<H, NOTE_SIZE>>,
    offset: Range<u64>, // Left child's min offset - Right child's max offset
    note: [u8; NOTE_SIZE],
}

impl<H: Hasher, const NOTE_SIZE: usize> Branch<H, NOTE_SIZE> {
    fn new(left: Node<H, NOTE_SIZE>, right: Node<H, NOTE_SIZE>) -> Self {
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
}

fn generate_proofs<H: Hasher, const NOTE_SIZE: usize>(
    root: &Node<H, NOTE_SIZE>,
) -> impl IntoIterator<Item = Proof<'static>> {
    let mut proofs = Vec::new();
    let mut stack = Vec::new();
    stack.push((root, Bytes::new()));

    while let Some((node, partial_proof)) = stack.pop() {
        match node {
            Node::Leaf(leaf) => {
                let mut proof = BytesMut::from(partial_proof);
                proof.extend_from_slice(leaf.chunk.data_hash().as_slice());
                proof.extend_from_slice(&leaf.note);
                proofs.push(Proof {
                    offset: leaf.chunk.offset().clone(),
                    proof: proof.freeze().into(),
                })
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<'a> {
    offset: Range<u64>,
    proof: Blob<'a>,
}

#[cfg(test)]
mod tests {
    use crate::base64::ToBase64;
    use crate::chunking::DefaultChunker;
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
        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(ONE_MB));
        let tree = DefaultMerkleTree::from_iter(chunker.finalize());

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
        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(TX_EVEN_DATA));
        let tree = DefaultMerkleTree::from_iter(chunker.finalize());

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
        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(TX_ODD_DATA));
        let tree = DefaultMerkleTree::from_iter(chunker.finalize());

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

        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(&data));
        let tree = DefaultMerkleTree::from_iter(chunker.finalize());

        assert_eq!(tree.root().to_base64(), expected);
        assert_eq!(tree.num_chunks(), 2);
        assert_eq!(*tree.offset(), 0..data.len() as u64);
        assert_eq!(tree.proofs.len(), tree.num_chunks());
        assert_eq!(tree.proofs.gaps(&tree.root.offset()).count(), 0);

        Ok(())
    }

    #[test]
    fn empty_tree() -> anyhow::Result<()> {
        let chunker = DefaultChunker::new();
        let empty_tree = DefaultMerkleTree::from_iter(chunker.finalize());
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
        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(REBAR3));
        let tree = DefaultMerkleTree::from_iter(chunker.finalize());

        assert_eq!(
            tree.root().to_base64(),
            "t-GCOnjPWxdox950JsrFMu3nzOE4RktXpMcIlkqSUTw"
        );
        Ok(())
    }

    #[test]
    fn generate_proof() -> anyhow::Result<()> {
        let mut chunker = DefaultChunker::new();
        chunker.update(&mut Cursor::new(REBAR3));
        let tree = DefaultMerkleTree::from_iter(chunker.finalize());

        assert_eq!(tree.proofs.len(), tree.num_chunks());
        assert_eq!(tree.proofs.gaps(&tree.root.offset()).count(), 0);
        assert_eq!(
            tree.proof(0).unwrap().proof.to_base64(),
            "7EAC9FsACQRwe4oIzu7Mza9KjgWKT4toYxDYGjWrCdp0QgsrYS6AueMJ_rM6ZEGslGqjUekzD3WSe7B5_fwipgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAnH6dASdQCigcL43lp0QclqBaSncF4TspuvxoFbn2L18EXpQrP1wkbwdIjSSWQQRt_F31yNvxtc09KkPFtzMKAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAIHiHU9QwOImFzjqSlfxkJJCtSbAox6TbbFhQvlEapSgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAA"
        );

        Ok(())
    }
}
