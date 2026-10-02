//! Merkle tree implementation for STM

mod commitment;
mod error;
mod leaf;
mod path;
mod tree;

pub use commitment::*;
pub use error::*;
pub use leaf::*;
pub use path::*;
pub use tree::*;

use digest::Digest;

/// Digest of a leaf, preceded by its leaf type's leaf tag.
fn hash_leaf<D: Digest, L: MerkleTreeLeaf>(leaf: &L) -> Vec<u8> {
    D::new()
        .chain_update(L::leaf_domain_separation_tag())
        .chain_update(leaf.as_bytes_for_merkle_tree())
        .finalize()
        .to_vec()
}

/// Digest of an internal node from its two children, without any domain separation tag.
fn hash_node<D: Digest>(left: &[u8], right: &[u8]) -> Vec<u8> {
    D::new().chain_update(left).chain_update(right).finalize().to_vec()
}

// ---------------------------------------------------------------------
// Heap Helpers
// ---------------------------------------------------------------------
fn parent(i: usize) -> usize {
    assert!(i > 0, "The root node does not have a parent");
    (i - 1) / 2
}

fn left_child(i: usize) -> usize {
    (2 * i) + 1
}

fn right_child(i: usize) -> usize {
    (2 * i) + 2
}

fn sibling(i: usize) -> usize {
    assert!(i > 0, "The root node does not have a sibling");
    // In the heap representation, the left sibling is always odd
    // And the right sibling is the next node
    // We're assuming that the heap is complete
    if i % 2 == 1 { i + 1 } else { i - 1 }
}
