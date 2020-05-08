use blake2b_rs::{Blake2b, Blake2bBuilder};
use bytes::Bytes;
use sparse_merkle_tree::{
    error::Error as SMTError,
    traits::{Hasher, Store},
    tree::{BranchNode, LeafNode},
    SparseMerkleTree, H256,
};
use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;

pub trait ClearStore {
    fn clear_store(&mut self) -> Result<(), Box<dyn StdError>>;
}

pub struct CkbBlake2bHasher(Blake2b);

impl Default for CkbBlake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2bBuilder::new(32)
            .personal(b"ckb-default-hash")
            .build();
        CkbBlake2bHasher(blake2b)
    }
}

impl Hasher for CkbBlake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
}

pub(crate) struct Proof {
    pub(crate) pairs: Vec<(H256, H256)>,
    pub(crate) proof: Bytes,
}

pub(crate) fn generate_proof<S: Store<H256>>(
    tree: &SparseMerkleTree<CkbBlake2bHasher, H256, S>,
    values: &HashMap<H256, H256>,
) -> Result<Proof, Box<dyn StdError>> {
    let mut pairs: Vec<(H256, H256)> = values.iter().map(|(k, v)| (*k, *v)).collect();
    pairs.sort_unstable_by_key(|(k, _)| *k);
    let keys: Vec<H256> = pairs.iter().map(|(k, _)| *k).collect();
    let proof: Bytes = if keys.is_empty() {
        Vec::new().into()
    } else {
        tree.merkle_proof(keys)?.compile(pairs.clone())?.0.into()
    };
    Ok(Proof { pairs, proof })
}

pub(crate) struct WrappedStore<'a, S: Store<H256>> {
    store: &'a S,
    branches_map: HashMap<H256, BranchNode>,
    leaves_map: HashMap<H256, LeafNode<H256>>,
    deleted_branches: HashSet<H256>,
    deleted_leaves: HashSet<H256>,
}

impl<'a, S: Store<H256>> WrappedStore<'a, S> {
    pub fn new(store: &'a S) -> Self {
        WrappedStore {
            store,
            branches_map: HashMap::default(),
            leaves_map: HashMap::default(),
            deleted_branches: HashSet::default(),
            deleted_leaves: HashSet::default(),
        }
    }
}

impl<'a, S: Store<H256>> Store<H256> for WrappedStore<'a, S> {
    fn get_branch(&self, node: &H256) -> Result<Option<BranchNode>, SMTError> {
        if self.deleted_branches.contains(&node) {
            return Ok(None);
        }
        match self.branches_map.get(node) {
            Some(value) => Ok(Some(value.clone())),
            None => self.store.get_branch(node),
        }
    }
    fn get_leaf(&self, leaf_hash: &H256) -> Result<Option<LeafNode<H256>>, SMTError> {
        if self.deleted_leaves.contains(&leaf_hash) {
            return Ok(None);
        }
        match self.leaves_map.get(leaf_hash) {
            Some(value) => Ok(Some(value.clone())),
            None => self.store.get_leaf(leaf_hash),
        }
    }
    fn insert_branch(&mut self, node: H256, branch: BranchNode) -> Result<(), SMTError> {
        self.deleted_branches.remove(&node);
        self.branches_map.insert(node, branch);
        Ok(())
    }
    fn insert_leaf(&mut self, leaf_hash: H256, leaf: LeafNode<H256>) -> Result<(), SMTError> {
        self.deleted_leaves.remove(&leaf_hash);
        self.leaves_map.insert(leaf_hash, leaf);
        Ok(())
    }
    fn remove_branch(&mut self, node: &H256) -> Result<(), SMTError> {
        self.deleted_branches.insert(node.clone());
        self.branches_map.remove(node);
        Ok(())
    }
    fn remove_leaf(&mut self, leaf_hash: &H256) -> Result<(), SMTError> {
        self.deleted_leaves.insert(leaf_hash.clone());
        self.leaves_map.remove(leaf_hash);
        Ok(())
    }
}
