use blake2b_rs::{Blake2b, Blake2bBuilder};
use bytes::Bytes;
use sparse_merkle_tree::{
    traits::{Hasher, Store},
    SparseMerkleTree, H256,
};
use std::collections::HashMap;
use std::error::Error as StdError;

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

pub(crate) fn generate_proof<H: Hasher + Default, S: Store<H256>>(
    tree: &SparseMerkleTree<H, H256, S>,
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
