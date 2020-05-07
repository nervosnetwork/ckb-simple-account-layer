#[macro_use]
extern crate derive_more;

mod smt;
mod vm;

pub use smt::CkbBlake2bHasher;

use crate::{
    smt::{generate_proof, Proof},
    vm::TreeSyscalls,
};
use bytes::Bytes;
use ckb_types::packed::OutPoint;
use ckb_vm::{
    machine::asm::{AsmCoreMachine, AsmMachine},
    DefaultMachineBuilder,
};
use sparse_merkle_tree::{
    traits::{Hasher, Store},
    SparseMerkleTree, H256,
};
use std::collections::HashMap;
use std::error::Error as StdError;

#[derive(Debug, PartialEq, Clone, Copy, Eq, Display)]
pub enum Error {
    #[display(fmt = "invalid response code {}", "_0")]
    InvalidResponseCode(i8),
}

impl StdError for Error {}

#[derive(Debug, PartialEq, Clone, Eq, Default)]
pub struct Config {
    pub validator: Bytes,
    pub generator: Bytes,
    pub validator_outpoint: OutPoint,
}

#[derive(Debug, PartialEq, Clone, Eq, Default)]
pub struct RunResult {
    pub read_values: HashMap<H256, H256>,
    pub write_values: HashMap<H256, H256>,
}

#[derive(Debug, PartialEq, Clone, Eq, Default)]
pub struct RunProofResult {
    /// Pairs of values in the old tree that is read by the program
    pub read_values: Vec<(H256, H256)>,
    /// Proof of read_values
    pub read_proof: Bytes,
    /// Tuple of values that is written by the program. Order of items is
    /// key, old value, new value
    pub write_values: Vec<(H256, H256, H256)>,
    /// Proof of all old values in write_values in the old tree. This proof
    /// Can also be used together with new values in write_values to calculate
    /// new root hash
    pub write_old_proof: Bytes,
}

pub fn run<H: Hasher + Default, S: Store<H256>>(
    config: &Config,
    tree: &SparseMerkleTree<H, H256, S>,
    program: &Bytes,
) -> Result<RunResult, Box<dyn StdError>> {
    let mut result = RunResult::default();
    {
        let core_machine = Box::<AsmCoreMachine>::default();
        let machine_builder =
            DefaultMachineBuilder::new(core_machine).syscall(Box::new(TreeSyscalls {
                tree,
                result: &mut result,
            }));
        let mut machine = AsmMachine::new(machine_builder.build(), None);
        let program_name = Bytes::from_static(b"generator");
        let program_length_bytes = (program.len() as u32).to_le_bytes()[..].to_vec();
        let program_length = Bytes::from(program_length_bytes);
        machine.load_program(
            &config.generator,
            &[program_name, program_length, program.clone()],
        )?;
        let code = machine.run()?;
        if code != 0 {
            return Err(Error::InvalidResponseCode(code).into());
        }
    }
    Ok(result)
}

pub fn run_and_update_tree<H: Hasher + Default, S: Store<H256>>(
    config: &Config,
    tree: &mut SparseMerkleTree<H, H256, S>,
    program: &Bytes,
) -> Result<RunProofResult, Box<dyn StdError>> {
    let RunResult {
        read_values,
        write_values,
    } = run(config, tree, program)?;
    let Proof {
        pairs: read_pairs,
        proof: read_proof,
    } = generate_proof(tree, &read_values)?;
    let mut write_old_values = HashMap::default();
    for key in write_values.keys() {
        write_old_values.insert(*key, tree.get(key)?);
    }
    let Proof {
        pairs: write_pairs,
        proof: write_old_proof,
    } = generate_proof(tree, &write_old_values)?;
    let write_tuples = write_pairs
        .into_iter()
        .map(|(key, old_value)| (key, old_value, *write_values.get(&key).unwrap()))
        .collect();
    for (key, value) in &write_values {
        tree.update(*key, *value)?;
    }
    Ok(RunProofResult {
        read_values: read_pairs,
        read_proof,
        write_values: write_tuples,
        write_old_proof,
    })
}
