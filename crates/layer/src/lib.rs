#[macro_use]
extern crate derive_more;

mod ckb;
mod smt;
mod vm;

pub use ckb::CkbSimpleAccount;
pub use smt::{CkbBlake2bHasher, ClearStore};

use crate::{
    smt::{generate_proof, Proof, WrappedStore},
    vm::{ExtraSyscalls, TreeSyscalls},
};
use bytes::Bytes;
use ckb_types::packed::{Byte32, OutPoint, Script};
use ckb_vm::{
    machine::asm::{AsmCoreMachine, AsmMachine},
    DefaultMachineBuilder, Error as VMError, SupportMachine,
};
use sparse_merkle_tree::{traits::Store, SparseMerkleTree, H256};
use std::collections::HashMap;
use std::error::Error as StdError;

#[derive(Debug, PartialEq, Clone, Eq, Display)]
pub enum Error {
    #[display(fmt = "invalid response code {}", "_0")]
    InvalidResponseCode(i8),
    #[display(fmt = "invalid transaction {:#x}: {}", "_0", "_1")]
    InvalidTransaction(Byte32, String),
    #[display(fmt = "other error: {}", "_0")]
    Other(String),
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}

impl StdError for Error {}

#[derive(Debug, PartialEq, Clone, Eq, Default)]
pub struct Config {
    pub validator: Bytes,
    pub generator: Bytes,
    pub validator_outpoint: OutPoint,
    pub type_script: Script,
    /// Lock script to use when creating the next cell. Creation would fail in
    /// initial cell creation when this field is missing. Updation, however, would
    /// automatically used the spent cell's lock script when this field is missing.
    pub lock_script: Option<Script>,
    /// Initial capacity used to create the first cell
    pub capacity: u64,
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

/// A context to run the program
pub trait RunContext<Mac: SupportMachine> {
    /// Handle extra syscalls
    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError>;
}
/// A dummy RunContext do nothing
pub struct DefaultRunContext {}

impl<Mac: SupportMachine> RunContext<Mac> for DefaultRunContext {
    fn ecall(&mut self, _machine: &mut Mac) -> Result<bool, VMError> {
        Ok(false)
    }
}

pub fn run_with_context<S: Store<H256>, C: RunContext<Box<AsmCoreMachine>>>(
    config: &Config,
    tree: &SparseMerkleTree<CkbBlake2bHasher, H256, S>,
    program: &Bytes,
    context: &mut C,
) -> Result<RunResult, Box<dyn StdError>> {
    let mut result = RunResult::default();
    {
        let core_machine = Box::<AsmCoreMachine>::default();
        let machine_builder = DefaultMachineBuilder::new(core_machine)
            .syscall(Box::new(ExtraSyscalls::new(context)))
            .syscall(Box::new(TreeSyscalls {
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

pub fn run<S: Store<H256>>(
    config: &Config,
    tree: &SparseMerkleTree<CkbBlake2bHasher, H256, S>,
    program: &Bytes,
) -> Result<RunResult, Box<dyn StdError>> {
    let mut ctx = DefaultRunContext {};
    run_with_context(config, tree, program, &mut ctx)
}

impl RunResult {
    pub fn generate_proof<S: Store<H256>>(
        &self,
        tree: &SparseMerkleTree<CkbBlake2bHasher, H256, S>,
    ) -> Result<RunProofResult, Box<dyn StdError>> {
        let read_values = &self.read_values;
        let write_values = &self.write_values;
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
        Ok(RunProofResult {
            read_values: read_pairs,
            read_proof,
            write_values: write_tuples,
            write_old_proof,
        })
    }

    // After this method returns successfully, the tree will be reverted to original value,
    // we only mark tree as mutable to make Rust happy.
    pub fn committed_root_hash<S: Store<H256>>(
        &self,
        tree: &SparseMerkleTree<CkbBlake2bHasher, H256, S>,
    ) -> Result<H256, Box<dyn StdError>> {
        let root_hash = *tree.root();
        let temp_store = WrappedStore::new(tree.store());
        let mut temp_tree: SparseMerkleTree<CkbBlake2bHasher, H256, WrappedStore<S>> =
            SparseMerkleTree::new(root_hash, temp_store);
        for (key, value) in &self.write_values {
            temp_tree.update(*key, *value)?;
        }
        Ok(*temp_tree.root())
    }

    pub fn commit<S: Store<H256>>(
        &self,
        tree: &mut SparseMerkleTree<CkbBlake2bHasher, H256, S>,
    ) -> Result<(), Box<dyn StdError>> {
        for (key, value) in &self.write_values {
            tree.update(*key, *value)?;
        }
        Ok(())
    }
}

impl RunProofResult {
    pub fn serialize_pure(&self) -> Result<Vec<u8>, Box<dyn StdError>> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(self.read_values.len() as u32).to_le_bytes()[..]);
        for (key, value) in &self.read_values {
            buffer.extend_from_slice(key.as_slice());
            buffer.extend_from_slice(value.as_slice());
        }
        if self.read_proof.len() > std::u32::MAX as usize {
            return Err("Read proof is too long!".into());
        }
        buffer.extend_from_slice(&(self.read_proof.len() as u32).to_le_bytes()[..]);
        buffer.extend_from_slice(&self.read_proof);
        if self.write_values.len() > std::u32::MAX as usize {
            return Err("Too many write values!".into());
        }
        buffer.extend_from_slice(&(self.write_values.len() as u32).to_le_bytes()[..]);
        for (_, old_value, _) in &self.write_values {
            buffer.extend_from_slice(old_value.as_slice());
        }
        if self.write_old_proof.len() > std::u32::MAX as usize {
            return Err("Write old proof is too long!".into());
        }
        buffer.extend_from_slice(&(self.write_old_proof.len() as u32).to_le_bytes()[..]);
        buffer.extend_from_slice(&self.write_old_proof);
        Ok(buffer)
    }

    pub fn serialize(&self, program: &Bytes) -> Result<Bytes, Box<dyn StdError>> {
        let mut buffer = Vec::new();
        if program.len() > std::u32::MAX as usize {
            return Err("Program is too long!".into());
        }
        buffer.extend_from_slice(&(program.len() as u32).to_le_bytes()[..]);
        buffer.extend_from_slice(program);
        if self.read_values.len() > std::u32::MAX as usize {
            return Err("Too many read values!".into());
        }
        buffer.extend(self.serialize_pure()?);
        Ok(buffer.into())
    }
}
