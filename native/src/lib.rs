#[macro_use]
extern crate derive_more;

use blake2b_rs::{Blake2b, Blake2bBuilder};
use bytes::Bytes;
use ckb_types::packed::OutPoint;
use ckb_vm::{
    machine::asm::{AsmCoreMachine, AsmMachine},
    registers::{A0, A1, A7},
    DefaultMachineBuilder, Error as VMError, Memory, Register, SupportMachine, Syscalls,
};
use sparse_merkle_tree::{
    traits::{Hasher, Store},
    SparseMerkleTree, H256,
};
use std::error::Error as StdError;

#[derive(Debug, PartialEq, Clone, Copy, Eq, Display)]
pub enum Error {
    #[display(fmt = "invalid response code {}", "_0")]
    InvalidResponseCode(i8),
}

impl StdError for Error {}

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

pub struct Config {
    pub validator: Bytes,
    pub generator: Bytes,
    pub validator_outpoint: OutPoint,
}

struct TreeSyscalls<'a, H: Hasher + Default, S: Store<H256>> {
    tree: &'a mut SparseMerkleTree<H, H256, S>,
}

fn load_data<Mac: SupportMachine>(machine: &mut Mac, address: u64) -> Result<H256, VMError> {
    let mut data = [0u8; 32];
    for (i, c) in data.iter_mut().enumerate() {
        *c = machine
            .memory_mut()
            .load8(&Mac::REG::from_u64(address).overflowing_add(&Mac::REG::from_u64(i as u64)))?
            .to_u8();
    }
    Ok(H256::from(data))
}

fn store_data<Mac: SupportMachine>(
    machine: &mut Mac,
    address: u64,
    data: &H256,
) -> Result<(), VMError> {
    machine.memory_mut().store_bytes(address, data.as_slice())
}

impl<'a, H: Hasher + Default, S: Store<H256>, Mac: SupportMachine> Syscalls<Mac>
    for TreeSyscalls<'a, H, S>
{
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        let code = machine.registers()[A7].to_u64();
        match code {
            3073 => {
                let key_address = machine.registers()[A0].to_u64();
                let key = load_data(machine, key_address)?;
                let value_address = machine.registers()[A1].to_u64();
                let value = load_data(machine, value_address)?;
                self.tree
                    .update(key, value)
                    .map_err(|_| VMError::Unexpected)?;
                machine.set_register(A0, Mac::REG::from_u64(0));
                Ok(true)
            }
            3074 => {
                let key_address = machine.registers()[A0].to_u64();
                let key = load_data(machine, key_address)?;
                let value_address = machine.registers()[A1].to_u64();
                let value = self.tree.get(&key).map_err(|_| VMError::Unexpected)?;
                store_data(machine, value_address, &value)?;
                machine.set_register(A0, Mac::REG::from_u64(0));
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

pub fn run<H: Hasher + Default, S: Store<H256>>(
    config: &Config,
    tree: &mut SparseMerkleTree<H, H256, S>,
    program: &Bytes,
) -> Result<(), Box<dyn StdError>> {
    let core_machine = Box::<AsmCoreMachine>::default();
    // TODO: generator syscalls
    let machine_builder =
        DefaultMachineBuilder::new(core_machine).syscall(Box::new(TreeSyscalls { tree }));
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
    Ok(())
}
