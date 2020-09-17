use crate::{RunContext, RunResult};
use ckb_vm::{
    registers::{A0, A1, A7},
    Error as VMError, Memory, Register, SupportMachine, Syscalls,
};
use sparse_merkle_tree::{
    traits::{Hasher, Store},
    SparseMerkleTree, H256,
};
use std::marker::PhantomData;

pub(crate) struct TreeSyscalls<'a, H: Hasher + Default, S: Store<H256>> {
    pub(crate) tree: &'a SparseMerkleTree<H, H256, S>,
    pub(crate) result: &'a mut RunResult,
}

fn load_h256<Mac: SupportMachine>(machine: &mut Mac, address: u64) -> Result<H256, VMError> {
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
            // insert
            3073 => {
                let key_address = machine.registers()[A0].to_u64();
                let key = load_h256(machine, key_address)?;
                let value_address = machine.registers()[A1].to_u64();
                let value = load_h256(machine, value_address)?;
                self.result.write_values.insert(key, value);
                machine.set_register(A0, Mac::REG::from_u64(0));
                Ok(true)
            }
            // fetch
            3074 => {
                let key_address = machine.registers()[A0].to_u64();
                let key = load_h256(machine, key_address)?;
                let value_address = machine.registers()[A1].to_u64();
                let value = match self.result.write_values.get(&key) {
                    Some(value) => *value,
                    None => {
                        let tree_value = self.tree.get(&key).map_err(|_| VMError::Unexpected)?;
                        if tree_value != H256::default() {
                            self.result.read_values.insert(key, tree_value);
                        }
                        tree_value
                    }
                };
                store_data(machine, value_address, &value)?;
                machine.set_register(A0, Mac::REG::from_u64(0));
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

pub(crate) struct ExtraSyscalls<'a, Mac, C> {
    pub(crate) context: &'a mut C,
    _mac: PhantomData<Mac>,
}

impl<'a, Mac: SupportMachine, C: RunContext<Mac>> ExtraSyscalls<'a, Mac, C> {
    pub(crate) fn new(context: &'a mut C) -> ExtraSyscalls<'a, Mac, C> {
        ExtraSyscalls {
            context,
            _mac: PhantomData,
        }
    }
}

impl<'a, Mac: SupportMachine, C: RunContext<Mac>> Syscalls<Mac> for ExtraSyscalls<'a, Mac, C> {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        self.context.ecall(machine)
    }
}
