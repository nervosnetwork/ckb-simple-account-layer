use crate::RunResult;
use ckb_vm::{
    registers::{A0, A1, A7},
    Error as VMError, Memory, Register, SupportMachine, Syscalls,
};
use sparse_merkle_tree::{
    traits::{Hasher, Store},
    SparseMerkleTree, H256,
};

pub(crate) struct VmSyscalls<'a, H: Hasher + Default, S: Store<H256>> {
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

fn load_data<Mac: SupportMachine>(
    machine: &mut Mac,
    address: u64,
    length: u32,
) -> Result<Vec<u8>, VMError> {
    let mut data = vec![0u8; length as usize];
    for (i, c) in data.iter_mut().enumerate() {
        *c = machine
            .memory_mut()
            .load8(&Mac::REG::from_u64(address).overflowing_add(&Mac::REG::from_u64(i as u64)))?
            .to_u8();
    }
    Ok(data)
}

fn store_data<Mac: SupportMachine>(
    machine: &mut Mac,
    address: u64,
    data: &H256,
) -> Result<(), VMError> {
    machine.memory_mut().store_bytes(address, data.as_slice())
}

impl<'a, H: Hasher + Default, S: Store<H256>, Mac: SupportMachine> Syscalls<Mac>
    for VmSyscalls<'a, H, S>
{
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        let code = machine.registers()[A7].to_u64();
        match code {
            3073 => {
                let key_address = machine.registers()[A0].to_u64();
                let key = load_h256(machine, key_address)?;
                let value_address = machine.registers()[A1].to_u64();
                let value = load_h256(machine, value_address)?;
                self.result.write_values.insert(key, value);
                machine.set_register(A0, Mac::REG::from_u64(0));
                Ok(true)
            }
            3074 => {
                let key_address = machine.registers()[A0].to_u64();
                let key = load_h256(machine, key_address)?;
                let value_address = machine.registers()[A1].to_u64();
                let value = match self.result.write_values.get(&key) {
                    Some(value) => *value,
                    None => {
                        let tree_value = self.tree.get(&key).map_err(|_| VMError::Unexpected)?;
                        self.result.read_values.insert(key, tree_value);
                        tree_value
                    }
                };
                store_data(machine, value_address, &value)?;
                machine.set_register(A0, Mac::REG::from_u64(0));
                Ok(true)
            }
            3075 => {
                let data_address = machine.registers()[A0].to_u64();
                let data_length = machine.registers()[A1].to_u32();
                let data = load_data(machine, data_address, data_length)?;
                self.result.return_data = data.into();
                Ok(true)
            }
            3076 => {
                let data_address = machine.registers()[A0].to_u64();
                let data_length = machine.registers()[A1].to_u32();
                let data = load_data(machine, data_address, data_length)?;
                self.result.logs.push(data.into());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
