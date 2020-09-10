use bytes::Bytes;
use ckb_simple_account_layer::{CkbSimpleAccount, ClearStore, Config};
use ckb_types::{
    core::ScriptHashType,
    packed::{OutPoint, Script, Uint32},
    prelude::*,
};
use neon::prelude::*;
use sparse_merkle_tree::{
    default_store::DefaultStore,
    error::Error as SmtError,
    traits::Store,
    tree::{BranchNode, LeafNode},
    SparseMerkleTree, H256,
};
use std::error::Error as StdError;
use std::fmt;
#[derive(Debug)]
pub enum Error {
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
#[derive(Default)]
pub struct DefaultStoreWrapper(DefaultStore<H256>);

impl Store<H256> for DefaultStoreWrapper {
    fn get_branch(&self, node: &H256) -> Result<Option<BranchNode>, SmtError> {
        self.0.get_branch(node)
    }
    fn get_leaf(&self, leaf_hash: &H256) -> Result<Option<LeafNode<H256>>, SmtError> {
        self.0.get_leaf(leaf_hash)
    }
    fn insert_branch(&mut self, node: H256, branch: BranchNode) -> Result<(), SmtError> {
        self.0.insert_branch(node, branch)
    }
    fn insert_leaf(&mut self, leaf_hash: H256, leaf: LeafNode<H256>) -> Result<(), SmtError> {
        self.0.insert_leaf(leaf_hash, leaf)
    }
    fn remove_branch(&mut self, node: &H256) -> Result<(), SmtError> {
        self.0.remove_branch(node)
    }
    fn remove_leaf(&mut self, leaf_hash: &H256) -> Result<(), SmtError> {
        self.0.remove_leaf(leaf_hash)
    }
}

impl ClearStore for DefaultStoreWrapper {
    fn clear_store(&mut self) -> Result<(), Box<dyn StdError>> {
        self.0.clear();
        Ok(())
    }
}

pub struct NativeCkbSimpleAccount(CkbSimpleAccount<DefaultStoreWrapper>);

declare_types! {
    pub class JsNativeCkbSimpleAccount for NativeCkbSimpleAccount {
        init(mut cx) {
            let js_config = cx.argument::<JsObject>(0)?;
            // extract config properties and convert to rust type
            // 1. validator
            let js_validator = js_config.get(&mut cx, "validator")?.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
            let validator_slice = cx.borrow(&js_validator, |data| { data.as_slice::<u8>().to_vec() });
            let validator = Bytes::from(validator_slice);
            // 2. generator
            let js_generator = js_config.get(&mut cx, "generator")?.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
            let generator_slice = cx.borrow(&js_generator, |data| { data.as_slice::<u8>().to_vec() });
            let generator = Bytes::from(generator_slice);
            // 3. validator_outpoint
            let js_validator_outpoint = js_config.get(&mut cx, "validator_outpoint")?.downcast::<JsObject>().or_throw(&mut cx)?;
            let js_tx_hash = js_validator_outpoint.get(&mut cx, "tx_hash")?.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
            let tx_hash_slice = cx.borrow(&js_tx_hash, |data| { data.as_slice::<u8>().to_vec() });
            let js_index = js_validator_outpoint.get(&mut cx, "index")?.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
            let index = cx.borrow(&js_index, |data| { data.as_slice::<u8>().to_vec() });
            let validator_outpoint = assemble_packed_validator_outpoint(&tx_hash_slice, Uint32::from_slice(&index).unwrap());
            if validator_outpoint.is_err() {
                return cx.throw_error(format!("Error assembling validator_outpoint: {:?}", validator_outpoint.unwrap_err()));
            }
            let validator_outpoint = validator_outpoint.unwrap();
            // 4. type_script
            let js_type_script = js_config.get(&mut cx, "type_script")?.downcast::<JsObject>().or_throw(&mut cx)?;
            let js_code_hash = js_type_script.get(&mut cx, "code_hash")?.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
            let code_hash = cx.borrow(&js_code_hash, |data| { data.as_slice::<u8>().to_vec() });
            let js_args = js_type_script.get(&mut cx, "args")?.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
            let args = cx.borrow(&js_args, |data| { data.as_slice::<u8>().to_vec() });
            let js_hash_type = js_type_script.get(&mut cx, "hash_type")?.downcast::<JsNumber>().or_throw(&mut cx)?.value();
            let type_script =  assemble_packed_script(&code_hash, js_hash_type, &args);
            if type_script.is_err() {
                return cx.throw_error(format!("Error assembling type_script: {:?}", type_script.unwrap_err()));
            }
            let type_script = type_script.unwrap();
            // 5. lock_script
            let js_lock_script = js_config.get(&mut cx, "lock_script")?;
            let lock_script = if js_lock_script.is_a::<JsObject>() {
                let js_lock_script = js_lock_script.downcast::<JsObject>().or_throw(&mut cx)?;
                let js_code_hash = js_lock_script.get(&mut cx, "code_hash")?.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
                let code_hash = cx.borrow(&js_code_hash, |data| { data.as_slice::<u8>().to_vec() });
                let js_args = js_lock_script.get(&mut cx, "args")?.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
                let args = cx.borrow(&js_args, |data| { data.as_slice::<u8>().to_vec() });
                let js_hash_type = js_lock_script.get(&mut cx, "hash_type")?.downcast::<JsNumber>().or_throw(&mut cx)?.value();
                let lock_script =  assemble_packed_script(&code_hash, js_hash_type, &args);
                if lock_script.is_err() {
                    return cx.throw_error(format!("Error assembling lock_script: {:?}", lock_script.unwrap_err()));
                }
                let lock_script = lock_script.unwrap();
                Some(lock_script)
            } else {
                None
            };
            // 6. capacity
            let capacity = js_config.get(&mut cx, "capacity")?.downcast::<JsNumber>().or_throw(&mut cx)?.value() as u64;
            let config = Config { validator: validator, generator: generator, validator_outpoint: validator_outpoint, type_script: type_script, lock_script: lock_script, capacity: capacity };
            let ckb_simple_account = CkbSimpleAccount::empty(config);
            Ok(NativeCkbSimpleAccount(ckb_simple_account))
        }
    }
}

fn assemble_packed_validator_outpoint(tx_hash: &[u8], index: Uint32) -> Result<OutPoint, Error> {
    let tx_hash = if tx_hash.len() == 32 {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&tx_hash[..]);
        buf.pack()
    } else {
        return Err(Error::Other("Invalid code hash length!".to_string()));
    };
    return Ok(OutPoint::new_builder()
        .tx_hash(tx_hash)
        .index(index)
        .build());
}

fn assemble_packed_script(code_hash: &[u8], hash_type: f64, args: &[u8]) -> Result<Script, Error> {
    let code_hash = if code_hash.len() == 32 {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&code_hash[0..32]);
        buf.pack()
    } else {
        return Err(Error::Other("Invalid code hash length!".to_string()));
    };
    let hash_type = if hash_type as u32 == 1 {
        ScriptHashType::Type
    } else {
        ScriptHashType::Data
    }
    .into();
    let args = args.pack();
    let script = Script::new_builder()
        .code_hash(code_hash)
        .hash_type(hash_type)
        .args(args)
        .build();
    Ok(script)
}

register_module!(mut cx, {
    cx.export_class::<JsNativeCkbSimpleAccount>("CkbSimpleAccount")?;
    Ok(())
});
