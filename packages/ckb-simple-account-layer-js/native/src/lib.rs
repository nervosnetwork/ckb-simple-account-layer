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
    H256,
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

        method generate(mut cx) {
            let mut this = cx.this();
            let js_program = cx.argument::<JsArrayBuffer>(0)?;
            let program_slice = cx.borrow(&js_program, |data| { data.as_slice::<u8>().to_vec() });
            let program = Bytes::from(program_slice);
            let generate_result =
            cx.borrow_mut(&mut this, |data| { data.0.generate(&program) });
            match generate_result {
                Ok(tx) => {
                    println!("{}",tx);
                    // convert CKB Transaction to Js object
                    let js_transaction = JsObject::new(&mut cx);
                    let raw_tx = tx.raw();
                    // version
                    let version: u32 = raw_tx.version().unpack();
                    let js_version = cx.string(format!("{:#x}", version));
                    js_transaction.set(&mut cx, "version", js_version)?;
                    // cell_deps
                    let cell_deps = raw_tx.cell_deps();
                    let js_cell_deps = JsArray::new(&mut cx, cell_deps.len() as u32);
                    for i in 0..cell_deps.item_count() {
                        let cell_dep = cell_deps.get(i).unwrap();
                        // out_point
                        let out_point = cell_dep.out_point();
                        let js_out_point = JsObject::new(&mut cx);
                        // tx_hash
                        let tx_hash = out_point.tx_hash();
                        let js_tx_hash = cx.string(format!("{:#x}", tx_hash));
                        // index
                        let index = out_point.index();
                        let js_index = cx.string(format!("{:#x}", index));
                        js_out_point.set(&mut cx, "tx_hash", js_tx_hash)?;
                        js_out_point.set(&mut cx, "index", js_index)?;
                        // dep_type
                        let dep_type = cell_dep.dep_type();
                        let js_dep_type = cx.string(format!("{:#x}", dep_type.as_slice()[0]));
                        // cell_dep
                        let js_cell_dep = JsObject::new(&mut cx);
                        js_cell_dep.set(&mut cx, "out_point", js_out_point)?;
                        js_cell_dep.set(&mut cx, "dep_type", js_dep_type)?;
                        js_cell_deps.set(&mut cx, i as u32, js_cell_dep)?;
                    }
                    js_transaction.set(&mut cx, "cell_deps", js_cell_deps)?;
                    // header_deps
                    let header_deps = raw_tx.header_deps();
                    let js_header_deps = JsArray::new(&mut cx, header_deps.len() as u32);
                    for i in 0..header_deps.item_count() {
                        let header_dep = header_deps.get(i).unwrap();
                        let js_header_dep = cx.string(format!("{:#x}", header_dep));
                        js_header_deps.set(&mut cx, i as u32, js_header_dep)?;
                    }
                    js_transaction.set(&mut cx, "header_deps", js_header_deps)?;
                    // inputs
                    let inputs = raw_tx.inputs();
                    let js_inputs = JsArray::new(&mut cx, inputs.len() as u32);
                    for i in 0..inputs.item_count() {
                        let input = inputs.get(i).unwrap();
                        // since
                        let since = input.since();
                        let js_since = cx.string(format!("{:#x}", since));
                        // previous_output
                        let previous_output = input.previous_output();
                        // tx_hash
                        let tx_hash = previous_output.tx_hash();
                        let js_tx_hash = cx.string(format!("{:#x}", tx_hash));
                        // index
                        let index = previous_output.index();
                        let js_index = cx.string(format!("{:#x}", index));
                        let js_previous_output = JsObject::new(&mut cx);
                        js_previous_output.set(&mut cx, "tx_hash", js_tx_hash)?;
                        js_previous_output.set(&mut cx, "index", js_index)?;
                        // input
                        let js_input = JsObject::new(&mut cx);
                        js_input.set(&mut cx, "previous_output", js_previous_output)?;
                        js_input.set(&mut cx, "since", js_since)?;
                        js_inputs.set(&mut cx, i as u32, js_input)?;
                    }
                    js_transaction.set(&mut cx, "inputs", js_inputs)?;
                    // outputs
                    let outputs = raw_tx.outputs();
                    let js_outputs = JsArray::new(&mut cx, outputs.len() as u32);
                    for i in 0..outputs.item_count() {
                        let output = outputs.get(i).unwrap();
                        // capacity
                        let capacity = output.capacity();
                        let js_capacity = cx.string(format!("{:#x}", capacity));
                        // lock script
                        let lock_script = output.lock();
                        let code_hash = lock_script.code_hash();
                        let js_code_hash = cx.string(format!("{:#x}", code_hash));
                        let hash_type = lock_script.hash_type();
                        let js_hash_type = cx.string(format!("{:#x}", hash_type.as_slice()[0]));
                        let args = lock_script.args();
                        let js_args = cx.string(format!("{:#x}", args));
                        let js_lock_script = JsObject::new(&mut cx);
                        js_lock_script.set(&mut cx, "code_hash", js_code_hash)?;
                        js_lock_script.set(&mut cx, "hash_type", js_hash_type)?;
                        js_lock_script.set(&mut cx, "args", js_args)?;
                        // type script
                        let type_script_opt = output.type_();
                        let js_type_script = if type_script_opt.is_some() {
                            let type_script = type_script_opt.to_opt().unwrap();
                            let code_hash = type_script.code_hash();
                            let js_code_hash = cx.string(format!("{:#x}", code_hash));
                            let hash_type = type_script.hash_type();
                            let js_hash_type = cx.string(format!("{:#x}", hash_type.as_slice()[0]));
                            let args = type_script.args();
                            let js_args = cx.string(format!("{:#x}", args));
                            let js_type_script = JsObject::new(&mut cx);
                            js_type_script.set(&mut cx, "code_hash", js_code_hash)?;
                            js_type_script.set(&mut cx, "hash_type", js_hash_type)?;
                            js_type_script.set(&mut cx, "args", js_args)?;
                            js_type_script
                        } else {
                            //JsNull::new()
                            JsObject::new(&mut cx)
                        };
                        // output
                        let js_output = JsObject::new(&mut cx);
                        js_output.set(&mut cx, "capacity", js_capacity)?;
                        js_output.set(&mut cx, "lock", js_lock_script)?;
                        js_output.set(&mut cx, "type_", js_type_script)?;
                        js_outputs.set(&mut cx, i as u32, js_output)?;
                    }
                    js_transaction.set(&mut cx, "outputs", js_outputs)?;
                    // outputs_data
                    let outputs_data = raw_tx.outputs_data();
                    let js_outputs_data = JsArray::new(&mut cx, outputs_data.len() as u32);
                    for i in 0..outputs_data.item_count() {
                        let output_data = outputs_data.get(i).unwrap();
                        let js_output_data = cx.string(format!("{:#x}", output_data));
                        js_outputs_data.set(&mut cx, i as u32, js_output_data)?;
                    }
                    js_transaction.set(&mut cx, "outputs_data", js_outputs_data)?;
                    // witnesses, it will always be empty here
                    let js_witnesses = JsArray::new(&mut cx, 0);
                    js_transaction.set(&mut cx, "witnesses", js_witnesses)?;
                    Ok(js_transaction.upcast())
                },
                error => cx.throw_error(format!("Generate transaction from program failed: {:?}", error.unwrap_err())),
            }
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
