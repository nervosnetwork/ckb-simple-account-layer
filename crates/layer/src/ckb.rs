use crate::{run, smt::CkbBlake2bHasher, Config, Error};
use bytes::Bytes;
use ckb_types::{
    core::{DepType, TransactionBuilder, TransactionView},
    packed::{
        BytesOpt, CellDep, CellInput, CellOutput, OutPoint, ScriptOpt, Transaction,
        WitnessArgs,
    },
    prelude::*,
};
use sparse_merkle_tree::{traits::Store, SparseMerkleTree, H256};
use std::collections::HashMap;
use std::error::Error as StdError;

pub struct CkbSimpleAccount<S: Store<H256>> {
    pub config: Config,
    pub tree: SparseMerkleTree<CkbBlake2bHasher, H256, S>,
    pub last_cell: Option<(OutPoint, CellOutput, Bytes)>,
}

impl<S: Store<H256> + Default> CkbSimpleAccount<S> {
    pub fn empty(config: Config) -> Self {
        CkbSimpleAccount {
            config,
            tree: SparseMerkleTree::default(),
            last_cell: None,
        }
    }

    /// Given a list of transactions, this method tries to connect the transactions
    /// a chain based on consumed OutPoints, then it uses the chain of transactions
    /// to restore the underlying account.
    pub fn restore_from_transactions(
        config: Config,
        transactions: &[Transaction],
        consume_all_transactions: bool,
    ) -> Result<Self, Box<dyn StdError>> {
        let mut chain: Vec<(TransactionView, Option<OutPoint>)> = Vec::new();
        let mut spent_cells: HashMap<Vec<u8>, (TransactionView, Option<OutPoint>)> =
            HashMap::default();
        let mut created_cells: HashMap<Vec<u8>, TransactionView> = HashMap::default();
        for transaction in transactions {
            let view = transaction.clone().into_view();
            let outputs: Vec<(usize, CellOutput)> = view
                .outputs()
                .into_iter()
                .enumerate()
                .filter(|(_, o)| {
                    o.type_().is_some() && o.type_().to_opt().unwrap() == config.type_script
                })
                .collect();
            if outputs.len() > 1 {
                return Err(Error::InvalidTransaction(
                    view.hash(),
                    "Invalid number of outputs!".to_string(),
                )
                .into());
            }

            let tx_hash = view.hash();
            let entry = (
                view,
                outputs.get(0).map(|(i, _)| {
                    OutPoint::new_builder()
                        .tx_hash(tx_hash)
                        .index((*i as u32).pack())
                        .build()
                }),
            );
            if chain.is_empty() {
                chain.push(entry);
            } else {
                for input in entry.0.inputs() {
                    spent_cells.insert(input.previous_output().as_slice().to_vec(), entry.clone());
                }
                if entry.1.is_some() {
                    created_cells.insert(entry.1.unwrap().as_slice().to_vec(), entry.0);
                }

                loop {
                    let mut inserted = false;
                    for input in chain[0].0.inputs() {
                        if let Some(tx) =
                            created_cells.remove(&input.previous_output().as_slice().to_vec())
                        {
                            chain.insert(0, (tx, Some(input.previous_output())));
                            inserted = true;
                            break;
                        }
                    }
                    if !inserted {
                        break;
                    }
                }
                loop {
                    if let Some(op) = &chain[chain.len() - 1].1 {
                        if let Some(next_entry) = spent_cells.remove(&op.as_slice().to_vec()) {
                            chain.push(next_entry);
                            continue;
                        }
                    }
                    break;
                }
            }
        }
        if consume_all_transactions && chain.len() != transactions.len() {
            return Err("Not all transactions can be chained together!".into());
        }
        let mut account = CkbSimpleAccount::empty(config);
        for (view, _) in chain {
            account.advance(&view.data())?;
        }
        Ok(account)
    }
}

impl<S: Store<H256>> CkbSimpleAccount<S> {
    pub fn empty_with_tree(
        config: Config,
        tree: SparseMerkleTree<CkbBlake2bHasher, H256, S>,
    ) -> Self {
        CkbSimpleAccount {
            config,
            tree,
            last_cell: None,
        }
    }

    pub fn new(
        config: Config,
        tree: SparseMerkleTree<CkbBlake2bHasher, H256, S>,
        last_cell: (OutPoint, CellOutput, Bytes),
    ) -> Self {
        CkbSimpleAccount {
            config,
            tree,
            last_cell: Some(last_cell),
        }
    }

    /// Runs program with latest SMT tree, and generate a transaction skeleton that can
    /// be used to alter on-chain state. Notice this method does not take transaction
    /// fees into account, nor will it gather enough capacity in initial cell creation.
    /// So typically, you would want to start from the transaction skeleton generated here
    /// and modify the transaction. Due to the same reason, this method doesn't consider
    /// signature generation in inputs as well.
    pub fn generate(&self, program: &Bytes) -> Result<Transaction, Box<dyn StdError>> {
        let result = run(&self.config, &self.tree, program)?;
        let proof = result.generate_proof(&self.tree)?;
        let root_hash = result.committed_root_hash(&self.tree)?;
        let data = BytesOpt::new_builder()
            .set(Some(proof.serialize(program)?.pack()))
            .build();
        let mut witness_builder = WitnessArgs::new_builder();
        if self.last_cell.is_none() {
            witness_builder = witness_builder.output_type(data);
        } else {
            witness_builder = witness_builder.input_type(data);
        }
        let mut output_builder = CellOutput::new_builder()
            .type_(
                ScriptOpt::new_builder()
                    .set(Some(self.config.type_script.clone()))
                    .build(),
            )
            .capacity(if self.last_cell.is_none() {
                self.config.capacity.pack()
            } else {
                self.last_cell.as_ref().unwrap().1.capacity()
            });
        if self.config.lock_script.is_none() {
            if self.last_cell.is_none() {
                return Err("No valid lock script to use!".into());
            }
            output_builder = output_builder.lock(self.last_cell.as_ref().unwrap().1.lock());
        } else {
            output_builder = output_builder.lock(self.config.lock_script.clone().unwrap());
        }
        let mut transaction_builder = TransactionBuilder::default()
            .cell_dep(
                CellDep::new_builder()
                    .out_point(self.config.validator_outpoint.clone())
                    .dep_type(DepType::Code.into())
                    .build(),
            )
            .witness(witness_builder.build().as_bytes().pack())
            .output(output_builder.build())
            .output_data(Bytes::from(root_hash.as_slice().to_vec()).pack());
        if self.last_cell.is_some() {
            transaction_builder = transaction_builder.input(
                CellInput::new_builder()
                    .previous_output(self.last_cell.as_ref().unwrap().0.clone())
                    .build(),
            );
        }
        Ok(transaction_builder.build().data())
    }

    /// Updates internal SMT state based on provided transaction. Typically, the
    /// transaction provided here comes from a committed block on chain.
    pub fn advance(&mut self, transaction: &Transaction) -> Result<(), Box<dyn StdError>> {
        let view = transaction.clone().into_view();
        let mut outputs: Vec<(usize, (CellOutput, Bytes))> = view
            .outputs_with_data_iter()
            .enumerate()
            .filter(|(_, (o, _))| {
                o.type_().is_some() && o.type_().to_opt().unwrap() == self.config.type_script
            })
            .collect();
        if outputs.len() > 1 {
            return Err(Error::InvalidTransaction(
                view.hash(),
                "Invalid number of outputs!".to_string(),
            )
            .into());
        }
        if let Some((last_op, _, _)) = &self.last_cell {
            if view.input_pts_iter().all(|op| &op != last_op) {
                return Err(Error::InvalidTransaction(
                    view.hash(),
                    "Provided transaction does not consume last cell!".to_string(),
                )
                .into());
            }
        }
        if outputs.is_empty() {
            // Destroying action
            return Err("TODO: find a way to clean a full SMT tree".into());
        }
        let (index, (output, output_data)) = outputs.pop().unwrap();
        let witness = view.witnesses().get(index).ok_or_else(|| "Witness is missing!")?;
        let witness_args = WitnessArgs::from_slice(witness.as_slice()).map_err(|_| "Witness format is invalid!")?;
        let program = if self.last_cell.is_none() {
            witness_args.output_type()
        } else {
            witness_args.input_type()
        }.to_opt().ok_or_else(|| "Witness format is invalid!")?.raw_data();
        let result = run(&self.config, &self.tree, &program)?;
        let new_root_hash = result.committed_root_hash(&self.tree)?;
        if output_data.len() != 32 || output_data != new_root_hash.as_slice() {
            return Err("Invalid new root hash!".into());
        }
        result.commit(&mut self.tree)?;
        let out_point = OutPoint::new_builder().tx_hash(view.hash()).index((index as u32).pack()).build();
        self.last_cell = Some((out_point, output, output_data));
        Ok(())
    }
}
