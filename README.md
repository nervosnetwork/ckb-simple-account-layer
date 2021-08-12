# ckb-simple-account-layer

**NOTE**: this repository is now only for legacy purposes, we have put together a more complete and secure design as a [Sparse Merkle Tree](https://github.com/nervosnetwork/sparse-merkle-tree) data structure. Please use the SMT implementation for all future projects.

A CKB account layer solution. This project consists of 3 parts:

* Minimal single header C parts for integrating an existing VM(whether it's JavaScript VM, Forth VM, EVM, Move VM, etc.) with an account based design. We are providing C source file since we are only defining a minimal integration layer, in this case, a C implementation provides maximum interoperability. Your VM can be written in any language supported by RISC-V, such as Rust.
* A Rust generator crate for interacting with the account layer on CKB, including querying account state, running VM programs to generate transactions containing latest state changes, etc.
* A nodejs binding on the Rust crate to provide the same functionality to JavaScript/TypeScript. We do have plan to deeply integrate ckb-simple-account-layer with [lumos](https://github.com/nervosnetwork/lumos).

To save on-chain storage requirement, currently we use a [SMT](https://github.com/jjyr/sparse-merkle-tree) based design: only the state root hash is stored in a cell on CKB. The current state values will be calculated and managed off-chain. Since all the validation logic will be executed on-chain, everyone can then verify current state values calculated from the series of transactions on chain. We are not jeopardizing the security of such a design in the decentralized manner.

One novelty of this account layer, is that it only requires the developers to provide a VM implementation running on RISC-V. The generator part also executes the same VM via a customized CKB VM instance to generate updates. This way we are minimizing the efforts taken to build an account layer on CKB.
