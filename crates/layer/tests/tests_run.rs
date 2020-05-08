use bytes::Bytes;
use ckb_simple_account_layer::{run, CkbBlake2bHasher, Config};
use hex::decode_to_slice;
use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree, H256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

fn read_file(name: &str) -> Bytes {
    let mut file =
        File::open(Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("testdata/{}", name)))
            .unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    Bytes::from(buffer)
}

fn build_dummy_config() -> Config {
    Config {
        validator: read_file("dummy_smt_validator"),
        generator: read_file("dummy_smt_generator"),
        ..Default::default()
    }
}

fn hex_to_h256(s: &str) -> H256 {
    let mut buffer = [0u8; 32];
    decode_to_slice(s, &mut buffer[..]).unwrap();
    buffer.into()
}

#[test]
pub fn test_run() {
    let mut tree: SparseMerkleTree<CkbBlake2bHasher, H256, DefaultStore<H256>> =
        SparseMerkleTree::default();
    tree.update(
        hex_to_h256("e8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5"),
        hex_to_h256("2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb"),
    )
    .unwrap();
    tree.update(
        hex_to_h256("381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b"),
        hex_to_h256("9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b"),
    )
    .unwrap();
    let old_root_hash = *tree.root();

    let mut program = Vec::new();
    program.push(0x52); // R
    program.extend_from_slice(
        hex_to_h256("e8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5").as_slice(),
    );
    program.extend_from_slice(
        hex_to_h256("2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb").as_slice(),
    );
    program.push(0x57); // W
    program.extend_from_slice(
        hex_to_h256("a9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a").as_slice(),
    );
    program.extend_from_slice(
        hex_to_h256("a939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82").as_slice(),
    );
    let program: Bytes = program.into();

    let config = build_dummy_config();
    let result = run(&config, &tree, &program).unwrap();

    let expected_root_hash =
        hex_to_h256("a4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
    let committed_root_hash = result.committed_root_hash(&tree).unwrap();
    assert_eq!(expected_root_hash, committed_root_hash);
    assert_eq!(&old_root_hash, tree.root());

    result.commit(&mut tree).unwrap();
    assert_eq!(&expected_root_hash, tree.root());
    let test_key = hex_to_h256("a9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
    let expected_test_value =
        hex_to_h256("a939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
    assert_eq!(expected_test_value, tree.get(&test_key).unwrap());
}

#[test]
pub fn test_run_read_written_value() {
    let tree: SparseMerkleTree<CkbBlake2bHasher, H256, DefaultStore<H256>> =
        SparseMerkleTree::default();

    let mut program = Vec::new();
    program.push(0x57); // W
    program.extend_from_slice(
        hex_to_h256("e8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5").as_slice(),
    );
    program.extend_from_slice(
        hex_to_h256("2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb").as_slice(),
    );
    program.push(0x52); // R
    program.extend_from_slice(
        hex_to_h256("e8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5").as_slice(),
    );
    program.extend_from_slice(
        hex_to_h256("2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb").as_slice(),
    );
    let program: Bytes = program.into();

    let config = build_dummy_config();
    run(&config, &tree, &program).unwrap();
}
