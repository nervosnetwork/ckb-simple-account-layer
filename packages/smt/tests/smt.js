const test = require("ava");
const { Reader } = require("ckb-js-toolkit");
const SparseMerkleTree = require("../lib/smt.js");
const { randomBytes } = require("crypto");

test("update and fetch", t => {
  const data = [];
  for (let i = 0; i < 100; i++) {
    data.push({
      key: randomBytes(32).buffer,
      value: randomBytes(32).buffer
    });
  }

  const tree = new SparseMerkleTree();
  for (const { key, value } of data) {
    tree.update(key, value);
  }
  for (const { key, value } of data) {
    t.deepEqual(value, tree.fetch(key));
  }
});

test("update and prove", t => {
  const data = [];
  for (let i = 0; i < 100; i++) {
    data.push({
      key: randomBytes(32).buffer,
      value: randomBytes(32).buffer
    });
  }

  const tree = new SparseMerkleTree();
  for (const { key, value } of data) {
    tree.update(key, value);
  }
  for (const { key, value } of data) {
    const proof = tree.proof(key);
    t.true(tree.verify(key, value, proof));
  }
});

test("verify fixed data", t => {
  const tree = new SparseMerkleTree();
  tree.update("0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a",
              "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  t.deepEqual("0x5faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f372c1",
              new Reader(tree.currentRootHash()).serializeJson());
  tree.update("0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b",
              "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  t.deepEqual("0x991175c5349e2b0ea459aa541be38c14e2d238a67bb75129f0db00043b485445",
              new Reader(tree.currentRootHash()).serializeJson());
  tree.update("0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5",
              "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  t.deepEqual("0x35500363552cb7b3f51ac929b87c5b38e08555b2094bfb3b96b09271f7541f33",
              new Reader(tree.currentRootHash()).serializeJson());

  t.true(tree.verify(
    "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b",
    "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b",
    "0x0000000000000000000000000000000000000000000000000000000000000001b70128add4d8437d43aa590f4fbc4535907e420c84efe39258a61ce2e2132b33"
  ));
  t.true(tree.verify(
    "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a",
    "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82",
    "0x00000000000000000000000000000000000000000000000000000000000000033f2a0a59ba1081f2d343682b200a778191a4e5838a46774eda8e1ee201c6cb2fa9cee9b111fddde5dd16c6684715587ba628bf73407e03e9db579e41af0c09b8"
  ));
  t.true(tree.verify(
    "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5",
    "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb",
    "0x00000000000000000000000000000000000000000000000000000000000000035faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f372c1a9cee9b111fddde5dd16c6684715587ba628bf73407e03e9db579e41af0c09b8"
  ));
});
