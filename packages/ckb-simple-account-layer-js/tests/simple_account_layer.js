const test = require("ava");
const { CkbSimpleAccount } = require("../lib");
const { readFile } = require("fs").promises;
const path = require("path");
const { normalizers } = require("ckb-js-toolkit");

test("require should work", (t) => {
  t.truthy(CkbSimpleAccount);
});

test("create a CkbSimpleAccount instance", async (t) => {
  const dummySmtGeneratorPath = path.join(__dirname, "/dummy_smt_generator");
  const dummySmtValidatorPath = path.join(__dirname, "/dummy_smt_validator");
  const generator_bin = await readFile(dummySmtGeneratorPath);
  const generator = toArrayBuffer(generator_bin);
  const validator_bin = await readFile(dummySmtValidatorPath);
  const validator = toArrayBuffer(validator_bin);
  const validator_outpoint = {
    tx_hash:
      "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c",
    index: 1,
  };
  const type_script = {
    code_hash:
      "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e",
    hash_type: "type",
    args: "0x",
  };
  const lock_script = {
    code_hash:
      "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    hash_type: "type",
    args: "0xda2910f58164f5bd0c5afaebf019f03dcecd026b",
  };
  const capacity = 100;
  const config = {
    validator: validator,
    generator: generator,
    validator_outpoint: normalizers.NormalizeOutPoint(validator_outpoint),
    type_script: normalizers.NormalizeScript(type_script),
    lock_script: normalizers.NormalizeScript(lock_script),
    capacity: capacity,
  };
  const _ckbSimpleAccount = new CkbSimpleAccount(config);
  t.pass();
});

function toArrayBuffer(buf) {
  var ab = new ArrayBuffer(buf.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return ab;
}
