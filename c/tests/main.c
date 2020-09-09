#include "utest.h"

void debug_print_hex(const char* prefix, const uint8_t* buf, size_t length) {
  printf("%s: ", prefix);
  for (size_t i = 0; i < length; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

/* hex2bin modified from
 * https://chromium.googlesource.com/chromium/deps/xz/+/77022065014d48cf51d83322264ab4836fd175ec/debug/hex2bin.c
 */
int getbin(int x) {
  if (x >= '0' && x <= '9') return x - '0';
  if (x >= 'A' && x <= 'F') return x - 'A' + 10;
  return x - 'a' + 10;
}

int hex2bin(uint8_t* buf, const char* src) {
  size_t length = strlen(src) / 2;
  if (src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) {
    src += 2;
    length--;
  }
  for (size_t i = 0; i < length; i++) {
    buf[i] = (getbin(src[i * 2]) << 4) | getbin(src[i * 2 + 1]);
  }
  return length;
}

#define CSAL_VALIDATOR_TYPE 1
#define CSAL_NO_VALIDATOR_SKELETON
#include "../validator.h"

UTEST(smt, verify1) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");

  int proof_length = hex2bin(
      proof,
      "0x4c50f85faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f372c1"
      "50fe3f2a0a59ba1081f2d343682b200a778191a4e5838a46774eda8e1ee201c6cb2f");

  csal_entry_t entries[8];
  csal_change_t changes;
  csal_change_init(&changes, entries, 32);
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);

  ASSERT_EQ(0, csal_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify2) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50f8a9cee9b111fddde5dd16c6684715587ba628bf73407e03e9db579e41af0c09b8"
      "50fe3f2a0a59ba1081f2d343682b200a778191a4e5838a46774eda8e1ee201c6cb2f");

  csal_entry_t entries[8];
  csal_change_t changes;
  csal_change_init(&changes, entries, 32);
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);

  ASSERT_EQ(0, csal_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify3) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50fe32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb511b97ea"
      "bf86");

  csal_entry_t entries[8];
  csal_change_t changes;
  csal_change_init(&changes, entries, 32);
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);

  ASSERT_EQ(0, csal_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_invalid_hash) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50fe32845309d34f132cd6f7ac6a7881962401adc35c19a18d4fffeb511b97ea"
      "bf86");

  csal_entry_t entries[8];
  csal_change_t changes;
  csal_change_init(&changes, entries, 32);
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);

  ASSERT_NE(0, csal_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_all_leaves_used) {}

UTEST(smt, verify_multi_2) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xaa84c1a9b237e29e78bf2c59539e0ab2aa4ddd727f1d43bda03cc37ca9c523ca");
  int proof_length = hex2bin(
      proof,
      "0x4c4c48f950fe32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb51"
      "1b97eabf86");

  csal_entry_t entries[8];
  csal_change_t changes;
  csal_change_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  csal_change_insert(&changes, key, value);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e6");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19ec");
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);

  ASSERT_EQ(0, csal_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_multi_3) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(proof, "0x4c4c48f84c48fe");

  csal_entry_t entries[8];
  csal_change_t changes;
  csal_change_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  csal_change_insert(&changes, key, value);
  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  csal_change_insert(&changes, key, value);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);

  ASSERT_EQ(0, csal_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_invalid_height) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(proof, "0x4c4c48204c4840");

  csal_entry_t entries[8];
  csal_change_t changes;
  csal_change_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  csal_change_insert(&changes, key, value);
  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  csal_change_insert(&changes, key, value);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);

  ASSERT_NE(0, csal_smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, update) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t expected_hash[32];
  uint8_t proof[96];
  csal_entry_t entries[8];
  csal_change_t changes;

  memset(root_hash, 0, 32);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  int proof_length = hex2bin(proof, "0x4c");
  memset(&proof[32], 0, 64);
  csal_change_init(&changes, entries, 32);
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);
  ASSERT_EQ(0, csal_smt_update_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0x5faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f372c1");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));

  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  proof_length = hex2bin(
      proof,
      "0x4c50f85faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f3"
      "72c1");
  memset(&proof[64], 0, 32);
  csal_change_init(&changes, entries, 32);
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);
  ASSERT_EQ(0, csal_smt_update_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0x32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb511b97eabf86");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  proof_length = hex2bin(
      proof,
      "0x4c50fe32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb511b97ea"
      "bf86");
  csal_change_init(&changes, entries, 32);
  csal_change_insert(&changes, key, value);
  csal_change_organize(&changes);
  ASSERT_EQ(0, csal_smt_update_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));
}

UTEST_MAIN();
