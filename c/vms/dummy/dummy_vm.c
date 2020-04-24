/*
 * This is a dummy VM that only accepts the following 2 operations:
 *
 * R <32 byte key> <32 byte value>
 * W <32 byte key> <32 byte value>
 *
 * Hence the source length will always be a multiple of 65.
 *
 * R operation reads the value from the storage, then compare it with the
 * provided value, if they don't match, the program halts with an error state,
 * otherwise it continues with the next operation.
 * W operation writes the value to storage. Future R operations on the same
 * key should read the newly written value.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef BUILD_GENERATOR
#include "generator.h"
#else
#define CSAL_VALIDATOR_TYPE 1
#include "validator.h"
#endif

int execute_vm(const uint8_t *source, uint32_t length,
               csal_change_t *existing_values, csal_change_t *changes) {
  size_t operation_length = 1 + CSAL_KEY_BYTES + CSAL_VALUE_BYTES;
  if (length % operation_length != 0) {
    return -100;
  }
  for (uint32_t i = 0; i < length; i += operation_length) {
    uint8_t read_value[CSAL_VALUE_BYTES];
    int ret;
    switch (source[i]) {
      case 'R':
        ret = csal_change_fetch(existing_values, &source[i + 1], read_value);
        if (ret != 0) {
          return ret;
        }
        if (memcmp(&source[i + 1 + CSAL_KEY_BYTES], read_value,
                   CSAL_VALUE_BYTES) != 0) {
          return -101;
        }
        break;
      case 'W':
        ret = csal_change_insert(existing_values, &source[i + 1],
                                 &source[i + 1 + CSAL_KEY_BYTES]);
        if (ret != 0) {
          return ret;
        }
        ret = csal_change_insert(changes, &source[i + 1],
                                 &source[i + 1 + CSAL_KEY_BYTES]);
        if (ret != 0) {
          return ret;
        }
        break;
      default:
        return -102;
    }
  }
  return 0;
}
