/*
 * CKB simple account layer in fullstorage mode, full storage means that
 * all values will be stored in CKB's cell data part.
 *
 * On hold and untested for now, you should take a look at the SMT solution
 * for the moment. We might bring this to life later but no promise now.
 */
#ifndef CSAL_VALIDATOR_FULLSTORAGE_H_
#define CSAL_VALIDATOR_FULLSTORAGE_H_

#include <blake2b.h>
#include <ckb_syscalls.h>
#include "core.h"

#ifdef CSAL_VALIDATOR_TYPE
#error "You can only pick one validator type in a script!"
#endif /* CSAL_VALIDATOR_TYPE */
#define CSAL_VALIDATOR_TYPE "fullstorage"

#define CSAL_ERROR_INVALID_MAIN_CELL_LENGTH (CSAL_LAST_COMMON_ERROR - 1)
#define CSAL_ERROR_MAIN_CELL_IS_MISSING (CSAL_LAST_COMMON_ERROR - 2)
#define CSAL_ERROR_BUFFER_NOT_LARGE_ENOUGH (CSAL_LAST_COMMON_ERROR - 3)
#define CSAL_ERROR_INVALID_TYPE_ID (CSAL_LAST_COMMON_ERROR - 4)
#define CSAL_ERROR_INVALID_ORDER (CSAL_LAST_COMMON_ERROR - 5)
#define CSAL_ERROR_INVALID_DATA (CSAL_LAST_COMMON_ERROR - 6)
#define CSAL_ERROR_REQUIRED_DATA_SHARD_MISSING (CSAL_LAST_COMMON_ERROR - 7)
#define CSAL_ERROR_EOF (CSAL_LAST_COMMON_ERROR - 8)
#define CSAL_LAST_ERROR CSAL_ERROR_EOF

#include "validator_utils.h"

#define CSAL_MAIN_CELL_IDENTIFIER 0x4e49414d
#define CSAL_DATA_CELL_IDENTIFIER 0x41544144

typedef struct {
  uint8_t prefix[CSAL_KEY_BYTES];
  uint8_t data_hash[32];
} csal_share_info_t;

typedef struct {
  uint64_t identifier;
  uint32_t nonce;
  uint32_t shards;
  csal_share_info_t shard_infos[CSAL_MAXIMUM_SHARDS];
} csal_main_cell_data_t;

uint64_t csal_main_cell_data_size(uint32_t shards) {
  return (uint64_t)(&(((csal_main_cell_data_t *)0)->shard_infos[shards]));
}

typedef struct {
  csal_main_cell_data_t main_cell;
  int32_t data_cell_indices[CSAL_MAXIMUM_SHARDS];
} csal_info_t;

int csal_load_info(csal_info_t *info, size_t source) {
  source |= 0x0100000000000000;
  /* Locates main cell first */
  size_t main_cell_index = 0;
  while (1) {
    uint64_t len = sizeof(csal_main_cell_data_t);
    int ret =
        ckb_load_cell_data(&info->main_cell, &len, 0, main_cell_index, source);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      return CSAL_ERROR_MAIN_CELL_IS_MISSING;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len >= 16 && info->main_cell.identifier == CSAL_MAIN_CELL_IDENTIFIER) {
      if (csal_main_cell_data_size(info->main_cell.shards) != len) {
        return CSAL_ERROR_INVALID_MAIN_CELL_LENGTH;
      }
      break;
    }
    main_cell_index++;
  }

  for (uint32_t j = 0; j < info->main_cell.shards; j++) {
    info->data_cell_indices[j] = -1;
  }
  /* Locates data cells */
  size_t i = 0;
  while (1) {
    if (i == main_cell_index) {
      i++;
      continue;
    }
    uint64_t len = 32;
    uint8_t hash[32];
    int ret = ckb_load_cell_by_field(hash, &len, 0, i, source,
                                     CKB_CELL_FIELD_DATA_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    for (uint32_t j = 0; j < info->main_cell.shards; j++) {
      if (memcmp(info->main_cell.shard_infos[j].data_hash, hash, 32) == 0) {
        info->data_cell_indices[j] = i;
      }
    }
    i++;
  }
  /* Checks that shards are in increasing orders */
  for (uint32_t j = 0; j < info->main_cell.shards - 1; j++) {
    if (memcmp(info->main_cell.shard_infos[j].prefix,
               info->main_cell.shard_infos[j + 1].prefix,
               CSAL_KEY_BYTES) >= 0) {
      return CSAL_ERROR_INVALID_ORDER;
    }
  }
  return CKB_SUCCESS;
}

typedef void (*_csal_data_func)(void *, const uint8_t *, size_t);

typedef struct {
  uint8_t data[(CSAL_KEY_BYTES + CSAL_VALUE_BYTES) * 64];
  int32_t total_count;
  int32_t entry_index;
  int32_t entry_start;
  size_t cell_index;
  size_t cell_source;
  int init;
  _csal_data_func data_func;
  void *data_func_data;
} _csal_data_reader;

void _csal_data_reader_dummy(_csal_data_reader *reader) { reader->init = 0; }

int _csal_data_reader_init(_csal_data_reader *reader, size_t cell_index,
                           size_t cell_source,
                           const uint8_t key_prefix[CSAL_KEY_BYTES],
                           _csal_data_func data_func, void *data_func_data) {
  cell_source |= 0x0100000000000000;
  uint64_t len = sizeof(reader->data);
  int ret = ckb_load_cell_data(reader->data, &len, 8, cell_index, cell_source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len % (CSAL_KEY_BYTES + CSAL_VALUE_BYTES) != 0) {
    return CSAL_ERROR_INVALID_DATA;
  }
  reader->total_count = len / (CSAL_KEY_BYTES + CSAL_VALUE_BYTES);
  int32_t loaded_count = reader->total_count > 64 ? 64 : reader->total_count;
  if (data_func != NULL) {
    data_func(data_func_data, reader->data,
              loaded_count * (CSAL_KEY_BYTES + CSAL_VALUE_BYTES));
  }
  if (loaded_count > 0) {
    if (memcmp(key_prefix, reader->data, CSAL_KEY_BYTES) > 0) {
      return CSAL_ERROR_INVALID_DATA;
    }
  }
  for (int32_t i = 0; i < loaded_count - 1; i++) {
    if (memcmp(&reader->data[(CSAL_KEY_BYTES + CSAL_VALUE_BYTES) * i],
               &reader->data[(CSAL_KEY_BYTES + CSAL_VALUE_BYTES) * (i + 1)],
               CSAL_KEY_BYTES) >= 0) {
      return CSAL_ERROR_INVALID_DATA;
    }
  }
  reader->entry_index = 0;
  reader->entry_start = 0;
  reader->cell_index = cell_index;
  reader->cell_source = cell_source;
  reader->init = 1;
  reader->data_func = data_func;
  reader->data_func_data = data_func_data;
  return CKB_SUCCESS;
}

int _csal_data_reader_peek(_csal_data_reader *reader, uint8_t **key,
                           uint8_t **value) {
  if (!reader->init) {
    return CSAL_ERROR_EOF;
  }
  if (reader->entry_start + reader->entry_index >= reader->total_count) {
    return CSAL_ERROR_EOF;
  }
  if (reader->entry_index >= 64) {
    /* Inflate reader with more data if available */
    uint8_t last[CSAL_KEY_BYTES];
    memcpy(last, &reader->data[(CSAL_KEY_BYTES + CSAL_VALUE_BYTES) * 63],
           CSAL_KEY_BYTES);
    uint64_t len = sizeof(reader->data);
    int32_t next_entry_start = reader->entry_start + 64;
    size_t offset = 8 + next_entry_start * (CSAL_KEY_BYTES + CSAL_VALUE_BYTES);
    int ret = ckb_load_cell_data(reader->data, &len, offset, reader->cell_index,
                                 reader->cell_source);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    int32_t remaining_count = reader->total_count - next_entry_start;
    int32_t loaded_count = remaining_count > 64 ? 64 : remaining_count;
    if (reader->data_func != NULL) {
      reader->data_func(reader->data_func_data, reader->data,
                        loaded_count * (CSAL_KEY_BYTES + CSAL_VALUE_BYTES));
    }
    if (memcmp(last, reader->data, CSAL_KEY_BYTES) >= 0) {
      return CSAL_ERROR_INVALID_DATA;
    }
    for (int32_t i = 0; i < loaded_count - 1; i++) {
      if (memcmp(&reader->data[(CSAL_KEY_BYTES + CSAL_VALUE_BYTES) * i],
                 &reader->data[(CSAL_KEY_BYTES + CSAL_VALUE_BYTES) * (i + 1)],
                 CSAL_KEY_BYTES) >= 0) {
        return CSAL_ERROR_INVALID_DATA;
      }
    }
    reader->entry_index = 0;
    reader->entry_start = next_entry_start;
  }
  if (key != NULL) {
    *key =
        &reader
             ->data[(CSAL_KEY_BYTES + CSAL_VALUE_BYTES) * reader->entry_index];
  }
  if (value != NULL) {
    *value =
        &reader
             ->data[(CSAL_KEY_BYTES + CSAL_VALUE_BYTES) * reader->entry_index +
                    CSAL_KEY_BYTES];
  }
  return CKB_SUCCESS;
}

int _csal_data_reader_next(_csal_data_reader *reader, uint8_t **key,
                           uint8_t **value) {
  int ret = _csal_data_reader_peek(reader, key, value);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  reader->entry_index++;
  return CKB_SUCCESS;
}

int _csal_data_reader_has(_csal_data_reader *reader) {
  return _csal_data_reader_peek(reader, NULL, NULL) != CSAL_ERROR_EOF;
}

/* TODO: blake2b check for generated outputs */
int _csal_consume_output(const csal_info_t *output_info, uint32_t *output_shard,
                         _csal_data_reader *output_reader, uint8_t **key,
                         uint8_t **value, blake2b_state *blake2b_ctx) {
  int ret = _csal_data_reader_next(output_reader, key, value);
  if (ret == CSAL_ERROR_EOF) {
    /* Load next output shard into output_reader */
    if (*output_shard >= output_info->main_cell.shards) {
      return CSAL_ERROR_INVALID_DATA;
    }
    int32_t cell_index = output_info->data_cell_indices[*output_shard];
    if (cell_index == -1) {
      return CSAL_ERROR_REQUIRED_DATA_SHARD_MISSING;
    }
    if (output_reader->init == 1 && output_shard > 0) {
      /* Already initialized with an output shard, check blake2b hash */
      uint8_t hash[32];
      blake2b_final(blake2b_ctx, hash, 32);
      if (memcmp(
              hash,
              output_info->main_cell.shard_infos[*output_shard - 1].data_hash,
              32) != 0) {
        return CSAL_ERROR_INVALID_DATA;
      }
    }
    blake2b_init(blake2b_ctx, 32);
    uint64_t data_identifier = CSAL_DATA_CELL_IDENTIFIER;
    blake2b_update(blake2b_ctx, &data_identifier, 8);
    int ret = _csal_data_reader_init(
        output_reader, cell_index, CKB_SOURCE_OUTPUT,
        output_info->main_cell.shard_infos[*output_shard].prefix,
        (_csal_data_func)blake2b_update, blake2b_ctx);
    if (ret != 0) {
      return ret;
    }
    *output_shard = *output_shard + 1;
    ret = _csal_data_reader_next(output_reader, key, value);
  }
  return ret;
}

int _csal_consume_output_final(const csal_info_t *output_info,
                               uint32_t *output_shard,
                               _csal_data_reader *output_reader,
                               blake2b_state *blake2b_ctx) {
  if (_csal_data_reader_has(output_reader)) {
    return CSAL_ERROR_INVALID_DATA;
  }
  if (output_reader->init == 1 && output_shard > 0) {
    uint8_t hash[32];
    blake2b_final(blake2b_ctx, hash, 32);
    if (memcmp(hash,
               output_info->main_cell.shard_infos[*output_shard - 1].data_hash,
               32) != 0) {
      return CSAL_ERROR_INVALID_DATA;
    }
  }
  return CKB_SUCCESS;
}

/* state must be processed via csal_change_organize */
__attribute__((visibility("default"))) int validate_changes(
    const csal_change_t *state) {
  /* 1. Load input and output cell infos. */
  csal_info_t input_info;
  int ret = csal_load_info(&input_info, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS && ret != CSAL_ERROR_MAIN_CELL_IS_MISSING) {
    return ret;
  }
  int has_input = (ret != CSAL_ERROR_MAIN_CELL_IS_MISSING);
  if (!has_input) {
    input_info.main_cell.nonce = 0;
    input_info.main_cell.shards = 0;
  }
  csal_info_t output_info;
  ret = csal_load_info(&output_info, CKB_SOURCE_OUTPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* 2. In case of first cell creation, check type ID. */
  if (!has_input) {
    ret = csal_check_type_id();
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }
  /*
   * 3. Iterate through data to make sure changes are applied and only changes
   * are changed.
   */
  uint32_t input_shard = 0, output_shard = 0;
  int32_t state_processed = 0;
  while (state_processed < state->length) {
    /* Skip shards that are not changed. */
    while (input_shard + 1 < input_info.main_cell.shards &&
           memcmp(input_info.main_cell.shard_infos[input_shard + 1].prefix,
                  state->entries[state_processed].key, CSAL_KEY_BYTES) <= 0) {
      /* TODO: reorg in non-changed cells */
      if (output_shard >= output_info.main_cell.shards ||
          memcmp(input_info.main_cell.shard_infos[input_shard].prefix,
                 output_info.main_cell.shard_infos[output_shard].prefix,
                 CSAL_KEY_BYTES) != 0 ||
          memcmp(input_info.main_cell.shard_infos[input_shard].data_hash,
                 output_info.main_cell.shard_infos[output_shard].data_hash,
                 32) != 0) {
        return CSAL_ERROR_INVALID_DATA;
      }
      input_shard++;
      output_shard++;
    }
    /* Load cell data from input_shard and output_shard, does entry level
     * checking with state changes considered. Notice output shard might have
     * data reorg(for simplicity, only considers cell splitting now). The loop
     * round should end with all entries from input shard as well as one or more
     * output shards processed and compared. For output shards, we also need to
     * check data hashes recorded in the main cell. For state, it should process
     * all changed entries belonging to the current input shard.
     */
    _csal_data_reader input_reader;
    _csal_data_reader_dummy(&input_reader);
    if (input_shard < input_info.main_cell.shards) {
      int32_t cell_index = input_info.data_cell_indices[input_shard];
      if (cell_index == -1) {
        return CSAL_ERROR_REQUIRED_DATA_SHARD_MISSING;
      }
      int ret = _csal_data_reader_init(
          &input_reader, cell_index, CKB_SOURCE_INPUT,
          input_info.main_cell.shard_infos[input_shard].prefix, NULL, NULL);
      if (ret != 0) {
        return ret;
      }
      input_shard++;
    }
    _csal_data_reader output_reader;
    _csal_data_reader_dummy(&output_reader);
    uint8_t *input_entry_key = NULL, *input_entry_value = NULL;
    uint8_t *output_entry_key = NULL, *output_entry_value = NULL;
    blake2b_state output_blake2b_ctx;
    while (_csal_data_reader_has(&input_reader) &&
           state_processed < state->length) {
      /*
       * First, iterate through all input key that come before the next
       * changed entry.
       */
      while (1) {
        uint8_t *state_entry_key = state->entries[state_processed].key;
        int ret = _csal_data_reader_peek(&input_reader, &input_entry_key,
                                         &input_entry_value);
        if (ret == CSAL_ERROR_EOF ||
            memcmp(input_entry_key, state_entry_key, CSAL_KEY_BYTES) >= 0) {
          break;
        }
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        /* Consumes current input key */
        ret = _csal_data_reader_next(&input_reader, NULL, NULL);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        /* Consumes corresponding output key */
        ret = _csal_consume_output(&output_info, &output_shard, &output_reader,
                                   &output_entry_key, &output_entry_value,
                                   &output_blake2b_ctx);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (memcmp(input_entry_key, output_entry_key, CSAL_KEY_BYTES) != 0 ||
            memcmp(input_entry_value, output_entry_value, CSAL_VALUE_BYTES) !=
                0) {
          return CSAL_ERROR_INVALID_DATA;
        }
      }
      /*
       * Next, iterate all changed entries that come before the next input
       * key (if present). Here we will also process input keys that match
       * changed entries.
       */
      while (state_processed < state->length) {
        uint8_t *state_entry_key = state->entries[state_processed].key;
        uint8_t *state_entry_value = state->entries[state_processed].value;
        int ret = _csal_data_reader_peek(&input_reader, &input_entry_key,
                                         &input_entry_value);
        if (ret != CKB_SUCCESS && ret != CSAL_ERROR_EOF) {
          return ret;
        }
        if (ret == CKB_SUCCESS) {
          int cmp_value =
              memcmp(state_entry_key, input_entry_key, CSAL_KEY_BYTES);
          if (cmp_value == 0) {
            /* Consume matched input key */
            ret = _csal_data_reader_next(&input_reader, NULL, NULL);
            if (ret != CKB_SUCCESS) {
              return ret;
            }
          } else if (cmp_value > 0) {
            break;
          }
        }
        ret = _csal_consume_output(&output_info, &output_shard, &output_reader,
                                   &output_entry_key, &output_entry_value,
                                   &output_blake2b_ctx);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (memcmp(output_entry_key, state_entry_key, CSAL_KEY_BYTES) != 0 ||
            memcmp(output_entry_value, state_entry_value, CSAL_VALUE_BYTES) !=
                0) {
          return CSAL_ERROR_INVALID_DATA;
        }
        state_processed++;
      }
    }
    if (state_processed < state->length) {
      /*
       * Current input shard is all process, but we still need to check
       * remaining changed keys that come before next input shard
       */
      uint8_t *next_prefix = NULL;
      /* When generating input_reader, we've already bumped the value of
       * input_shard */
      if (input_shard < input_info.main_cell.shards) {
        next_prefix = input_info.main_cell.shard_infos[input_shard].prefix;
      }
      while (state_processed < state->length) {
        uint8_t *state_entry_key = state->entries[state_processed].key;
        uint8_t *state_entry_value = state->entries[state_processed].value;
        if (next_prefix != NULL &&
            memcmp(state_entry_key, next_prefix, CSAL_KEY_BYTES) >= 0) {
          break;
        }
        ret = _csal_consume_output(&output_info, &output_shard, &output_reader,
                                   &output_entry_key, &output_entry_value,
                                   &output_blake2b_ctx);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (memcmp(output_entry_key, state_entry_key, CSAL_KEY_BYTES) != 0 ||
            memcmp(output_entry_value, state_entry_value, CSAL_VALUE_BYTES) !=
                0) {
          return CSAL_ERROR_INVALID_DATA;
        }
        state_processed++;
      }
    } else {
      /*
       * Changed keys are all processed, check the remaining input shard to make
       * sure it matches output shard(s)
       */
      while (1) {
        int ret = _csal_data_reader_next(&input_reader, &input_entry_key,
                                         &input_entry_value);
        if (ret == CSAL_ERROR_EOF) {
          break;
        }
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        /* Consumes corresponding output key */
        ret = _csal_consume_output(&output_info, &output_shard, &output_reader,
                                   &output_entry_key, &output_entry_value,
                                   &output_blake2b_ctx);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (memcmp(input_entry_key, output_entry_key, CSAL_KEY_BYTES) != 0 ||
            memcmp(input_entry_value, output_entry_value, CSAL_VALUE_BYTES) !=
                0) {
          return CSAL_ERROR_INVALID_DATA;
        }
      }
    }
    /*
     * We are only doing simple cases right now, which means when input shard is
     * all processed, we will also check we land exactly on the end of an output
     * shard as well. Complicated cell reorgs will be left to future work.
     */
    ret = _csal_consume_output_final(&output_info, &output_shard,
                                     &output_reader, &output_blake2b_ctx);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }
  /* Check remaining input & output shards if there is any */
  while (input_shard < input_info.main_cell.shards &&
         output_shard < output_info.main_cell.shards) {
    if (memcmp(input_info.main_cell.shard_infos[input_shard].prefix,
               output_info.main_cell.shard_infos[output_shard].prefix,
               CSAL_KEY_BYTES) != 0 ||
        memcmp(input_info.main_cell.shard_infos[input_shard].data_hash,
               output_info.main_cell.shard_infos[output_shard].data_hash,
               32) != 0) {
      return CSAL_ERROR_INVALID_DATA;
    }
    input_shard++;
    output_shard++;
  }
  if (input_shard < input_info.main_cell.shards ||
      output_shard < output_info.main_cell.shards) {
    return CSAL_ERROR_INVALID_DATA;
  }
  return CKB_SUCCESS;
}

#endif /* CSAL_VALIDATOR_FULLSTORAGE_H_ */
