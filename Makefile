CFLAGS := -O3 -g -Wall -Werror -Wno-nonnull -I c/deps -I c/deps/ckb-c-stdlib -I c/deps/ckb-c-stdlib/molecule
TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
EXTRA_CFLAGS := -I c
CUSTOM_CFLAGS :=
OBJCOPY := $(TARGET)-objcopy
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
VM_FILES :=
OUTPUT := simple_account

build-smt:
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(CUSTOM_CFLAGS) $(LDFLAGS) $(VM_FILES) -o $(OUTPUT)
	$(OBJCOPY) --only-keep-debug $(OUTPUT) $(OUTPUT).debug
	$(OBJCOPY) --strip-debug --strip-all $(OUTPUT)

fmt:
	clang-format -i --style=Google $(wildcard c/*.h c/*.c c/vms/**/*.c c/tests/main.c)

test:
	gcc c/tests/main.c -o c/tests/runtest $(CFLAGS)
	./c/tests/runtest

.PHONY: build-smt fmt test
