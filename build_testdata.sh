#!/bin/bash
set -ex

riscv64-unknown-elf-gcc -o crates/layer/testdata/always_success crates/layer/testdata/always_success.S -nostdlib -nostartfiles
make build-smt VM_FILES=c/vms/dummy/dummy_vm.c OUTPUT=crates/layer/testdata/dummy_smt_validator
make build-smt VM_FILES=c/vms/dummy/dummy_vm.c OUTPUT=crates/layer/testdata/dummy_smt_generator CUSTOM_CFLAGS=-DBUILD_GENERATOR
