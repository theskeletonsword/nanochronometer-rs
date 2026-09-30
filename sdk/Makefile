# SPDX-License-Identifier: Apache-2.0
# NanoChronometer SDK: C plugins (.ncplu), the kernel, a bootable ISO, QEMU.
#
#   make                           C plugins in examples/ -> build/<MODE>/<NAME>.NCPLU
#   make MODE=release [OPT=-O3]    the same optimised: -O2 by default, no debug info
#   make sign KEYS=<keydir>        sign them (ML-DSA-87 + P-521; keys from ncplu-sign keygen)
#   make kernel                    the x86-64 kernel, -O0 -g, custom Rust target
#   make iso                       kernel + hybrid ISO; the C plugins go on its FAT partition
#   make run [PLUGIN=rng_demo]     boot the ISO as a USB stick (KVM on an x86-64 host, else TCG)
#   make gdb [PLUGIN=rng_demo]     the same, stopped for: gdb -x packaging/baremetal/gdb/x86_64.gdb
#   make clean
#
# Plugins: MODE=debug is -O0 -g3 (step through under GDB), MODE=release is
# -O2 (OPT=-O3 for more). The kernel stays -O0 -g. KEYS=<keydir> on iso/run/gdb
# signs every plugin and builds the kernel to trust that key's root, which is
# how a developer gets Official plugins on their own machine. Key directories
# live outside the repository.

REPO    := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
SDK     := $(REPO)/sdk
KERNEL  := $(REPO)/crates/nanochrono-baremetal
MODE    ?= debug
ifeq ($(MODE),debug)
OPTFLAGS := -O0 -g3                           # debug: step it in GDB
else ifeq ($(MODE),release)
OPT     ?= -O2
OPTFLAGS := $(OPT) -DNDEBUG                   # release: what users run, and what gets signed
else
$(error MODE must be debug or release)
endif
BUILD   := $(SDK)/build/$(MODE)
# Off the repository's exFAT volume: no hard links there, and rustc's
# incremental cache corrupts on it.
export CARGO_TARGET_DIR ?= $(HOME)/.cache/nanochrono/kernel-target
export CARGO_INCREMENTAL := 0

CC      := clang
LD      := ld.lld
PYTHON  := python3

# ---------------------------------------------------------------------------
# Freestanding C for this OS: x86-64, ring 0, loaded at any address in the
# plugin arena, reaching the kernel only through the nc_api_t table.
# ---------------------------------------------------------------------------
CFLAGS  := --target=x86_64-unknown-none-elf   # no OS: ELF, x86-64 System V ABI
CFLAGS  += -march=x86-64                      # baseline ISA (SSE2): runs wherever the kernel does
CFLAGS  += -std=c11 -ffreestanding            # no hosted library; main() is not special
CFLAGS  += -fno-builtin                       # memcpy & co. are ours, not libc's
CFLAGS  += -nostdinc -isystem $(shell $(CC) -print-resource-dir)/include  # compiler headers only
CFLAGS  += -fPIC                              # position independent: the loader picks the address
CFLAGS  += -fvisibility=hidden                # only ncplu_main is exported (NCPLU_EXPORT)
CFLAGS  += -mno-red-zone                      # ring 0: an exception pushes onto this same stack
CFLAGS  += -fno-stack-protector -fno-stack-check  # no __stack_chk_* in the kernel
CFLAGS  += -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables  # no .eh_frame
CFLAGS  += -ffunction-sections -fdata-sections
CFLAGS  += $(OPTFLAGS)
CFLAGS  += -Wall -Wextra -Werror=implicit-function-declaration
CFLAGS  += -I $(SDK)/include

LDFLAGS := -shared                            # ET_DYN, the input tools/ncplu.py packs
LDFLAGS += -Bsymbolic                         # the plugin's own references bind locally
LDFLAGS += --gc-sections
LDFLAGS += -z max-page-size=4096
LDFLAGS += --build-id=none
LDFLAGS += -e ncplu_main
# No --no-undefined: kernel data (nc_abi_version) stays undefined on purpose
# and becomes an IMPORT64 relocation. Undefined *functions* are refused by
# the packer: kernel services go through nc_api_t, never a PLT.

# ---------------------------------------------------------------------------
EXAMPLES := $(basename $(notdir $(wildcard $(SDK)/examples/*.c)))
upper     = $(shell echo '$(1)' | tr a-z A-Z)
PLUGINS  := $(foreach e,$(EXAMPLES),$(BUILD)/$(call upper,$(e)).NCPLU)

.PHONY: all sign kernel iso run gdb clean
all: $(PLUGINS)

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: $(SDK)/examples/%.c $(SDK)/include/ncplu.h | $(BUILD)
	$(CC) $(strip $(CFLAGS)) -c $< -o $@

$(BUILD)/ncplu_rt.o: $(SDK)/runtime/ncplu_rt.c $(SDK)/include/ncplu.h | $(BUILD)
	$(CC) $(strip $(CFLAGS)) -c $< -o $@

$(BUILD)/%.so: $(BUILD)/%.o $(BUILD)/ncplu_rt.o
	$(LD) $(strip $(LDFLAGS)) $^ -o $@

# <name>.so -> <NAME>.NCPLU: the name the kernel's plugin=<name> looks for.
define pack_rule
$(BUILD)/$(call upper,$(1)).NCPLU: $(BUILD)/$(1).so
	$(PYTHON) $(REPO)/tools/ncplu.py pack $$< -o $$@
endef
$(foreach e,$(EXAMPLES),$(eval $(call pack_rule,$(e))))

# The host signing tool, built once, off the repository.
SIGNER_DIR := $(HOME)/.cache/nanochrono/ncplu-sign
SIGNER     := $(SIGNER_DIR)/debug/ncplu-sign

sign: $(PLUGINS)
	@test -n "$(KEYS)" || { echo "usage: make sign KEYS=<dir from ncplu-sign keygen>" >&2; exit 1; }
	cd $(REPO)/tools/ncplu-sign && CARGO_TARGET_DIR=$(SIGNER_DIR) cargo build --quiet
	for p in $(PLUGINS); do $(SIGNER) sign $$p --keys $(KEYS); done

# What iso/run/gdb hand build.sh: these plugins, the Rust plugins' profile,
# and with KEYS the signing keys plus the root the kernel will trust.
BUILD_ENV = NCPLU_EXTRA="$(PLUGINS)" PLUGIN_PROFILE=$(MODE) \
            $(if $(KEYS),NCPLU_SIGN_KEYS=$(KEYS) NCPLU_ROOT_PUBKEYS=$(KEYS)/root_pubkeys.bin)

# The kernel for the custom target. crates/nanochrono-baremetal/.cargo/
# config.toml supplies RUST_TARGET_PATH (targets/x86_64-nanochrono-none.json),
# build-std for core, and the no-red-zone / static relocation flags.
kernel:
	cd $(KERNEL) && cargo +nightly build --target x86_64-nanochrono-none --features simd \
	    --config 'target.x86_64-nanochrono-none.rustflags=["-C","force-frame-pointers=yes"]'

# ISO: GRUB (BIOS + UEFI) with the multiboot kernel, plus the FAT partition
# (NANOCRASH) that holds CRASH.DMP and every .NCPLU — in-tree and these.
iso: $(PLUGINS)
	$(BUILD_ENV) $(REPO)/packaging/baremetal/build.sh debug x86_64

run: $(PLUGINS)
	$(BUILD_ENV) $(REPO)/packaging/baremetal/build.sh boot x86_64 $(if $(PLUGIN),plugin=$(PLUGIN))

gdb: $(PLUGINS)
	$(BUILD_ENV) $(REPO)/packaging/baremetal/build.sh gdb x86_64 $(if $(PLUGIN),plugin=$(PLUGIN))

clean:
	rm -rf $(SDK)/build
