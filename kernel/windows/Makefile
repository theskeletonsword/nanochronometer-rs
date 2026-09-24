# SPDX-License-Identifier: MIT
#
# NanoChronometer Windows driver — cross-build from Linux.
#
# Toolchain: clang-based mingw-w64 drivers (x86_64 + aarch64) plus rustc with
# the `{x86_64,aarch64}-pc-windows-gnullvm` targets. Point TOOLCHAIN at the
# bin/ directory of an llvm-mingw release (tools/fetch-cross-toolchains.sh
# downloads one to ~/.cache/nanochrono/toolchains).
#
# Targets:
#   make all            build/x64/nanochrono.sys + build/arm64/nanochrono.sys
#                       (PE native, imports ntoskrnl.exe only). One driver,
#                       one name; the directory says the architecture.
#   make offsets-check  abort if the Rust offset constants disagree with the
#                       toolchain headers for either architecture
#   make sign           sign artifacts with osslsigncode (test cert)
#   make clean
#
# Verified on Fedora 43 (rustc 1.98, gnullvm targets, clang 23.1.0-rc3 mingw).

TOOLCHAIN ?= $(firstword $(wildcard $(HOME)/.cache/nanochrono/toolchains/llvm-mingw-*/bin) /opt/llvm-mingw/bin)
RUSTC     ?= rustc
X86       := x86_64-w64-mingw32
ARM       := aarch64-w64-mingw32

BUILD     := build
IMPORTS   := $(BUILD)/imports
OUT_X64   := $(BUILD)/x64/nanochrono.sys
OUT_ARM   := $(BUILD)/arm64/nanochrono.sys

# no-redzone: a kernel stack is shared with interrupt and exception frames, so
# a leaf function must not keep data below its stack pointer. The Win64 ABI
# has no red zone and LLVM does not use one there; this makes that a rule.
RUSTC_FLAGS := -O --crate-type=bin -C panic=abort -C no-redzone=yes
# Each -C link-arg must be its own argument (spaces would be mis-parsed).
LINK_ARGS := -C link-arg=-nostdlib \
             -C link-arg=-Wl,--subsystem,native \
             -C link-arg=-Wl,--entry,DriverEntry \
             -C link-arg=-Wno-unused-command-line-argument

.PHONY: all offsets-check sign clean dirs
.PRECIOUS: $(IMPORTS)/ntoskrnl-x64.a $(IMPORTS)/ntoskrnl-arm64.a

all: dirs offsets-check $(OUT_X64) $(OUT_ARM)
	@echo "== built =="
	@file $(OUT_X64) $(OUT_ARM)

dirs:
	@mkdir -p $(BUILD) $(IMPORTS) $(BUILD)/x64 $(BUILD)/arm64

$(IMPORTS)/ntoskrnl-x64.a: defs/ntoskrnl.def
	$(TOOLCHAIN)/$(X86)-dlltool -d $< -D ntoskrnl.exe -l $@

$(IMPORTS)/ntoskrnl-arm64.a: defs/ntoskrnl.def
	$(TOOLCHAIN)/$(ARM)-dlltool -d $< -D ntoskrnl.exe -l $@

# Offset check — compiled against the real headers for BOTH architectures.
# x64 builds the native wdm.h; arm64 needs the _M_ARM workaround because the
# mingw wdm.h has no _M_ARM64 branch (see docs/PORTING_LINUX_TO_WDM.md).
offsets-check:
	@mkdir -p $(BUILD)
	@echo "== offsets-check: x86_64 =="
	$(TOOLCHAIN)/$(X86)-gcc -ffreestanding -fms-extensions -c defs/offsets-check.c -o $(BUILD)/offsets-x64.o
	@echo "== offsets-check: arm64 =="
	$(TOOLCHAIN)/$(ARM)-gcc -I defs/armddk-shim -D_M_ARM=100 -ffreestanding -fms-extensions -c defs/offsets-check.c -o $(BUILD)/offsets-arm64.o
	@echo "== offsets-check: ok (both architectures) =="

define build_sys
	$(RUSTC) --target $(1)-pc-windows-gnullvm $(RUSTC_FLAGS) \
	  -C linker=$(TOOLCHAIN)/$(1)-w64-mingw32-gcc \
	  $(LINK_ARGS) \
	  -C link-arg=$(IMPORTS)/ntoskrnl-$(2).a \
	  src/main.rs -o $(3)
endef

$(OUT_X64): src/*.rs $(IMPORTS)/ntoskrnl-x64.a
	$(call build_sys,x86_64,x64,$@)

$(OUT_ARM): src/*.rs $(IMPORTS)/ntoskrnl-arm64.a
	$(call build_sys,aarch64,arm64,$@)

sign:
	./sign.sh

clean:
	rm -rf $(BUILD)