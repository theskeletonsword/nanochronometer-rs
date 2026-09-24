# SPDX-License-Identifier: (GPL-2.0-only OR MIT)
# One module, one name: nanochrono.ko (hypervisor probe, counters, perf).
obj-m += nanochrono.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# The kernel's Rust crates are metadata-locked to the exact rustc that built
# the kernel, so the distribution compiler must be used rather than whatever
# rustup has on PATH.
RUSTC ?= /usr/bin/rustc

all:
	$(MAKE) -C $(KDIR) M=$(PWD) RUSTC=$(RUSTC) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load: all
	sudo insmod nanochrono.ko
	@cat /proc/nanochrono

unload:
	sudo rmmod nanochrono

.PHONY: all clean load unload
