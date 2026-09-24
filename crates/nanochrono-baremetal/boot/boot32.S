/* SPDX-License-Identifier: Apache-2.0
 *
 * The one loose assembly file in this project, and the reason it has to be
 * one.
 *
 * A multiboot2 loader hands control over in 32-bit protected mode, with no
 * paging, no stack, and no guarantee about any register but EAX and EBX. Rust
 * cannot be entered there: the compiler emits 64-bit code for this target, the
 * ABI assumes a stack that does not exist yet, and `global_asm!` cannot place
 * the multiboot header in the first 32 KiB of the image the way the
 * specification requires. So this file exists to build the world Rust needs —
 * a stack, identity-mapped page tables, and long mode — and then jump into it.
 *
 * Everything after `kmain` is Rust. Every other instruction sequence in this
 * project is `core::arch::asm!`.
 */

/* ---------------------------------------------------------------------------
 * Boot headers. Both are emitted, because the two loaders that matter want
 * different ones: GRUB2 prefers multiboot2, and QEMU's `-kernel` implements
 * only multiboot1. Carrying both means the same image boots under either
 * without a separate build, and testing under QEMU needs no ISO.
 *
 * A loader scans the first 32 KiB for its magic, so the linker script places
 * this section first.
 * ------------------------------------------------------------------------ */
.section .multiboot_header, "a"

/* --- multiboot1: what QEMU's -kernel understands --- */
.align 4
    .long 0x1BADB002                /* magic                              */
    .long 0x00000000                /* flags: nothing beyond the defaults */
    .long -(0x1BADB002 + 0)         /* checksum: the three sum to zero    */

/* --- multiboot2: what GRUB2 prefers --- */
.align 8
multiboot2_header_start:
    .long 0xE85250D6                                      /* magic            */
    .long 0                                               /* architecture i386 */
    .long multiboot2_header_end - multiboot2_header_start /* header length    */
    /* The checksum makes the four fields sum to zero in 32 bits. */
    .long -(0xE85250D6 + 0 + (multiboot2_header_end - multiboot2_header_start))

    /* Framebuffer tag: ask the loader for a linear graphics mode. Zero for
     * width, height and depth means "whatever you think best", which is what
     * lets this work on a machine whose modes are unknown.
     *
     * Type 1 (optional) rather than 0: without it a loader that cannot set a
     * graphics mode refuses to boot at all, and a text-mode boot that still
     * prints to serial is far better than no boot. */
    .align 8
    .short 5                        /* tag type: framebuffer */
    .short 1                        /* flags: optional        */
    .long 20                        /* size                   */
    .long 0                         /* width:  loader chooses */
    .long 0                         /* height: loader chooses */
    .long 0                         /* depth:  loader chooses */

    /* The end tag, which terminates the tag list. */
    .align 8
    .short 0
    .short 0
    .long 8
multiboot2_header_end:

/* ---------------------------------------------------------------------------
 * 32-bit entry.
 * ------------------------------------------------------------------------ */
.section .boot, "ax"
.code32
.global _start
.type _start, @function
_start:
    /* EAX holds the boot magic and EBX the info structure pointer. Both are
     * needed in 64-bit code, and neither survives the journey: `cpuid`
     * clobbers all four general registers, and the stack cannot carry them
     * either — a 32-bit `push` writes four bytes where a 64-bit `pop` reads
     * eight, so the two values would come back fused into one. Fixed storage
     * in `.data` is the only place that means the same thing on both sides of
     * the mode switch, and it survives the zeroing below.
     *
     * Saved first, before anything else can clobber them. */
    mov %eax, boot_magic
    mov %ebx, boot_info

    /* Zero .bss, inline and before a stack exists.
     *
     * Multiboot 1 does not require the loader to do this, and relying on a
     * loader that happens to means the kernel works on the machine it was
     * tested on. Rust assumes zeroed statics, and the page tables below live
     * here — so on a machine whose RAM still holds what POST left in it, an
     * unzeroed .bss is an immediate triple fault rather than a subtle bug.
     * An emulator hands over zeroed memory, which is exactly why this is the
     * kind of difference that only shows up on real hardware.
     *
     * Inline rather than a `call`: the stack is itself inside .bss, so a
     * routine would overwrite its own return address partway through and
     * `ret` into nothing. */
    /* The direction flag. Multiboot leaves EFLAGS undefined apart from VM
     * and IF, so DF may be set — and then `rep stosl` below walks *down*
     * from __bss_start, zeroing whatever precedes .bss instead. The Rust
     * ABI also requires DF clear at every call: compiler-builtins'
     * memcpy/memset use `rep movs`/`rep stos` and would copy backwards
     * through memory for the whole run. */
    cld

    mov $__bss_start, %edi
    mov $__bss_end, %ecx
    sub %edi, %ecx                  /* byte count */
    shr $2, %ecx                    /* dwords; .bss is 4-byte aligned */
    xor %eax, %eax
    rep stosl

    /* Now that the memory behind it is zeroed, the stack is usable. */
    mov $stack_top, %esp

    call check_cpuid
    call check_long_mode
    call enable_sse
    call build_page_tables
    call install_stack_guard
    call enter_long_mode

    /* The GDT is loaded and CS still refers to the 32-bit descriptor. A far
     * jump is the only way to reload CS, and reloading CS with a 64-bit
     * descriptor is what actually starts executing 64-bit code. */
    lgdt gdt64_pointer
    ljmp $0x08, $long_mode_start

/* CPUID is not architecturally guaranteed: it exists only if bit 21 of EFLAGS
 * can be toggled. Everything below depends on it, so it is checked first. */
check_cpuid:
    pushfl
    pop %eax
    mov %eax, %ecx
    xor $(1 << 21), %eax
    push %eax
    popfl
    pushfl
    pop %eax
    push %ecx
    popfl
    cmp %ecx, %eax
    je no_cpuid
    ret

/* Long mode is reported by CPUID.80000001H:EDX[29], and that leaf only exists
 * if the maximum extended leaf reaches it.
 *
 * PDPE1GB, bit 26 of the same register, is *recorded* rather than required.
 * Setting the huge-page bit in a PDPT entry on a CPU without that feature
 * makes the entry reserved rather than large, and the resulting page fault
 * with no IDT is a triple fault — so it has to be known before the tables are
 * built. It used to be a hard requirement, which quietly excluded every part
 * before Westmere and Barcelona: Core 2 and Nehalem run long mode perfectly
 * well and simply stopped here. They now take the 2 MiB path below. */
/* Gigabytes mapped by the 2 MiB fallback, and so how many page directories
 * it needs. See `build_2m_tables` for why sixty-four rather than 512. */
.set PD_COUNT, 64

check_long_mode:
    mov $0x80000000, %eax
    cpuid
    cmp $0x80000001, %eax
    jb no_long_mode
    mov $0x80000001, %eax
    cpuid
    test $(1 << 29), %edx
    jz no_long_mode
    xor %eax, %eax
    test $(1 << 26), %edx           /* PDPE1GB */
    setnz %al
    mov %al, have_gib_pages
    ret

/* Enables SSE, and AVX where the CPU has it.
 *
 * `x86_64-unknown-none` is a soft-float target: the compiler will not touch
 * XMM unless told to, because on a freestanding target nothing has enabled
 * it. This kernel does tell it to (`-C target-feature=+sse,+sse2`), because
 * the SIMD probes it shares with the hosted build are the whole point of
 * measuring here — so the enable has to happen, and it has to happen before
 * any Rust runs. Executing an SSE instruction with CR0.EM set or CR4.OSFXSR
 * clear is #UD, not a slow path. */
enable_sse:
    mov %cr0, %eax
    and $~(1 << 2), %eax            /* EM: no coprocessor emulation */
    or  $(1 << 1), %eax             /* MP: monitor coprocessor */
    mov %eax, %cr0

    mov %cr4, %eax
    or  $(1 << 9), %eax             /* OSFXSR: FXSAVE/FXRSTOR and SSE */
    or  $(1 << 10), %eax            /* OSXMMEXCPT: SIMD FP exceptions */
    mov %eax, %cr4

    /* Everything wider than XMM needs the OS to declare that it will save the
     * state, which is what XCR0 is for. Without it CPUID still reports AVX
     * and AVX-512, but every VEX or EVEX instruction is #UD — which is
     * exactly the trap the hosted build's XGETBV check exists to avoid, and
     * here it has to be made *true* rather than merely detected.
     *
     * OSXSAVE is set whenever XSAVE exists, not only when AVX does: it is
     * what makes XGETBV legal, and the feature detection reads XCR0 to decide
     * what the OS has enabled. Leaving it clear would make that read return
     * zero and every wide register file look disabled. */
    mov $1, %eax
    cpuid
    test $(1 << 26), %ecx           /* CPUID.1:ECX[26], XSAVE */
    jz 2f

    mov %cr4, %eax
    or  $(1 << 18), %eax            /* CR4.OSXSAVE, required before XGETBV */
    mov %eax, %cr4

    /* Which XCR0 bits this CPU actually supports, from CPUID.0DH:EAX. XSETBV
     * raises #GP on any bit the processor does not implement, so the wanted
     * set is masked by the supported set rather than written blind. */
    mov $0x0D, %eax
    xor %ecx, %ecx
    cpuid
    mov %eax, %ebx

    /* Bits 0 and 1 are x87 and SSE, 2 is AVX (YMM_Hi128), and 5, 6 and 7 are
     * the three AVX-512 components: opmask, ZMM_Hi256 and Hi16_ZMM. All of
     * AVX-512 needs all three, which is why the hosted detection checks
     * 0xE6 and not just bit 5. */
    and $0b11100111, %ebx
    or  $0b00000011, %ebx           /* x87 and SSE are always supported */

    xor %ecx, %ecx
    xgetbv                          /* EDX:EAX = current XCR0 */
    or  %ebx, %eax
    xsetbv
2:
    ret

/* Identity-maps the first 512 GiB with 1 GiB pages.
 *
 * Not because that much memory exists, but because of where firmware puts
 * things: a UEFI framebuffer is routinely above 4 GiB, and a mapping that
 * stopped short of it would fault on the first pixel. One PDPT holds 512
 * entries, so covering the whole range it can address costs the same table
 * either way.
 *
 * Every entry is written as a full 64-bit value. Writing only the low half —
 * which an earlier version of this file did — leaves the upper half holding
 * whatever was in RAM, and the upper half contains bits the architecture
 * reserves and requires to be zero. Under an emulator that memory is already
 * zeroed and it works; on a machine with a real POST behind it, a stray
 * reserved bit is a page fault with no handler. */
build_page_tables:
    /* PML4[0] -> PDPT, both halves. */
    mov $pdpt, %eax
    or $0b11, %eax                  /* present + writable */
    mov %eax, pml4
    movl $0, pml4 + 4

    cmpb $0, have_gib_pages
    je build_2m_tables

    /* PDPT[i] -> a 1 GiB page at i GiB, for all 512 entries.
     *
     * PCD (bit 4) is set on everything above the first gigabyte: that range
     * is where MMIO lives, and a cached write to a framebuffer can sit in a
     * cache line instead of reaching the display. The first gigabyte holds
     * the kernel and its stack and stays cached. */
    xor %ecx, %ecx                  /* entry index */
1:
    mov %ecx, %eax
    shl $30, %eax                   /* low half of the physical address */
    or $0b10000011, %eax            /* present + writable + huge */
    test %ecx, %ecx
    jz 2f
    or $0b10000, %eax               /* PCD on everything but entry 0 */
2:
    mov %eax, pdpt(, %ecx, 8)

    /* The upper half: bits 63:32 of the address. Entry i covers i GiB, so
     * bits 61:32 of the address are i >> 2. */
    mov %ecx, %eax
    shr $2, %eax
    mov %eax, pdpt + 4(, %ecx, 8)

    inc %ecx
    cmp $512, %ecx
    jb 1b
    ret

/* A guard page under the kernel stack.
 *
 * Without one, a stack overflow runs silently into whatever .bss holds below
 * the stack — the page directories, as it happens — and the kernel carries on
 * with corrupted state. With one, the first write past the end is a page
 * fault, reported as such.
 *
 * A 4 KiB hole cannot be punched in a 1 GiB page, so the first gigabyte is
 * re-expressed as 2 MiB pages (in `pd`'s first directory, which the 1 GiB
 * path otherwise leaves unused), and the one 2 MiB page containing the guard
 * as 4 KiB pages with the guard's entry not present. The linker script
 * asserts the image lies inside that first gigabyte. The first gigabyte stays
 * cached, exactly as before. */
install_stack_guard:
    cmpb $0, have_gib_pages
    je 1f
    xor %ecx, %ecx
2:  mov %ecx, %eax
    shl $21, %eax
    or $0b10000011, %eax            /* present + writable + 2 MiB */
    mov %eax, pd(, %ecx, 8)
    movl $0, pd + 4(, %ecx, 8)
    inc %ecx
    cmp $512, %ecx
    jb 2b
    mov $pd, %eax
    or $0b11, %eax
    mov %eax, pdpt                  /* PDPT[0] -> the directory, not a page */
    movl $0, pdpt + 4
1:
    mov $nc_stack_guard, %ebx
    shr $21, %ebx                   /* which 2 MiB page holds the guard */
    mov %ebx, %edx
    shl $21, %edx                   /* and where that page starts */
    xor %ecx, %ecx
3:  mov %ecx, %eax
    shl $12, %eax
    add %edx, %eax
    or $0b11, %eax                  /* present + writable, 4 KiB */
    mov %eax, guard_pt(, %ecx, 8)
    movl $0, guard_pt + 4(, %ecx, 8)
    inc %ecx
    cmp $512, %ecx
    jb 3b
    mov $nc_stack_guard, %eax
    shr $12, %eax
    and $511, %eax
    movl $0, guard_pt(, %eax, 8)    /* the guard: not present */
    mov $guard_pt, %eax
    or $0b11, %eax
    mov %eax, pd(, %ebx, 8)
    movl $0, pd + 4(, %ebx, 8)
    ret

/* The same map, built from 2 MiB pages, for a CPU without PDPE1GB.
 *
 * Sixty-four gigabytes rather than the 512 the 1 GiB path covers, because the
 * tables are the cost: a 2 MiB page directory covers one gigabyte, so 512
 * would need two megabytes of page tables in the image. Sixty-four needs 256
 * kilobytes and is far past anything a machine of this vintage has — 1 GiB
 * pages arrived with Westmere and Barcelona around 2009, and PCIe devices
 * with BARs above four gigabytes came years after that. A part that lands
 * here has its MMIO low.
 *
 * PCD above the first gigabyte, exactly as the other path does, and for the
 * same reason: that is where MMIO lives, and a cached write to a framebuffer
 * can sit in a cache line instead of reaching the display. */
build_2m_tables:
    /* PDPT[i] -> pd + i * 4096, for the directories that exist. */
    xor %ecx, %ecx
1:
    mov %ecx, %eax
    shl $12, %eax                   /* i * 4096 */
    add $pd, %eax
    or $0b11, %eax                  /* present + writable */
    mov %eax, pdpt(, %ecx, 8)
    movl $0, pdpt + 4(, %ecx, 8)
    inc %ecx
    cmp $PD_COUNT, %ecx
    jb 1b

    /* Every 2 MiB entry across all of them, as one flat run: directory i,
     * entry j, covers page number i * 512 + j. */
    xor %ecx, %ecx                  /* flat page index */
2:
    mov %ecx, %eax
    shl $21, %eax                   /* low half of the physical address */
    or $0b10000011, %eax            /* present + writable + huge */
    cmp $512, %ecx                  /* the first gigabyte stays cached */
    jb 3f
    or $0b10000, %eax               /* PCD */
3:
    mov %eax, pd(, %ecx, 8)

    /* Bits 63:32 of the address. Page i covers i * 2 MiB, so the high half
     * is i >> 11. */
    mov %ecx, %eax
    shr $11, %eax
    mov %eax, pd + 4(, %ecx, 8)

    inc %ecx
    cmp $(PD_COUNT * 512), %ecx
    jb 2b
    ret

enter_long_mode:
    /* CR3 points the MMU at the tables built above. */
    mov $pml4, %eax
    mov %eax, %cr3

    /* PAE (CR4 bit 5) is mandatory for long mode: the 4-level page tables
     * only exist in PAE format. */
    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4

    /* EFER.LME (bit 8) requests long mode. It does not take effect until
     * paging is enabled, which is the next step. */
    mov $0xC0000080, %ecx
    rdmsr
    or $(1 << 8), %eax
    wrmsr

    /* CR0.PG (bit 31) turns paging on, which activates long mode. The CPU is
     * in compatibility mode from here until CS is reloaded. */
    mov %cr0, %eax
    or $(1 << 31), %eax
    mov %eax, %cr0
    ret

/* Failure paths. There is no console yet — the UART is not initialised and
 * would need code that cannot run before long mode. But two things do work
 * here, and an earlier version of this used neither: the VGA text buffer is
 * plain memory at 0xB8000, and the serial port is three OUTs. So each stop
 * says which check failed instead of halting mute.
 *
 * That mattered the first time this met a CPU it could not run on. The
 * machine went black at the instant GRUB handed over, with nothing on the
 * screen and nothing on the wire, and "it does not boot" was the entire bug
 * report available. A single line naming the missing feature turns that into
 * a fact. */
no_cpuid:
    mov $msg_no_cpuid, %esi
    jmp die
no_long_mode:
    mov $msg_no_long_mode, %esi
    jmp die
no_gib_pages:
    mov $msg_no_gib_pages, %esi
    jmp die

/* Prints the NUL-terminated string at %esi and stops.
 *
 * To both outputs, because neither is guaranteed: a machine booted with no
 * display still has a serial port, and one with no serial port still has a
 * screen. Writing to both costs nothing at the point where everything has
 * already gone wrong. */
die:
    push %esi

    /* VGA text, white on red, from the top-left corner. */
    mov $0xB8000, %edi
    mov $0x4F, %ah                  /* white on red */
1:  lodsb
    test %al, %al
    jz 2f
    mov %ax, (%edi)
    add $2, %edi
    jmp 1b
2:

    /* COM1. The port is left as firmware set it: reprogramming the divisor
     * here would be one more thing to get wrong on a machine that has already
     * failed a feature check. */
    pop %esi
3:  lodsb
    test %al, %al
    jz 4f
    mov $0x3F8, %dx
    out %al, %dx
    jmp 3b
4:
    mov $'\n', %al
    mov $0x3F8, %dx
    out %al, %dx

    cli
1:  hlt
    jmp 1b

msg_no_cpuid:
    .asciz "nanochrono: this CPU has no CPUID; it predates long mode entirely"
msg_no_long_mode:
    .asciz "nanochrono: this CPU does not support long mode (64-bit)"
msg_no_gib_pages:
    .asciz "nanochrono: this CPU has no 1 GiB pages (CPUID.80000001H:EDX[26]); the boot page tables need them"

/* ---------------------------------------------------------------------------
 * 64-bit entry.
 * ------------------------------------------------------------------------ */
.code64
long_mode_start:
    /* The data segment registers still hold 32-bit selectors. Long mode
     * ignores their bases, but a stale selector faults on load, so they are
     * zeroed. */
    xor %ax, %ax
    mov %ax, %ss
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs

    /* The upper halves of the general registers are undefined after the
     * switch from protected mode, RSP included: only ESP was ever loaded.
     * A 32-bit write zero-extends, so this makes RSP exactly `stack_top`,
     * which is 4 KiB aligned — the System V rule that RSP is 16-byte
     * aligned at a `call` holds for `kmain`. */
    mov $stack_top, %esp

    /* Exceptions become reports instead of resets from here on. */
    call setup_exceptions

    /* Recover the values saved in 32-bit mode, into the first two System V
     * argument registers. A 32-bit load zero-extends, which is what is
     * wanted: both quantities are 32-bit. */
    mov boot_magic, %edi
    mov boot_info, %esi

    call kmain

    /* kmain is `-> !` and does not return. If it somehow does, stopping is
     * the only safe thing left. */
    cli
1:  hlt
    jmp 1b

/* ---------------------------------------------------------------------------
 * Exceptions.
 *
 * Without an IDT every exception is a triple fault: the CPU cannot deliver
 * the fault, cannot deliver the resulting double fault, and resets. On real
 * hardware that is a reboot loop with no message; under QEMU with
 * -no-reboot, an exit. Either way the one piece of information that matters
 * — which instruction, and why — is lost.
 *
 * So the 32 architectural exception vectors get stubs that push a uniform
 * frame and call `nanochrono_x86_exception`, which reports and halts. The
 * double fault, NMI and machine check run on their own stack (IST1): a
 * double fault is what a kernel-stack overflow becomes, and a handler that
 * pushes onto the stack that just overflowed faults a third time.
 *
 * Vectors 32-255 are left outside the IDT limit. Interrupts stay masked for
 * the whole run; one that arrives anyway raises #GP, which is reported.
 * ------------------------------------------------------------------------ */
setup_exceptions:
    /* The TSS descriptor is 16 bytes at selector 0x10. Its base is only
     * known at link time as a relocatable symbol, and the descriptor splits
     * the base across four fields, so it is assembled here. */
    lea tss64(%rip), %rax
    mov $103, %ecx                  /* limit: sizeof(TSS) - 1           */
    mov %rax, %r8
    and $0xFFFFFF, %r8              /* base[23:0] -> bits 16..39        */
    shl $16, %r8
    or %r8, %rcx
    movabs $(0x89 << 40), %r8       /* present, type 9: available TSS   */
    or %r8, %rcx
    mov %rax, %r8
    shr $24, %r8
    and $0xFF, %r8                  /* base[31:24] -> bits 56..63       */
    shl $56, %r8
    or %r8, %rcx
    mov %rcx, gdt64 + 16(%rip)
    shr $32, %rax                   /* base[63:32] in the high quadword */
    mov %rax, gdt64 + 24(%rip)

    lea ist1_top(%rip), %rax
    mov %rax, tss64 + 36(%rip)      /* IST1                             */
    lea ist2_top(%rip), %rax
    mov %rax, tss64 + 44(%rip)      /* IST2: page faults                */
    movw $104, tss64 + 102(%rip)    /* I/O map base past the limit: none */
    mov $0x10, %ax
    ltr %ax

    /* 32 interrupt gates, one per stub, 16 bytes apart. */
    lea isr_stubs(%rip), %r8
    lea idt64(%rip), %r9
    xor %ecx, %ecx
1:  mov %r8, %rax
    mov %rax, %r10
    and $0xFFFF, %r10               /* offset[15:0]                     */
    or $(0x08 << 16), %r10          /* selector: the 64-bit code segment */
    movabs $(0x8E << 40), %r11      /* present, DPL 0, interrupt gate   */
    or %r11, %r10
    mov %rax, %r11
    shr $16, %r11
    and $0xFFFF, %r11
    shl $48, %r11                   /* offset[31:16]                    */
    or %r11, %r10
    cmp $2, %ecx                    /* NMI                              */
    je 2f
    cmp $8, %ecx                    /* #DF                              */
    je 2f
    cmp $18, %ecx                   /* #MC                              */
    je 2f
    /* #PF on a stack of its own: a fault on the stack guard is taken while
     * RSP points into the guard, and pushing the frame there would fault
     * again. */
    cmp $14, %ecx
    jne 3f
    movabs $(2 << 32), %r11         /* IST2                             */
    or %r11, %r10
    jmp 3f
2:  movabs $(1 << 32), %r11         /* IST1                             */
    or %r11, %r10
3:  mov %r10, (%r9)
    shr $32, %rax                   /* offset[63:32]                    */
    mov %rax, 8(%r9)
    add $16, %r8
    add $16, %r9
    inc %ecx
    cmp $32, %ecx
    jb 1b

    lidt idt64_pointer(%rip)
    ret

/* One stub per vector, 16 bytes apart so the loop above can compute each
 * address. The CPU pushes an error code for 8, 10-14, 17, 21, 29 and 30;
 * the others push a zero so every frame has the same shape:
 *   [vector, error, RIP, CS, RFLAGS, RSP, SS] */
.balign 16
isr_stubs:
.irp v, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    .balign 16
    .if (\v == 8) || (\v == 10) || (\v == 11) || (\v == 12) || (\v == 13) || (\v == 14) || (\v == 17) || (\v == 21) || (\v == 29) || (\v == 30)
    .else
    pushq $0
    .endif
    pushq $\v
    jmp isr_common
.endr

isr_common:
    cld
    mov %rsp, %rdi                  /* the frame, as the first argument */
    and $-16, %rsp                  /* System V alignment for the call  */
    call nanochrono_x86_exception
    cli
1:  hlt
    jmp 1b

/* ---------------------------------------------------------------------------
 * Tables and stack.
 * ------------------------------------------------------------------------ */
/* In .data, not .rodata: `ltr` writes the busy bit into the TSS descriptor. */
.section .data
.align 16
gdt64:
    .quad 0                                     /* the mandatory null entry */
    /* Code segment: executable, descriptor type, present, 64-bit.
     * Long mode ignores base and limit, so only the flags matter. */
    .quad (1<<43) | (1<<44) | (1<<47) | (1<<53)
    /* 0x10: the TSS, 16 bytes, filled in by `setup_exceptions`. */
    .quad 0
    .quad 0
gdt64_end:
gdt64_pointer:
    .short gdt64_end - gdt64 - 1
    .quad gdt64

.align 16
idt64_pointer:
    .short 32 * 16 - 1
    .quad idt64

.section .data
.align 4
/* Written in 32-bit mode, read in 64-bit mode. In `.data` rather than `.bss`
 * because a multiboot loader is not required to zero `.bss`, and a stale
 * value here would be reported as a boot magic. */
boot_magic:
    .long 0
boot_info:
    .long 0

.section .bss
.align 4096
/* Whether this CPU has 1 GiB pages, recorded by `check_long_mode` and read by
 * `build_page_tables`. A byte rather than a register because the two run at
 * different points and everything in between clobbers registers freely. */
have_gib_pages:
    .byte 0
.align 4096
pml4:
    .skip 4096
pdpt:
    .skip 4096
/* Page directories for the 2 MiB fallback. One per gigabyte mapped; see
 * `build_2m_tables`. Untouched, and costing only zeroed image space, on a
 * CPU that has 1 GiB pages. */
pd:
    .skip 4096 * PD_COUNT
/* The 4 KiB table for the 2 MiB page around the stack guard. */
guard_pt:
    .skip 4096
/* Never mapped; see `install_stack_guard`. */
.global nc_stack_guard
nc_stack_guard:
    .skip 4096
stack_bottom:
    /* 64 KiB. The kernel makes no deep calls and allocates nothing, but the
     * measurement buffers are stack-resident. */
    .skip 65536
stack_top:

.align 16
idt64:
    .skip 32 * 16
tss64:
    .skip 104
.align 16
ist1_bottom:
    .skip 32768
ist1_top:
.align 16
ist2_bottom:
    .skip 32768
ist2_top:
