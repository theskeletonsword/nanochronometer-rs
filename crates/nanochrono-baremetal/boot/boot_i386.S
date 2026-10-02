/* SPDX-License-Identifier: Apache-2.0
 *
 * The i386 entry: what boot32.S does for x86_64, minus everything that exists
 * only to reach long mode. A multiboot loader already leaves the CPU in 32-bit
 * protected mode with flat segments, which is exactly what a 32-bit Rust
 * kernel runs in — so there are no page tables to build and no mode to
 * switch. With paging off every physical address is directly usable, which
 * is also the limit: a framebuffer above 4 GiB is out of reach (that would
 * take PAE), and the interface then falls back to the serial console.
 *
 * What remains is what Rust cannot do for itself before it has a stack:
 * save the loader's registers, zero .bss, set the stack, enable SSE (the
 * target is pentium4, so the compiler emits SSE2), load descriptor tables of
 * its own — without an IDT every exception is a triple fault — turn on
 * paging, and call kmain with the two values as cdecl arguments. */

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
    /* EAX = boot magic, EBX = info pointer. Kept in ESI and EBP, which the
     * zeroing, the SSE setup (CPUID clobbers EAX-EDX) and the descriptor
     * setup leave alone. Multiboot leaves ESP undefined, so nothing is
     * pushed before the stack below exists. */
    mov %eax, %esi
    mov %ebx, %ebp

    /* Direction flag clear before `rep stos`, and for the Rust ABI. */
    cld
    mov $__bss_start, %edi
    mov $__bss_end, %ecx
    sub %edi, %ecx
    shr $2, %ecx
    xor %eax, %eax
    rep stosl

    mov $stack_top, %esp
    call enable_sse
    call setup_descriptors
    call enable_paging

    /* kmain(magic, info), cdecl: arguments pushed right to left. The stack
     * is 16-byte aligned at the call, as the i386 SysV ABI with SSE wants. */
    and $~15, %esp
    sub $8, %esp
    push %ebp
    push %esi
    call kmain
1:  cli
    hlt
    jmp 1b

/* Every floating-point and SIMD fault must reach the IDT below, and from it
 * the stop screen: CR0.NE makes an x87 error #MF (vector 16) — clear, it is
 * reported the PC/AT way, FERR# to IRQ 13, and with interrupts masked for the
 * whole run the core just stops at the next x87 instruction, with no fault
 * and nothing on the screen; CR4.OSXMMEXCPT makes an unmasked SSE/AVX
 * exception #XM (vector 19) rather than #UD; and CR0.TS is cleared, or the
 * first SSE instruction would be #NM. */
enable_sse:
    mov %cr0, %eax
    and $~((1 << 2) | (1 << 3)), %eax   /* EM: no emulation; TS: no task-switch trap */
    or  $((1 << 1) | (1 << 5)), %eax    /* MP: monitor coprocessor; NE: native #MF */
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
     * OSXSAVE is set only when XSAVE *and* AVX exist (the CPUID half of the
     * control dispatcher, nanochrono_core::cpu_control): XSAVE without AVX
     * has no state beyond x87 and SSE to manage, and turning the machinery on
     * for nothing costs power and a larger state footprint. With it clear,
     * XGETBV is #UD, so the feature detection reads XCR0 only after
     * CPUID.1:ECX.OSXSAVE says the bit is set (xcr0_safe) and reports AVX
     * and AVX-512 off, which on such a part they are. */
    mov $1, %eax
    cpuid
    test $(1 << 26), %ecx           /* CPUID.1:ECX[26], XSAVE */
    jz 2f
    test $(1 << 28), %ecx           /* CPUID.1:ECX[28], AVX */
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
    /* A defined x87 and SSE state, whatever the loader left: every exception
     * masked, round to nearest (FCW 0x037F, MXCSR 0x1F80). */
    fninit
    push $0x1F80
    ldmxcsr (%esp)
    add $4, %esp
    ret

/* ---------------------------------------------------------------------------
 * Descriptor tables.
 *
 * The loader's GDT is not this kernel's to rely on — the multiboot
 * specification says to load one's own before loading a segment register,
 * and delivering an exception loads CS from the gate — and there is no IDT
 * at all: every exception would be a triple fault, a reset with nothing said.
 * So: a flat GDT, a TSS, and the 32 architectural exception vectors — the
 * floating-point and SIMD ones included, #NM (7), #MF (16), #AC (17) and #XM
 * (19) — as interrupt gates to stubs that push a uniform frame and call
 * `nanochrono_i386_exception`, which reports through the panic path to the
 * UART and the stop screen.
 *
 * The double fault is a task gate instead: a fault that cannot be delivered
 * on the current stack (a bad SS:ESP) raises #DF, and an interrupt gate would
 * push that onto the same stack and fault a third time. A task switch loads
 * a stack of its own from the double-fault TSS — 32-bit protected mode's
 * counterpart of x86_64's IST1. The state at the fault is then in the
 * kernel's TSS, where the switch saved it.
 *
 * Vectors 32-255 are left outside the IDT limit. Interrupts stay masked for
 * the whole run; one that arrives anyway raises #GP, which is reported.
 * ------------------------------------------------------------------------ */
setup_descriptors:
    mov $tss_main, %eax
    mov $gdt32 + 0x18, %edx
    call set_tss_descriptor
    mov $tss_df, %eax
    mov $gdt32 + 0x20, %edx
    call set_tss_descriptor

    lgdt gdt32_pointer
    ljmp $0x08, $1f
1:  mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    /* The double-fault task: flat segments, interrupts off, its own stack.
     * Paging is off, so CR3 means nothing, but a task switch loads it. */
    mov %cr3, %eax
    mov %eax, tss_df + 28           /* CR3                              */
    movl $df_task, tss_df + 32      /* EIP                              */
    movl $2, tss_df + 36            /* EFLAGS: reserved bit 1, IF clear */
    movl $df_stack_top, tss_df + 56 /* ESP                              */
    movl $df_stack_top, tss_df + 4  /* ESP0                             */
    movl $0x10, tss_df + 8          /* SS0                              */
    movl $0x10, tss_df + 72         /* ES                               */
    movl $0x08, tss_df + 76         /* CS                               */
    movl $0x10, tss_df + 80         /* SS                               */
    movl $0x10, tss_df + 84         /* DS                               */
    movl $0x10, tss_df + 88         /* FS                               */
    movl $0x10, tss_df + 92         /* GS                               */
    movw $104, tss_df + 102         /* I/O map base past the limit: none */
    movw $104, tss_main + 102
    mov $0x18, %ax
    ltr %ax

    /* 32 gates, one per stub, 16 bytes apart; #DF a task gate. */
    mov $isr_stubs32, %ecx
    mov $idt32, %edi
    xor %ebx, %ebx
2:  mov %ecx, %eax
    and $0xFFFF, %eax
    or $(0x08 << 16), %eax          /* selector: code; offset[15:0]     */
    mov %eax, (%edi)
    mov %ecx, %eax
    and $0xFFFF0000, %eax
    or $0x8E00, %eax                /* present, DPL 0, interrupt gate   */
    mov %eax, 4(%edi)
    cmp $8, %ebx
    jne 3f
    movl $(0x20 << 16), (%edi)      /* the double-fault TSS             */
    movl $0x8500, 4(%edi)           /* present, DPL 0, task gate        */
3:  add $16, %ecx
    add $8, %edi
    inc %ebx
    cmp $32, %ebx
    jb 2b

    lidt idt32_pointer
    ret

/* ---------------------------------------------------------------------------
 * Paging.
 *
 * CR0.PG, with an identity map of the 4 GiB a 32-bit kernel can address, in
 * 4 MiB pages (CR4.PSE): one page directory of 1024 entries and nothing
 * else. Physical addresses stay what every driver here uses — ACPI tables,
 * PCI BARs, the framebuffer — and the kernel gains what paging gives:
 *
 * * the first gigabyte, where the image and its stacks live, cached and
 *   global (G: survives CR3 loads once the control dispatcher sets
 *   CR4.PGE); everything above it uncached (PCD), because that is where
 *   MMIO and the framebuffer live, exactly as on x86_64;
 * * the top 4 MiB left unmapped — firmware flash, which the kernel never
 *   reads after boot — so `crashtest=pf` has an address that faults and the
 *   page-fault path can be proven here too;
 * * CR0.WP, so a read-only mapping would bind ring 0 as well.
 *
 * A part without PSE (none this kernel's pentium4 baseline can run on) keeps
 * paging off rather than taking a #GP. */
enable_paging:
    mov $1, %eax
    cpuid
    test $(1 << 3), %edx            /* CPUID.1:EDX[3], PSE */
    jz 9f
    xor %ecx, %ecx
1:  mov %ecx, %eax
    shl $22, %eax                   /* entry i maps i * 4 MiB */
    or $0x83, %eax                  /* present + writable + 4 MiB (PS) */
    cmp $256, %ecx
    jae 2f
    or $0x100, %eax                 /* the first GiB: global */
    jmp 3f
2:  or $0x10, %eax                  /* above it: PCD */
3:  cmp $1023, %ecx
    jne 4f
    xor %eax, %eax                  /* the top 4 MiB: not present */
4:  mov %eax, page_directory(, %ecx, 4)
    inc %ecx
    cmp $1024, %ecx
    jb 1b
    mov %cr4, %eax
    or $(1 << 4), %eax              /* PSE */
    mov %eax, %cr4
    mov $page_directory, %eax
    mov %eax, %cr3
    /* The double-fault task switch loads CR3 from its TSS, which
     * setup_descriptors filled before paging existed: it must name this
     * directory, or #DF would run on whatever CR3 held then. */
    mov %eax, tss_df + 28
    mov %cr0, %eax
    or $((1 << 31) | (1 << 16)), %eax   /* PG, WP */
    mov %eax, %cr0
    jmp 9f                          /* a branch after enabling paging */
9:  ret

/* An available 32-bit TSS descriptor for the TSS at EAX (104 bytes), written
 * to EDX. */
set_tss_descriptor:
    movw $103, (%edx)               /* limit[15:0]                      */
    mov %ax, 2(%edx)                /* base[15:0]                       */
    mov %eax, %ecx
    shr $16, %ecx
    mov %cl, 4(%edx)                /* base[23:16]                      */
    movb $0x89, 5(%edx)             /* present, DPL 0, type 9           */
    movb $0, 6(%edx)                /* limit[19:16], byte granularity   */
    mov %ch, 7(%edx)                /* base[31:24]                      */
    ret

/* One stub per vector, 16 bytes apart so the loop above can compute each
 * address. The CPU pushes an error code for 8, 10-14, 17, 21, 29 and 30;
 * the others push a zero so every frame has the same shape:
 *   [vector, error, EIP, CS, EFLAGS]
 * (#DF's stub is never reached: its gate is the task gate.) */
.balign 16
isr_stubs32:
.irp v, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    .balign 16
    .if (\v == 8) || (\v == 10) || (\v == 11) || (\v == 12) || (\v == 13) || (\v == 14) || (\v == 17) || (\v == 21) || (\v == 29) || (\v == 30)
    .else
    pushl $0
    .endif
    pushl $\v
    jmp isr_common32
.endr

isr_common32:
    cld
    /* CR0.TS clear before any Rust, which uses SSE freely: for an #NM the
     * handler would otherwise fault on its own first SSE instruction. */
    clts
    pusha
    /* pusha stored the ESP from before it — the vector's address. The ESP at
     * the fault is past the CPU's frame (no privilege change, so it pushed
     * no SS:ESP): 13 words up. `TrapFrame32` reads it from that slot. */
    lea 52(%esp), %eax
    mov %eax, 12(%esp)
exception_frame32:
    mov %esp, %ebx
    and $~15, %esp
    sub $12, %esp
    push %ebx
    call nanochrono_i386_exception
1:  cli
    hlt
    jmp 1b

/* The double-fault task. The switch saved the interrupted state in tss_main
 * and pushed #DF's error code (zero) on this task's stack; the frame
 * isr_common32 would have built is rebuilt from that state. */
df_task:
    cld
    clts
    pushl tss_main + 36             /* EFLAGS                           */
    pushl tss_main + 76             /* CS                               */
    pushl tss_main + 32             /* EIP                              */
    pushl $0                        /* error code                       */
    pushl $8                        /* vector                           */
    pushl tss_main + 40             /* EAX                              */
    pushl tss_main + 44             /* ECX                              */
    pushl tss_main + 48             /* EDX                              */
    pushl tss_main + 52             /* EBX                              */
    pushl tss_main + 56             /* ESP                              */
    pushl tss_main + 60             /* EBP                              */
    pushl tss_main + 64             /* ESI                              */
    pushl tss_main + 68             /* EDI                              */
    jmp exception_frame32

/* ---------------------------------------------------------------------------
 * Tables and stacks.
 * ------------------------------------------------------------------------ */
/* In .data, not .rodata: `ltr` and the task switch write the busy bits into
 * the TSS descriptors. Flat 4 GiB code and data, the two TSSs, and a stack
 * segment one byte long that only `crashtest=df` loads. */
.section .data
.align 16
gdt32:
    .quad 0                         /* 0x00 null                        */
    .quad 0x00CF9A000000FFFF        /* 0x08 code: base 0, 4 GiB, 32-bit */
    .quad 0x00CF92000000FFFF        /* 0x10 data: base 0, 4 GiB, 32-bit */
    .quad 0                         /* 0x18 the kernel's TSS            */
    .quad 0                         /* 0x20 the double-fault TSS        */
    .quad 0x0040920000000000        /* 0x28 data, limit 0: crashtest=df */
gdt32_end:
.align 4
gdt32_pointer:
    .short gdt32_end - gdt32 - 1
    .long gdt32
.align 4
idt32_pointer:
    .short 32 * 8 - 1
    .long idt32

.section .bss
.align 4096
page_directory:
    .skip 4096
.align 16
idt32:
    .skip 32 * 8
tss_main:
    .skip 104
.align 16
tss_df:
    .skip 104
.align 16
df_stack_bottom:
    .skip 16384
df_stack_top:
.align 16
stack_bottom:
    .skip 131072
stack_top:
