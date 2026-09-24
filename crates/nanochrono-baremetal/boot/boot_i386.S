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
 * target is pentium4, so the compiler emits SSE2), and call kmain with the
 * two values as cdecl arguments.
 */

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
    /* EAX = boot magic, EBX = info pointer. Kept in callee-saved registers
     * across the zeroing and the SSE setup, whose CPUID clobbers EAX-EDX. */
    mov %eax, %esi
    mov %ebx, %edi

    /* Direction flag clear before `rep stos`, and for the Rust ABI. */
    cld
    push %edi
    mov $__bss_start, %edi
    mov $__bss_end, %ecx
    sub %edi, %ecx
    shr $2, %ecx
    xor %eax, %eax
    rep stosl
    pop %edi

    mov $stack_top, %esp
    push %esi
    push %edi
    call enable_sse
    pop %edi
    pop %esi

    /* kmain(magic, info), cdecl: arguments pushed right to left. The stack
     * is 16-byte aligned at the call, as the i386 SysV ABI with SSE wants. */
    and $~15, %esp
    sub $8, %esp
    push %edi
    push %esi
    call kmain
1:  cli
    hlt
    jmp 1b

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


.section .bss
.align 16
stack_bottom:
    .skip 131072
stack_top:
