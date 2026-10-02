/* SPDX-License-Identifier: Apache-2.0
 *
 * UEFI loader for the NanoChronometer kernel on 32-bit ARM, RISC-V 64 and
 * RISC-V 32 — the program an ISO boots as EFI/BOOT/BOOT{ARM,RISCV64,RISCV32}.EFI,
 * under UEFI firmware (edk2) or U-Boot's EFI support alike.
 *
 * The kernel is an ordinary ELF executable linked at a fixed physical address
 * (arm32 0x40200000, riscv64 0x80200000, riscv32 0x80400000), embedded here
 * by kernel_blob.S. The loader:
 *
 *   1. reserves the kernel's address range (AllocateAddress) and copies each
 *      PT_LOAD segment to its physical address;
 *   2. finds the device tree the firmware publishes (its configuration
 *      table) and, on RISC-V, the boot hart (RISCV_EFI_BOOT_PROTOCOL);
 *   3. leaves boot services, so no firmware timer or driver runs on behind
 *      the kernel's back;
 *   4. hands the machine over as a direct boot would: on arm32 the device
 *      tree at the start of RAM, where the kernel reads it, the image cleaned
 *      from the data cache, then the MMU and the caches off; on RISC-V the
 *      hart in a0 and the device tree in a1, as the SBI passes them, with
 *      interrupts off and satp Bare;
 *   5. jumps to the ELF entry point.
 *
 * It is position independent — no absolute address anywhere in its image
 * (packaging/baremetal/build.sh links it at two bases and compares) — so it
 * runs wherever the firmware loads it. Freestanding: no library at all.
 */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef __UINTPTR_TYPE__   uintptr_t;
typedef uintptr_t          UINTN;
typedef UINTN              EFI_STATUS;
typedef void              *EFI_HANDLE;

#define EFI_SUCCESS        0
#define EFI_ERROR_BIT      ((UINTN)1 << (sizeof(UINTN) * 8 - 1))
#define ALLOCATE_ADDRESS   2
#define EFI_LOADER_DATA    2
#define PAGE_SIZE          4096u
#define PAGES(n)           (((n) + PAGE_SIZE - 1) / PAGE_SIZE)

#if __SIZEOF_POINTER__ == 8
#define ELF_CLASS 2
typedef struct {
    uint8_t  ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
} elf_ehdr;
typedef struct {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
} elf_phdr;
#else
#define ELF_CLASS 1
typedef struct {
    uint8_t  ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint32_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
} elf_ehdr;
typedef struct {
    uint32_t type, offset, vaddr, paddr, filesz, memsz, flags, align;
} elf_phdr;
#endif
#define PT_LOAD 1

typedef struct {
    uint32_t a;
    uint16_t b, c;
    uint8_t  d[8];
} EFI_GUID;

typedef struct {
    uint64_t Signature;
    uint32_t Revision, HeaderSize, CRC32, Reserved;
} EFI_TABLE_HEADER;

typedef struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void *Reset;
    EFI_STATUS (*OutputString)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, const uint16_t *String);
};

typedef struct {
    EFI_TABLE_HEADER Hdr;
    void *RaiseTPL, *RestoreTPL;
    EFI_STATUS (*AllocatePages)(UINTN Type, UINTN MemoryType, UINTN Pages, uint64_t *Memory);
    void *FreePages;
    EFI_STATUS (*GetMemoryMap)(UINTN *Size, void *Map, UINTN *Key, UINTN *DescSize, uint32_t *DescVersion);
    void *AllocatePool, *FreePool;
    void *CreateEvent, *SetTimer, *WaitForEvent, *SignalEvent, *CloseEvent, *CheckEvent;
    void *InstallProtocolInterface, *ReinstallProtocolInterface, *UninstallProtocolInterface;
    void *HandleProtocol, *Reserved, *RegisterProtocolNotify, *LocateHandle;
    void *LocateDevicePath, *InstallConfigurationTable;
    void *LoadImage, *StartImage, *Exit, *UnloadImage;
    EFI_STATUS (*ExitBootServices)(EFI_HANDLE Image, UINTN MapKey);
    void *GetNextMonotonicCount, *Stall, *SetWatchdogTimer;
    void *ConnectController, *DisconnectController;
    void *OpenProtocol, *CloseProtocol, *OpenProtocolInformation;
    void *ProtocolsPerHandle, *LocateHandleBuffer;
    EFI_STATUS (*LocateProtocol)(const EFI_GUID *Protocol, void *Registration, void **Interface);
    void *InstallMultipleProtocolInterfaces, *UninstallMultipleProtocolInterfaces;
    void *CalculateCrc32;
    void (*CopyMem)(void *Dest, const void *Src, UINTN Length);
    void (*SetMem)(void *Buffer, UINTN Size, uint8_t Value);
} EFI_BOOT_SERVICES;

typedef struct {
    EFI_GUID VendorGuid;
    void    *VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct {
    EFI_TABLE_HEADER Hdr;
    uint16_t *FirmwareVendor;
    uint32_t FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    void *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
    EFI_HANDLE StandardErrorHandle;
    void *StdErr;
    void *RuntimeServices;
    EFI_BOOT_SERVICES *BootServices;
    UINTN NumberOfTableEntries;
    EFI_CONFIGURATION_TABLE *ConfigurationTable;
} EFI_SYSTEM_TABLE;

/* The device tree's configuration table (UEFI 2.x, "EFI_DTB_TABLE"). */
static const EFI_GUID DTB_TABLE = {0xb1b621d5, 0xf19c, 0x41a5,
                                   {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}};

#if defined(__riscv)
/* RISCV_EFI_BOOT_PROTOCOL: which hart the firmware booted on. */
static const EFI_GUID RISCV_BOOT_PROTOCOL = {0xccd15fec, 0x6f73, 0x4eec,
                                             {0x83, 0x95, 0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf}};
typedef struct RISCV_EFI_BOOT_PROTOCOL RISCV_EFI_BOOT_PROTOCOL;
struct RISCV_EFI_BOOT_PROTOCOL {
    uint64_t Revision; /* 64 bits on RV32 too, so the function sits at offset 8 */
    EFI_STATUS (*GetBootHartId)(RISCV_EFI_BOOT_PROTOCOL *This, UINTN *BootHartId);
};
#endif

#if defined(__arm__)
/* Where the kernel reads the device tree: the start of RAM on QEMU's `virt`,
 * clear of the image at 0x40200000. */
#define DTB_HOME 0x40000000u
#endif

/* The kernel ELF, from kernel_blob.S; and this image's own bounds. */
extern const uint8_t kernel_image[] __attribute__((visibility("hidden")));
extern const uint8_t kernel_image_end[] __attribute__((visibility("hidden")));
extern const uint8_t __image_start[] __attribute__((visibility("hidden")));
extern const uint8_t __image_end[] __attribute__((visibility("hidden")));

/* The memory map ExitBootServices needs a key from: static, since nothing
 * may be allocated between the map and the exit. */
static uint8_t memory_map[64 * 1024];

static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *con;

static void say(const char *s)
{
    uint16_t buf[160];
    UINTN i = 0;
    for (; *s && i < 157; s++) {
        if (*s == '\n')
            buf[i++] = '\r';
        buf[i++] = (uint16_t)(uint8_t)*s;
    }
    buf[i] = 0;
    if (con)
        con->OutputString(con, buf);
}

static void say_hex(uint64_t v)
{
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; i++) {
        unsigned d = (unsigned)(v >> ((15 - i) * 4)) & 0xf;
        buf[2 + i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    buf[18] = 0;
    say(buf);
}

static int guid_eq(const EFI_GUID *x, const EFI_GUID *y)
{
    const uint8_t *a = (const uint8_t *)x, *b = (const uint8_t *)y;
    for (unsigned i = 0; i < sizeof(EFI_GUID); i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static EFI_STATUS fail(const char *why)
{
    say("NanoChronometer EFI loader: ");
    say(why);
    say("\n");
    return EFI_ERROR_BIT | 1;
}

/* Leaves boot services. The map key must be the latest map's, and the call
 * itself may change the map, so it is retried with a fresh one. */
static int exit_boot_services(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        UINTN size = sizeof(memory_map), key = 0, desc_size = 0;
        uint32_t desc_version = 0;
        if (st->BootServices->GetMemoryMap(&size, memory_map, &key, &desc_size, &desc_version) != EFI_SUCCESS)
            continue;
        if (st->BootServices->ExitBootServices(image, key) == EFI_SUCCESS)
            return 1;
    }
    return 0;
}

#if defined(__arm__)
/* Cleans and invalidates [start, end) to the point of coherency, so what was
 * written through the cache is in memory once the caches are off. */
static void dcache_clean(uintptr_t start, uintptr_t end)
{
    uint32_t ctr;
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 1" : "=r"(ctr));
    uintptr_t line = 4u << ((ctr >> 16) & 0xf);
    for (uintptr_t a = start & ~(line - 1); a < end; a += line)
        __asm__ volatile("mcr p15, 0, %0, c7, c14, 1" : : "r"(a) : "memory"); /* DCCIMVAC */
    __asm__ volatile("dsb" : : : "memory");
}

/* Interrupts off, MMU and caches off, then the kernel — in registers only,
 * from the identity-mapped code the firmware loaded this into. */
__attribute__((noreturn)) static void enter_kernel(uintptr_t entry)
{
    __asm__ volatile(
        "cpsid aif\n"
        "mrc   p15, 0, r4, c1, c0, 0\n"   /* SCTLR */
        "bic   r4, r4, #1\n"              /* M */
        "bic   r4, r4, #4\n"              /* C */
        "bic   r4, r4, #0x1000\n"         /* I */
        "mcr   p15, 0, r4, c1, c0, 0\n"
        "isb\n"
        "mov   r4, #0\n"
        "mcr   p15, 0, r4, c7, c5, 0\n"   /* ICIALLU */
        "mcr   p15, 0, r4, c7, c5, 6\n"   /* BPIALL */
        "dsb\n"
        "isb\n"
        "mov   r0, #0\n"
        "mvn   r1, #0\n"
        "mov   r2, %1\n"                  /* the device tree, Linux-style, too */
        "bx    %0\n"
        :
        : "r"(entry), "r"((uintptr_t)DTB_HOME)
        : "r0", "r1", "r2", "r4", "memory");
    __builtin_unreachable();
}
#elif defined(__riscv)
/* Interrupts off and satp Bare, then the kernel with the SBI's registers:
 * a0 = hart, a1 = device tree. */
__attribute__((noreturn)) static void enter_kernel(uintptr_t entry, uintptr_t hart, uintptr_t dtb)
{
    register uintptr_t a0 __asm__("a0") = hart;
    register uintptr_t a1 __asm__("a1") = dtb;
    __asm__ volatile(
        "csrci sstatus, 2\n"              /* SIE */
        "csrw  sie, zero\n"
        "csrw  satp, zero\n"
        "sfence.vma\n"
        "fence.i\n"
        "jr    %0\n"
        :
        : "r"(entry), "r"(a0), "r"(a1)
        : "memory");
    __builtin_unreachable();
}
#endif

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    con = st->ConOut;
#if defined(__arm__)
    say("NanoChronometer EFI loader (arm32)\n");
#elif __riscv_xlen == 64
    say("NanoChronometer EFI loader (riscv64)\n");
#else
    say("NanoChronometer EFI loader (riscv32)\n");
#endif

    /* The embedded ELF: little-endian, this target's class. */
    const uint8_t *img = kernel_image;
    const elf_ehdr *eh = (const elf_ehdr *)img;
    if ((UINTN)(kernel_image_end - kernel_image) < sizeof(elf_ehdr) ||
        img[0] != 0x7f || img[1] != 'E' || img[2] != 'L' || img[3] != 'F' ||
        img[4] != ELF_CLASS || img[5] != 1)
        return fail("the embedded kernel is not an ELF for this target");

    uint64_t base = ~(uint64_t)0, cap = 0;
    for (unsigned i = 0; i < eh->phnum; i++) {
        const elf_phdr *p = (const elf_phdr *)(img + eh->phoff + (UINTN)i * eh->phentsize);
        if (p->type != PT_LOAD || p->memsz == 0)
            continue;
        if (p->paddr < base)
            base = p->paddr;
        if (p->paddr + p->memsz > cap)
            cap = p->paddr + p->memsz;
    }
    if (cap <= base || eh->entry < base || eh->entry >= cap)
        return fail("the embedded kernel has no loadable image around its entry");
    base &= ~(uint64_t)(PAGE_SIZE - 1);

    /* Reserve the range, so nothing the firmware does before the exit lands
     * on it. On arm32 it starts at the device tree's home when that is free;
     * when the firmware holds it (the tree QEMU put there, say), the kernel's
     * own range is enough. */
    uint64_t start = base, at = base;
#if defined(__arm__)
    at = DTB_HOME;
    if (st->BootServices->AllocatePages(ALLOCATE_ADDRESS, EFI_LOADER_DATA, PAGES(cap - DTB_HOME), &at) == EFI_SUCCESS &&
        at == DTB_HOME)
        start = DTB_HOME;
    else
        at = base;
#endif
    if (start == base &&
        (st->BootServices->AllocatePages(ALLOCATE_ADDRESS, EFI_LOADER_DATA, PAGES(cap - base), &at) != EFI_SUCCESS ||
         at != base)) {
        say("the range ");
        say_hex(base);
        say(" .. ");
        say_hex(cap);
        say(" is taken\n");
        return fail("cannot reserve the kernel's memory");
    }

    for (unsigned i = 0; i < eh->phnum; i++) {
        const elf_phdr *p = (const elf_phdr *)(img + eh->phoff + (UINTN)i * eh->phentsize);
        if (p->type != PT_LOAD || p->memsz == 0)
            continue;
        st->BootServices->CopyMem((void *)(uintptr_t)p->paddr, img + p->offset, (UINTN)p->filesz);
        if (p->memsz > p->filesz)
            st->BootServices->SetMem((void *)(uintptr_t)(p->paddr + p->filesz), (UINTN)(p->memsz - p->filesz), 0);
    }

    /* The device tree the firmware publishes. */
    const uint8_t *dtb = 0;
    for (UINTN i = 0; i < st->NumberOfTableEntries; i++)
        if (guid_eq(&st->ConfigurationTable[i].VendorGuid, &DTB_TABLE))
            dtb = st->ConfigurationTable[i].VendorTable;
    if (!dtb || be32(dtb) != 0xd00dfeed)
        return fail("the firmware publishes no device tree");
    uint32_t dtb_size = be32(dtb + 4);

#if defined(__riscv)
    UINTN hart = 0;
    RISCV_EFI_BOOT_PROTOCOL *boot = 0;
    if (st->BootServices->LocateProtocol(&RISCV_BOOT_PROTOCOL, 0, (void **)&boot) == EFI_SUCCESS && boot)
        boot->GetBootHartId(boot, &hart);
#endif
#if defined(__arm__)
    if (DTB_HOME + dtb_size > base)
        return fail("the device tree does not fit below the kernel");
    /* Its home must not be where this loader runs. */
    if ((uintptr_t)dtb != DTB_HOME && (uintptr_t)__image_start < DTB_HOME + dtb_size &&
        (uintptr_t)__image_end > DTB_HOME)
        return fail("this loader sits where the device tree goes");
#endif

    say("kernel ");
    say_hex(base);
    say(" .. ");
    say_hex(cap);
    say(", entry ");
    say_hex(eh->entry);
    say(", device tree ");
    say_hex((uintptr_t)dtb);
    say(" (");
    say_hex(dtb_size);
    say(" bytes)");
#if defined(__riscv)
    say(", hart ");
    say_hex(hart);
#endif
    say("\nleaving boot services\n");

    if (!exit_boot_services(image, st))
        return fail("ExitBootServices failed");
    con = 0; /* the console is gone with boot services */

#if defined(__arm__)
    /* The device tree to its home, as memmove would: the two may overlap.
     * Byte by byte, through a volatile pointer, so no library call is made. */
    volatile uint8_t *to = (volatile uint8_t *)(uintptr_t)DTB_HOME;
    if ((uintptr_t)dtb > DTB_HOME)
        for (uint32_t i = 0; i < dtb_size; i++)
            to[i] = dtb[i];
    else if ((uintptr_t)dtb < DTB_HOME)
        for (uint32_t i = dtb_size; i-- > 0;)
            to[i] = dtb[i];
    dcache_clean(DTB_HOME, (uintptr_t)cap);
    enter_kernel((uintptr_t)eh->entry);
#else
    enter_kernel((uintptr_t)eh->entry, hart, (uintptr_t)dtb);
#endif
}
