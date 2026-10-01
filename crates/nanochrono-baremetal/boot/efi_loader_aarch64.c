/* SPDX-License-Identifier: Apache-2.0
 *
 * UEFI loader for the AArch64 NanoChronometer freestanding kernel.
 *
 * GRUB2's arm64-efi port cannot load a bare ELF kernel (its `linux` command
 * wants a Linux image with an EFI stub, and there is no multiboot2 on ARM).
 * The supported way to start other code from GRUB2 on AArch64 is
 * `chainloader`, which transfers control to a PE/COFF EFI application. That
 * is what this is.
 *
 * The kernel is an ordinary ELF64 executable linked at 0x40200000 (2 MiB into
 * the `virt` machine's RAM, clear of the devicetree QEMU puts at its start).  It sets
 * up its own stack and zeroes its own .bss in `_start`, but it is not fully
 * relocatable: data (Rust vtables, statics) keeps absolute addresses that
 * assume the linked base, so the image must be loaded at exactly 0x40200000.
 * The loader therefore:
 *
 *   1. allocates the needed pages at that exact address (AllocateAddress);
 *   2. copies each PT_LOAD segment to its linked virtual address;
 *   3. leaves boot services (ExitBootServices), so no firmware timer or
 *      driver runs on behind the kernel's back;
 *   4. hands over the machine as a firmware's direct boot would: interrupts
 *      masked, the image cleaned from the data cache to the point of
 *      coherency, then the MMU and the caches off — the kernel's entry
 *      assumes exactly that, and turns them back on with its own tables;
 *   5. jumps to the ELF entry point `e_entry`.
 *
 * We cannot allocate at the base with a plain `chainloader`, which is why this
 * EFI wrapper exists: the image is embedded in the PE and copied to the
 * base by this code before control is passed.
 */
typedef unsigned long long   uint64_t;
typedef unsigned int         uint32_t;
typedef unsigned short       uint16_t;
typedef unsigned char        uint8_t;
typedef unsigned long        uintptr_t;
typedef void                 VOID;
typedef unsigned long long   EFI_STATUS;
typedef void                *EFI_HANDLE;

#define EFI_SUCCESS 0

/* ELF64 file header as used by the AArch64 kernel image. */
typedef struct {
    uint8_t  Ident[16];
    uint16_t Type;
    uint16_t Machine;
    uint32_t Version;
    uint64_t Entry;
    uint64_t Phoff;
    uint64_t Shoff;
    uint32_t Flags;
    uint16_t Ehsize;
    uint16_t Phentsize;
    uint16_t Phnum;
    uint16_t Shentsize;
    uint16_t Shnum;
    uint16_t Shstrndx;
} Elf64_Ehdr;

/* ELF64 program header (56 bytes). */
typedef struct {
    uint32_t Type;
    uint32_t Flags;
    uint64_t Offset;
    uint64_t Vaddr;
    uint64_t Paddr;
    uint64_t Filesz;
    uint64_t Memsz;
    uint64_t Align;
} Elf64_Phdr;

#define PT_LOAD 1
#define EI_CLASS_BASE 4
#define ELFCLASS64 2
#define EI_DATA 5
#define ELFDATA2LSB 1
#define ELF_MAGIC0 0x7f
#define ELF_MAGIC1 'E'
#define ELF_MAGIC2 'L'
#define ELF_MAGIC3 'F'

typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
} EFI_GUID;

typedef struct {
    uint64_t Signature;
    uint32_t Revision;
    uint32_t HeaderSize;
    uint32_t CRC32;
    uint32_t Reserved;
} EFI_TABLE_HEADER;

typedef struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef EFI_STATUS (*EFI_TEXT_STRING)(
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    const uint16_t *String);

struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void  *Reset;
    EFI_TEXT_STRING OutputString;
    void  *TestString;
    void  *QueryMode;
    void  *SetMode;
    void  *SetAttribute;
    void  *ClearScreen;
    void  *SetCursorPosition;
    void  *EnableCursor;
    void  *Mode;
};

typedef EFI_STATUS (*EFI_ALLOCATE_PAGES)(
    int Type, int MemoryType, uint64_t Pages, uint64_t *Memory);

typedef VOID (*EFI_COPY_MEM)(VOID *Dest, const VOID *Src, uint64_t Len);

typedef EFI_STATUS (*EFI_GET_MEMORY_MAP)(
    uint64_t *MemoryMapSize, VOID *MemoryMap, uint64_t *MapKey,
    uint64_t *DescriptorSize, uint32_t *DescriptorVersion);

typedef EFI_STATUS (*EFI_EXIT_BOOT_SERVICES)(EFI_HANDLE ImageHandle, uint64_t MapKey);

typedef struct EFI_BOOT_SERVICES EFI_BOOT_SERVICES;

struct EFI_BOOT_SERVICES {
    EFI_TABLE_HEADER Hdr;
    void  *RaiseTPL;
    void  *RestoreTPL;
    EFI_ALLOCATE_PAGES AllocatePages;
    void  *FreePages;
    EFI_GET_MEMORY_MAP GetMemoryMap;
    void  *AllocatePool;
    void  *FreePool;
    void  *CreateEvent;
    void  *SetTimer;
    void  *WaitForEvent;
    void  *SignalEvent;
    void  *CloseEvent;
    void  *CheckEvent;
    void  *InstallProtocolInterface;
    void  *ReinstallProtocolInterface;
    void  *UninstallProtocolInterface;
    void  *HandleProtocol;
    void  *Reserved;
    void  *RegisterProtocolNotify;
    void  *LocateHandle;
    void  *LocateDevicePath;
    void  *InstallConfigurationTable;
    void  *LoadImage;
    void  *StartImage;
    void  *Exit;
    void  *UnloadImage;
    EFI_EXIT_BOOT_SERVICES ExitBootServices;
    void  *GetNextMonotonicCount;
    void  *Stall;
    void  *SetWatchdogTimer;
    void  *ConnectController;
    void  *DisconnectController;
    void  *OpenProtocol;
    void  *CloseProtocol;
    void  *OpenProtocolInformation;
    void  *ProtocolsPerHandle;
    void  *LocateHandleBuffer;
    void  *LocateProtocol;
    void  *InstallMultipleProtocolInterfaces;
    void  *UninstallMultipleProtocolInterfaces;
    void  *CalculateCrc32;
    EFI_COPY_MEM CopyMem;
    void  *SetMem;
    void  *CreateEventEx;
};

typedef struct {
    EFI_TABLE_HEADER Hdr;
    void  *FirmwareVendor;
    uint32_t FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    void  *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
    EFI_HANDLE StandardErrorHandle;
    void  *StdErr;
    void  *RuntimeServices;
    EFI_BOOT_SERVICES *BootServices;
    uint64_t NumberOfTableEntries;
    void  *ConfigurationTable;
} EFI_SYSTEM_TABLE;

#define EFI_LOADER_CODE   1
#define ALLOCATE_ANY_PAGES 0
#define ALLOCATE_ADDRESS  2
#define EFI_SIZE_TO_PAGES(a) (((a) >> 12) + (((a) & 0xfff) ? 1 : 0))

/* The kernel is an ordinary aarch64 bare-metal image linked at a fixed
 * virtual base (0x40200000, 2 MiB into the `virt` machine's RAM).  It uses
 * PC-relative code for control flow but keeps absolute addresses (Rust
 * vtables, statics) that assume it runs at its linked base, so it must be
 * loaded at exactly that address. */
#define KERNEL_BASE 0x40200000ull

/* The kernel ELF image, embedded as a raw blob. */
extern const unsigned char kernel_image[];
extern const unsigned char kernel_image_end[];

static void put_string(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *con, const char *msg)
{
    uint16_t buf[128];
    uint16_t *o = buf;
    while (*msg && (o - buf) < 127)
        *o++ = (uint16_t)*msg++;
    *o = 0;
    con->OutputString(con, buf);
}

/* The memory map ExitBootServices needs a key from. Sized for any firmware's
 * map with room to spare; static, as no allocation may happen in between. */
static uint8_t memory_map[64 * 1024];

/* Leaves boot services. The map key must be the one of the latest map, and
 * the call itself may change the map, so it is tried again with a fresh one
 * as the specification says. */
static int exit_boot_services(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        uint64_t size = sizeof(memory_map), key = 0, desc_size = 0;
        uint32_t desc_version = 0;
        if (st->BootServices->GetMemoryMap(&size, memory_map, &key,
                                           &desc_size, &desc_version) != EFI_SUCCESS)
            continue;
        if (st->BootServices->ExitBootServices(image, key) == EFI_SUCCESS)
            return 1;
    }
    return 0;
}

/* Cleans and invalidates [start, end) from the data cache to the point of
 * coherency, turns the MMU and both caches off at the current exception
 * level (EL1 or EL2), and branches to `entry`. Nothing touches memory after
 * the caches go off: what follows runs in registers, from the identity-mapped
 * code UEFI loaded. */
__attribute__((noreturn, naked))
static void enter_kernel(uint64_t entry, uint64_t start, uint64_t end)
{
    __asm__ volatile(
        "msr  daifset, #0xf\n"
        "mrs  x3, ctr_el0\n"
        "ubfx x3, x3, #16, #4\n"          /* DminLine: log2(words) */
        "mov  x4, #4\n"
        "lsl  x4, x4, x3\n"               /* line size in bytes */
        "sub  x5, x4, #1\n"
        "bic  x1, x1, x5\n"
        "1:\n"
        "dc   civac, x1\n"
        "add  x1, x1, x4\n"
        "cmp  x1, x2\n"
        "b.lo 1b\n"
        "dsb  sy\n"
        "mrs  x3, CurrentEL\n"
        "cmp  x3, #8\n"                   /* EL2 */
        "b.eq 2f\n"
        "mrs  x3, sctlr_el1\n"
        "bic  x3, x3, #1\n"               /* M */
        "bic  x3, x3, #4\n"               /* C */
        "bic  x3, x3, #0x1000\n"          /* I */
        "msr  sctlr_el1, x3\n"
        "b    3f\n"
        "2:\n"
        "mrs  x3, sctlr_el2\n"
        "bic  x3, x3, #1\n"
        "bic  x3, x3, #4\n"
        "bic  x3, x3, #0x1000\n"
        "msr  sctlr_el2, x3\n"
        "3:\n"
        "isb\n"
        "ic   iallu\n"
        "dsb  sy\n"
        "isb\n"
        "br   x0\n");
}

void panic(EFI_SYSTEM_TABLE *st)
{
    put_string(st->ConOut, "NanoChronometer loader: fatal\n");
    for (;;)
        __asm__ volatile("wfe");
    __builtin_unreachable();
}

__attribute__((noreturn))
EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    /* Validate and parse the embedded ELF. */
    const uint8_t *img = kernel_image;
    if (img[0] != ELF_MAGIC0 || img[1] != ELF_MAGIC1 ||
        img[2] != ELF_MAGIC2 || img[3] != ELF_MAGIC3) {
        panic(st);
    }
    if (img[EI_CLASS_BASE] != ELFCLASS64 || img[EI_DATA] != ELFDATA2LSB) {
        panic(st);
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)img;
    uint64_t base = 0, cap = 0;
    const unsigned char *ph = img + eh->Phoff;
    unsigned int phnum = eh->Phnum;
    unsigned int i;

    for (i = 0; i < phnum; i++) {
        const Elf64_Phdr *p = (const Elf64_Phdr *)(ph + (uint64_t)i * eh->Phentsize);
        if (p->Type != PT_LOAD || p->Memsz == 0)
            continue;
        if (base == 0 || p->Vaddr < base)
            base = p->Vaddr;
        if (p->Vaddr + p->Memsz > cap)
            cap = p->Vaddr + p->Memsz;
    }

    if (base == 0 || cap <= base || eh->Entry < base || eh->Entry >= cap) {
        panic(st);
    }
    if (base != KERNEL_BASE) {
        panic(st);
    }

    /* Reserve enough pages for the full image (loadable segments plus .bss),
     * at exactly the linked base so absolute data references stay valid.
     * AllocateAddress uses the value of *Memory as the requested address, so
     * it must hold the base before the call. */
    uint64_t need = (uint64_t)EFI_SIZE_TO_PAGES(cap - base);
    uint64_t addr = base;
    EFI_STATUS status = st->BootServices->AllocatePages(
        ALLOCATE_ADDRESS, EFI_LOADER_CODE, need, &addr);
    if (status != EFI_SUCCESS) {
        panic(st);
    }
    if (addr != base) {
        panic(st);
    }

    /* Copy the loadable segments to their linked virtual addresses. */
    for (i = 0; i < phnum; i++) {
        const Elf64_Phdr *p = (const Elf64_Phdr *)(ph + (uint64_t)i * eh->Phentsize);
        if (p->Type != PT_LOAD || p->Filesz == 0)
            continue;
        st->BootServices->CopyMem(
            (VOID *)(addr + (p->Vaddr - base)),
            (const VOID *)(img + p->Offset),
            p->Filesz);
    }

    /* The kernel `_start` zeroes .bss and sets up its own stack, then jumps
     * to `kmain`, which enables the MMU with its own tables: it has to find
     * the machine as a firmware's direct boot leaves it (see the top). */
    if (!exit_boot_services(image, st)) {
        panic(st);
    }
    enter_kernel(addr + (eh->Entry - base), addr, addr + (cap - base));
}