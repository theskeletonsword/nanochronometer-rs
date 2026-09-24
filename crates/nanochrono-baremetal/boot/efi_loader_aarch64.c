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
 *   3. jumps to the ELF entry point `e_entry`.
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

typedef struct EFI_BOOT_SERVICES EFI_BOOT_SERVICES;

struct EFI_BOOT_SERVICES {
    EFI_TABLE_HEADER Hdr;
    void  *RaiseTPL;
    void  *RestoreTPL;
    EFI_ALLOCATE_PAGES AllocatePages;
    void  *FreePages;
    void  *GetMemoryMap;
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
    void  *ExitBootServices;
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
     * to `kmain`.  Pass control at the relocated entry point. */
    typedef void (*entry_fn)(void);
    entry_fn entry = (entry_fn)(uintptr_t)(addr + (eh->Entry - base));
    entry();

    __builtin_unreachable();
}