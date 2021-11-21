#include "types.h"
#include "memlayout.h"

#define ACPI_BASE PHYSTOP
#define SRAT_PHYS_SIZE 10

#define CPU_CONFIG 0
#define MEM_CONFIG 1

typedef unsigned long size_t;
struct RSDT
{
    char Signature[4];
    uint32 Length;
    uint8 Revision;
    uint8 Checksum;
    char OEMID[6];
    char OEMTableID[8];
    uint32 OEMRevision;
    uint32 CreatorID;
    uint32 CreatorRevision;
} __attribute__((packed));

struct SRAT
{
    char signature[4]; // Contains "SRAT"
    uint32 length;     // Length of entire SRAT including entries
    uint8 rev;         // 3
    uint8 checksum;    // Entire table must sum to zero
    uint8 OEMID[6];    // What do you think it is?
    uint64 OEMTableID; // For the SRAT it's the manufacturer model ID
    uint32 OEMRev;     // OEM revision for OEM Table ID
    uint32 creatorID;  // Vendor ID of the utility used to create the table
    uint32 creatorRev; // Blah blah

    uint8 reserved[12];
} __attribute__((packed));

struct SRAT_proc_lapic_struct
{
    uint8 type;      // 0x0 for this type of structure
    uint8 length;    // 16
    uint8 lo_DM;     // Bits [0:7] of the proximity domain
    uint8 APIC_ID;   // Processor's APIC ID
    uint32 flags;    // Haha the most useless thing ever
    uint8 SAPIC_EID; // The processor's local SAPIC EID. Don't even bother.
    uint8 hi_DM[3];  // Bits [8:31] of the proximity domain
    uint32 _CDM;     // The clock domain which the processor belongs to (more jargon)
} __attribute__((packed));

struct SRAT_proc_lapic2_struct
{
    uint8 type;         // 0x2 for this type of structure
    uint8 length;       // 24
    uint8 reserved1[2]; // Must be zero
    uint32 domain;      // The proximity domain which the logical processor belongs to
    uint8 x2APIC_ID;    // Processor's x2APIC ID
    uint32 flags;       // Haha the most useless thing ever
    uint32 _CDM;        // The clock domain which the processor belongs to (more jargon)
    uint8 reserved2[4]; // Reserved.
} __attribute__((packed));

struct SRAT_mem_struct
{
    uint8 type;         // 0x1 for this type of structure
    uint8 length;       // 40
    uint32 domain;      // The domain to which this memory region belongs to
    uint8 reserved1[2]; // Reserved
    uint32 lo_base;     // Low 32 bits of the base address of the memory range
    uint32 hi_base;     // High 32 bits of the base address of the memory range
    uint32 lo_length;   // Low 32 bits of the length of the range
    uint32 hi_length;   // High 32 bits of the length
    uint8 reserved2[4]; // Reserved
    uint32 flags;       // Flags
    uint8 reserved3[8]; // Reserved
} __attribute__((packed));

struct lapic_list
{
};

struct mem_affinity_list
{
};

struct machine
{
    struct cpu_desc *all_cpus;
    struct memrange *all_memranges;
    struct domain *all_domains;
};
struct cpu_desc
{
    struct cpu_desc *next_cpu_desc;
    struct domain *domain;
    int lapic;
};
struct memrange
{
    uint8 *start; /*virtual address*/
    size_t length;
    struct domain *domain;
};

struct domain
{
    struct domain *next_domain;
    struct memrange *memranges;
    struct cpu_desc *cpus;
    struct page_t *freepages;
};