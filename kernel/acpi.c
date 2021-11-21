#include "types.h"
#include "memlayout.h"
#include "riscv.h"
#include "defs.h"
#include "acpi.h"

#define NULL ((void *)0)

int max(int a, int b)
{
    return a > b ? a : b;
}

void initial_numa_topology(struct SRAT_proc_lapic_struct **lapic_list, struct SRAT_mem_struct **mem_aff_list)
{
    // First check size of all the necessary structures
    size_t total_size = (sizeof(struct machine) + sizeof(struct domain) +
                         sizeof(struct cpu_desc) + sizeof(struct memrange));

    if (total_size > PGSIZE)
    {
        panic("Cannot initialize basic tables in a page!\n");
    }
    else
    {
        int max_domain = 0;
        // Domain size.
        for (int i = 0; i < SRAT_PHYS_SIZE; i++)
        {
            if (mem_aff_list[i])
                max_domain = max(max_domain, mem_aff_list[i]->domain);
        }

        // Create domains with domain size
        struct domain domains[max_domain];

        // Set next domain to NULL
        for (int i = 0; i < max_domain; i++)
        {
            domains[i].next_domain = NULL;
        }

        // Link all domains
        for (int i = 0; i < max_domain - 1; i++)
        {
            if (i == max_domain - 1)
            {
                domains[i].next_domain = NULL;
            }
            domains[i].next_domain = &(domains[i + 1]);
        }

        // Walk through domains.
        struct domain *addr = (domains);
        while (addr != NULL)
        {
            printf("%p -> %p\n", addr, addr->next_domain);
            addr = addr->next_domain;
        }
    }
}

const char *flag_strings(uint32 f)
{
    switch (f)
    {
    case 0x1:
        return "ENABLED";
    case 0x11:
        return "ENABLED | HOT-PLUGGABLE";
    case 0x111:
        return "ENABLED | HOT-PLUGGABLE | NON-VOLATILE";
    default:
        return "DISABLED";
    }
}

int verify_srat(struct RSDT *srat)
{
    uint8 sum = 0;

    for (int i = 0; i < srat->Length; i++)
    {
        sum += ((uint8 *)srat)[i];
    }

    return sum == 0;
}
void createdomains(void)
{
    uint8 srat_table[] = {
        83,
        82, 65, 84, 128, 1, 0, 0, 1, 141, 66,
        79, 67, 72, 83, 32, 66, 88, 80, 67, 32,
        32, 32, 32, 1, 0, 0, 0, 66, 88, 80,
        67, 1, 0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 16, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 16, 0, 1, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        16, 1, 2, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 16, 1, 3, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 16, 2, 4, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 16, 3,
        5, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 10, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
        0, 0, 0, 16, 0, 0, 0, 0, 0, 0,
        0, 240, 127, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 128, 0, 0, 0, 0, 0,
        0, 0, 64, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 64, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 2, 0, 0, 0, 0,
        0, 0, 0, 0, 64, 1, 0, 0, 0, 0,
        0, 0, 64, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 3, 0, 0, 0, 0,
        0, 0, 0, 0, 128, 1, 0, 0, 0, 0,
        0, 0, 64, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0

    };

    struct SRAT *srat = (struct SRAT *)kalloc();

    memmove(srat, srat_table, sizeof(srat_table));

    struct SRAT_mem_struct *mem_aff_list[SRAT_PHYS_SIZE];
    struct SRAT_proc_lapic_struct *lapic_list[SRAT_PHYS_SIZE];

    // do a checksum.
    if (verify_srat((struct RSDT *)srat))
    {
        // Grab the first address after the header.
        uint64 *addr = (uint64 *)((uint8 *)srat + sizeof(*srat));
        uint64 *srat_end = (uint64 *)((uint8 *)srat + srat->length);

        int lapic_pos = 0, mem_aff_pos = 0;

        while (addr < srat_end)
        {
            uint8 value = *((uint8 *)(addr));

            if (value == 0x0)
            {
                struct SRAT_proc_lapic_struct *lapic = (struct SRAT_proc_lapic_struct *)(addr);

                lapic_list[lapic_pos] = lapic;
                lapic_pos += 1;

                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_proc_lapic_struct));
            }
            else if (value == 0x1)
            {
                struct SRAT_mem_struct *mem = (struct SRAT_mem_struct *)(addr);

                mem_aff_list[mem_aff_pos] = mem;
                mem_aff_pos += 1;

                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_mem_struct));
            }
            else if (value == 0x2)
            {
                printf("x2 Proc APIC TABLE FOUND!\n");
                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_proc_lapic2_struct));
            }
        }
        initial_numa_topology(lapic_list, mem_aff_list);
    }
}
