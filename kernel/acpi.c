#include "types.h"
#include "memlayout.h"
#include "riscv.h"
#include "defs.h"
#include "acpi.h"

#define NULL ((void *)0)

#define max(a, b) ((a > b ? a : b))

#define create_domain_lapic(dom, lapic) ((dom << 28) | lapic)
#define get_domain_id(domain_lapic) (domain_lapic >> 28)
#define get_lapic_id(domain_lapic) ((uint8)domain_lapic)

struct machine *machine;
struct domain *domains;
struct cpu_desc *mycpus;
struct memrange *memranges;

void check_relations(void *start, size_t pt_size, size_t size)
{
    while (start != NULL)
    {
        printf("%p -> %p\n", start, (start + size));
        start = (start + size);
    }
}

uint64 *get_memrange_range(uint32 lo_base, uint32 lo_length, uint32 hi_base, uint32 hi_length)
{
    uint64 *range = kalloc();

    if (hi_base)
    {
        range[0] = ((uint64)hi_base << 32) + lo_base;
    }
    else
    {
        range[0] = (uint64)(lo_base);
    }
    range[1] = (uint64)(range[0] + lo_length);

    return range;
}
struct domain *get_domain_by_id(uint32 domain_id)
{
    struct domain *domain = &machine->all_domains[0];

    while (domain != NULL)
    {
        if (domain->domain_id == domain_id)
        {
            return domain;
        }
        domain = domain->next_domain;
    }
    return NULL;
}

int count_cpus(struct machine *machine)
{
    struct cpu_desc *mycpu = &machine->all_cpus[0];
    int count = 0;
    while (mycpu != NULL)
    {
        count++;
        mycpu = mycpu->next_cpu_desc;
    }
    return count;
}
int count_domains(struct machine *machine)
{
    struct domain *domain = &machine->all_domains[0];
    int count = 0;

    while (domain != NULL)
    {
        count++;
        domain = domain->next_domain;
    }
    return count;
}

void describe_cpu_in_domain(struct cpu_desc *cpu_desc, uint32 domain_id)
{
    while (cpu_desc != NULL)
    {
        if (get_domain_id((uint64)cpu_desc->domain) == domain_id)
        {
            printf("---[CPU]---\n");
            printf("\tBelongs to: Domain %d\n", get_domain_id((uint64)cpu_desc->domain));
            printf("\tAPIC ID: %d\n", cpu_desc->lapic);
            printf("\tNext CPU: %p\n", cpu_desc->next_cpu_desc);
        }

        cpu_desc = cpu_desc->next_cpu_desc;
    }
    printf("\n");
}

void describe_memrange_by_domain_id(uint32 domain_id)
{
    uint64 *start = NULL;
    uint64 *end = NULL;
    int start_set = 0;
    for (int i = 0; i < SRAT_PHYS_SIZE; i++)
    {
        if (memranges[i].start != (uint64 *)-1)
        {
            if (domain_id == get_domain_id(memranges[i].domain_id))
            {
                if (!start_set)
                {
                    start = memranges[i].start;
                    start_set = 1;
                }
                end = (memranges[i].end);

                memranges[i].domain = get_domain_by_id(domain_id);
            }
        }
    }

    printf("\tMemrange: [%p ~ %p]\n", start, end);
}
void describe_domains(struct machine *machine)
{
    struct domain *domain = &machine->all_domains[0];

    while (domain != NULL)
    {
        printf("\n --- DOMAIN --- \n");
        printf("Domain id: %d\n", domain->domain_id);
        describe_cpu_in_domain(domain->cpus, domain->domain_id);
        describe_memrange_by_domain_id(domain->domain_id);
        printf("\tNext Domain: %p\n", domain->next_domain);
        domain = domain->next_domain;
        printf("\n --- [END DOMAIN] ---\n");
    }
}
void describe_machine(struct machine *machine)
{
    printf("---Machine---\n");
    printf("CPUS: %d\n", count_cpus(machine));
    printf("DOMAINS: %d\n", count_domains(machine));
    describe_domains(machine);
}

struct cpu_desc *get_cpus(uint32 domain_id)
{
    struct cpu_desc *domain_cpus = kalloc();
    struct cpu_desc *cpu_desc = &mycpus[0];

    int i = 0;
    while (cpu_desc != NULL)
    {
        if (get_domain_id((uint64)cpu_desc->domain) == domain_id)
        {
            domain_cpus[i] = *cpu_desc;
            i += 1;
        }
        cpu_desc = cpu_desc->next_cpu_desc;
    }
    return domain_cpus;
}

void initial_numa_topology(struct SRAT_proc_lapic_struct **lapic_list, int lapic_pos, struct SRAT_mem_struct **mem_aff_list, int mem_aff_pos)
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
        domains = kalloc();
        mycpus = kalloc();
        memranges = kalloc();

        int domain_size = 0;

        for (int i = 0; i < SRAT_PHYS_SIZE; i++)
        {
        }

        for (int i = 0; i < SRAT_PHYS_SIZE; i++)
        {
            if (mem_aff_list[i])
            {
                domains[i].domain_id = MAX_UINT32;
                memranges[i].domain_id = MAX_UINT32;
                memranges[i].start = (uint64)0;
                domains[i].domain_id = mem_aff_list[i]->domain;
                domain_size = max(domain_size, mem_aff_list[i]->domain);
            }
            domains[i].cpus = NULL;
            domains[i].freepages = NULL;
            domains[i].next_domain = NULL;
            mycpus[i].next_cpu_desc = NULL;
            memranges[i].start = (void *)-1;
            memranges[i].end = (void *)-1;
            memranges[i].domain = NULL;
        }

        for (int i = 0; i < SRAT_PHYS_SIZE; i++)
        {
            if (mem_aff_list[i])
            {
                uint64 *range = get_memrange_range(mem_aff_list[i]->lo_base, mem_aff_list[i]->lo_length, mem_aff_list[i]->hi_base, mem_aff_list[i]->hi_length);
                uint32 domain_lapic = create_domain_lapic(mem_aff_list[i]->domain, lapic_list[i]->APIC_ID);

                memranges[i].domain_id = domain_lapic;
                memranges[i].domain = (struct domain *)(uint64)get_domain_id(domain_lapic);
                memranges[i].start = (uint64 *)range[0];
                memranges[i].end = (uint64 *)range[1];
            }

            if (lapic_list[i])
            {
                mycpus[i].lapic = lapic_list[i]->APIC_ID;
                if (lapic_list[i + 1] == NULL)
                {
                    mycpus[i].next_cpu_desc = NULL;
                }
                else
                {
                    mycpus[i].next_cpu_desc = &mycpus[i + 1];
                }
                mycpus[i].domain = (struct domain *)(uint64)(create_domain_lapic(lapic_list[i]->lo_DM, lapic_list[i]->APIC_ID));
            }
        }

        for (int i = 0; i <= domain_size; i++)
        {
            domains[i].domain_id = i;
            if (i == domain_size)
            {
                domains[i].next_domain = NULL;
            }
            else
                domains[i].next_domain = &domains[i + 1];
            domains[i].cpus = get_cpus(i);
        }

        machine = kalloc();
        machine->all_cpus = mycpus;
        machine->all_domains = domains;
        machine->all_memranges = memranges;

        for (int i = 0; i < SRAT_PHYS_SIZE; i++)
        {
            if (memranges[i].start != (void *)-1)
            {
                memranges[i].domain = get_domain_by_id(memranges[i].domain_id);
            }
        }

        describe_machine(machine);
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
    // uint8 srat_table[] = {
    //     83,
    //     82, 65, 84, 128, 1, 0, 0, 1, 141, 66,
    //     79, 67, 72, 83, 32, 66, 88, 80, 67, 32,
    //     32, 32, 32, 1, 0, 0, 0, 66, 88, 80,
    //     67, 1, 0, 0, 0, 1, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 16, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 16, 0, 1, 1, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     16, 1, 2, 1, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 16, 1, 3, 1,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 16, 2, 4, 1, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 16, 3,
    //     5, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 10, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
    //     0, 0, 0, 16, 0, 0, 0, 0, 0, 0,
    //     0, 240, 127, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 1, 0, 0, 0, 0,
    //     0, 0, 0, 0, 128, 0, 0, 0, 0, 0,
    //     0, 0, 64, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 1, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    //     0, 0, 64, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 2, 0, 0, 0, 0,
    //     0, 0, 0, 0, 64, 1, 0, 0, 0, 0,
    //     0, 0, 64, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 3, 0, 0, 0, 0,
    //     0, 0, 0, 0, 128, 1, 0, 0, 0, 0,
    //     0, 0, 64, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0};

    uint8 srat_table[] = {
        83,
        82, 65, 84, 48, 1, 0, 0, 1, 62, 66,
        79, 67, 72, 83, 32, 66, 88, 80, 67, 32,
        32, 32, 32, 1, 0, 0, 0, 66, 88, 80,
        67, 1, 0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 16, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 16, 0, 1, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        16, 0, 2, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 16, 0, 3, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 16, 0, 4, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 16, 1,
        5, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 10, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
        0, 0, 0, 16, 0, 0, 0, 0, 0, 0,
        0, 240, 191, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 192, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 40, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 192, 1, 0, 0, 0, 0,
        0, 0, 128, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0};

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

                if (mem->flags)
                {
                    mem_aff_list[mem_aff_pos] = mem;
                    mem_aff_pos += 1;
                }

                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_mem_struct));
            }
            else if (value == 0x2)
            {
                printf("x2 Proc APIC TABLE FOUND!\n");
                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_proc_lapic2_struct));
            }
        }

        printf("[%d, %d]\n", lapic_pos, mem_aff_pos);
        initial_numa_topology(lapic_list, lapic_pos, mem_aff_list, mem_aff_pos);
    }
}
