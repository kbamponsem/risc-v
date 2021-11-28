#include "types.h"
#include "memlayout.h"
#include "riscv.h"
#include "defs.h"
#include "acpi.h"

#define NULL ((void *)0)

#define BYTE (sizeof(uint8))

#define max(a, b) ((a > b ? a : b))

#define create_domain_lapic(dom, lapic) ((dom << 28) | lapic)
#define get_domain_id(domain_lapic) (domain_lapic >> 28)
#define get_lapic_id(domain_lapic) ((uint8)domain_lapic)

struct topology_allocator *t_mem;

struct machine *machine;
struct domain *domains;
struct cpu_desc *mycpus;
struct memrange *memranges;

void *mymemcpy(void *dest, void *src, size_t size)
{
    char *a = (char *)dest;
    char *b = (char *)src;

    for (int i = 0; i < size; i++)
    {
        a[i] = b[i];
        printf("%x, (%p, %x)\n", a[i], &b[i], b[i]);
    }
    return dest;
}

void tinit()
{
    t_mem = kalloc();
    t_mem->cur = kalloc();
    t_mem->max = (t_mem->cur + PGSIZE);
}

void *talloc(size_t size)
{
    if (t_mem->cur + size > t_mem->max)
    {
        t_mem->cur = kalloc();
        t_mem->max = t_mem->cur + PGSIZE;
    }

    void *res = t_mem->cur;
    t_mem->cur = (t_mem->cur + size);
    return res;
}
void copy_memrange(struct memrange **dest, struct memrange *src)
{
    (*dest) = (struct memrange *)talloc(sizeof(*(*dest)));
    (*dest)->domain_id = src->domain_id;
    (*dest)->domain = src->domain;
    (*dest)->start = src->start;
    (*dest)->length = src->length;
    (*dest)->next_memrange = NULL;
}

struct memrange *get_domain_memrange(uint32 domain_id)
{
    struct memrange *results = (struct memrange *)talloc(sizeof(*results));
    results->next_memrange = NULL;

    struct memrange *range = machine->all_memranges;
    while (range != NULL)
    {
        if (range->domain_id == domain_id)
        {
            printf("%p\n", range);
        }
        range = range->next_memrange;
    }
    return results;
}

struct domain *get_domain_by_id(uint32 domain_id)
{
    struct domain *domain = machine->all_domains;

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
    struct cpu_desc *mycpu = machine->all_cpus;
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
    struct domain *domain = machine->all_domains;
    int count = 0;

    while (domain != NULL)
    {
        count++;
        domain = domain->next_domain;
    }
    return count;
}

void describe_cpus(struct cpu_desc *cpu_desc)
{
    printf("[");
    while (cpu_desc != NULL)
    {
        printf("CPU%d ", cpu_desc->lapic);
        cpu_desc = cpu_desc->next_cpu_desc;
    }
    printf("]\n");
}

void describe_domains(struct domain *domain)
{
    while (domain != NULL)
    {
        printf("Domain %d\n", domain->domain_id);
        struct cpu_desc *cpus_in_domain = domain->cpus;
        printf("[ ");
        while (cpus_in_domain != NULL)
        {
            printf("CPU%d ", cpus_in_domain->lapic);
            cpus_in_domain = cpus_in_domain->next_cpu_desc;
        }
        printf("]\n");

        domain = domain->next_domain;
    }
}

void describe_machine(struct machine *machine)
{
    printf("---Machine---\n");
    // printf("CPUS: %d\n", count_cpus(machine));
    describe_cpus(machine->all_cpus);
    printf("DOMAINS: %d\n", count_domains(machine));
    describe_domains(machine->all_domains);
}

void copy_cpu_desc(struct cpu_desc **dest, struct cpu_desc *src)
{
    (*dest) = (struct cpu_desc *)talloc(sizeof(*(*dest)));
    (*dest)->lapic = src->lapic;
    (*dest)->domain_id = src->domain_id;
    (*dest)->domain = src->domain;
    (*dest)->next_cpu_desc = NULL;

    // if ((*dest)->next_cpu_desc != NULL)
}

struct cpu_desc *get_cpus(uint32 domain_id)
{
    struct cpu_desc *domain_cpus = NULL;
    struct cpu_desc *cpu_desc = machine->all_cpus;

    while (cpu_desc != NULL)
    {
        if (cpu_desc->domain_id == domain_id)
        {
            if (domain_cpus == NULL)
            {
                // Do a shallow copy because we are using pointers.
                copy_cpu_desc(&domain_cpus, cpu_desc);
            }
            else
            {
                struct cpu_desc *_dom = domain_cpus;
                while (_dom != NULL)
                {
                    if (_dom->next_cpu_desc == NULL)
                        break;

                    _dom = _dom->next_cpu_desc;
                }
                copy_cpu_desc(&_dom->next_cpu_desc, cpu_desc);
            }
        }

        cpu_desc = cpu_desc->next_cpu_desc;
    }

    return domain_cpus;
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

void create_domain_by_id(uint32 dom_id)
{
    struct domain *domain = (struct domain *)talloc(sizeof(*domain));

    domain->cpus = NULL;
    domain->domain_id = dom_id;
    domain->freepages = NULL;
    domain->next_domain = NULL;

    if (machine->all_domains == NULL)
    {
        machine->all_domains = domain;
    }
    else
    {
        struct domain *dom = machine->all_domains;

        while (dom != NULL)
        {
            if (dom_id == dom->domain_id)
            {
                return;
            }
            else if (dom->next_domain == NULL)
            {
                break;
            }
            dom = (dom)->next_domain;
        }
        dom->next_domain = domain;
    }
}

void create_cpu_desc_by_apic_id(uint8 apic_id, uint32 domain)
{
    struct cpu_desc *descriptor = (struct cpu_desc *)talloc(sizeof(*descriptor));

    descriptor->domain = NULL;
    descriptor->lapic = apic_id;
    descriptor->domain_id = (uint32)domain;
    descriptor->next_cpu_desc = NULL;

    if (machine->all_cpus == NULL)
    {
        machine->all_cpus = descriptor;
    }
    else
    {
        struct cpu_desc *cpu_desc = machine->all_cpus;
        while (cpu_desc != NULL)
        {
            if (cpu_desc->next_cpu_desc == NULL)
            {
                break;
            }

            cpu_desc = cpu_desc->next_cpu_desc;
        }
        cpu_desc->next_cpu_desc = descriptor;
    }
}

void initialize_domain_cpus()
{
    struct domain *dom = machine->all_domains;

    while (dom != NULL)
    {
        dom->cpus = get_cpus(dom->domain_id);
        dom = dom->next_domain;
    }
}

void initialize_cpus_domain()
{

    struct cpu_desc *cpu_desc = machine->all_cpus;

    while (cpu_desc != NULL)
    {
        cpu_desc->domain = get_domain_by_id(cpu_desc->domain_id);
        cpu_desc = cpu_desc->next_cpu_desc;
    }
}

void create_memrange(uint64 range_start, uint64 range_end, uint32 domain_id)
{
    struct memrange *memrange = (struct memrange *)talloc(sizeof(*memrange));
    memrange->domain = NULL;
    memrange->domain_id = domain_id;
    memrange->start = (uint8 *)range_start;
    memrange->length = (range_end - range_start);
    memrange->next_memrange = NULL;

    if (machine->all_memranges == NULL)
    {
        machine->all_memranges = memrange;
    }
    else
    {
        memrange->next_memrange = machine->all_memranges;
        machine->all_memranges = memrange;
    }
}
void initialize_memranges()
{
    struct memrange *memrange = machine->all_memranges;

    while (memrange != NULL)
    {
        printf("DOMAIN ID: %d\n", memrange->domain_id);
        /* code */
        memrange->domain = get_domain_by_id(memrange->domain_id);
        memrange = memrange->next_memrange;
    }
}
void extracttopology(void)
{
    tinit();

    machine = (struct machine *)talloc(sizeof(struct machine));

    machine->all_domains = NULL;
    machine->all_cpus = NULL;
    machine->all_memranges = NULL;

    uint8 srat_table[] = {
        83,
        82, 65, 84, 0, 1, 0, 0, 1, 16, 66,
        79, 67, 72, 83, 32, 66, 88, 80, 67, 32,
        32, 32, 32, 1, 0, 0, 0, 66, 88, 80,
        67, 1, 0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 16, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 16, 0, 1, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        16, 1, 2, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 40, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 10, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 40, 0, 0, 0,
        0, 0, 0, 0, 0, 16, 0, 0, 0, 0,
        0, 0, 0, 240, 31, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 40, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
        0, 0, 0, 0, 32, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 40, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0};

    struct SRAT *srat = (struct SRAT *)kalloc();

    memmove(srat, srat_table, sizeof(srat_table));

    // do a checksum.
    if (verify_srat((struct RSDT *)srat))
    {
        // Grab the first address after the header.
        uint64 *addr = (uint64 *)((uint8 *)srat + sizeof(*srat));
        uint64 *srat_end = (uint64 *)((uint8 *)srat + srat->length);

        while (addr < srat_end)
        {
            uint8 value = *((uint8 *)(addr));

            if (value == 0x0)
            {
                struct SRAT_proc_lapic_struct *lapic = (struct SRAT_proc_lapic_struct *)(addr);

                uint32 domain_id = (lapic->hi_DM[2] << 3 * BYTE) + (lapic->hi_DM[1] << 2 * BYTE) + (lapic->hi_DM[0] << BYTE) + (lapic->lo_DM);
                create_cpu_desc_by_apic_id(lapic->APIC_ID, domain_id);

                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_proc_lapic_struct));
            }
            else if (value == 0x1)
            {
                struct SRAT_mem_struct *mem = (struct SRAT_mem_struct *)(addr);
                create_domain_by_id(mem->domain);
                uint64 range_start = (uint64)(mem->lo_base);
                uint64 range_end = range_start + ((uint64)(mem->hi_base << 4 * BYTE) + mem->lo_length);
                if (mem->flags)
                    create_memrange(range_start, range_end, mem->domain);

                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_mem_struct));
            }
            else if (value == 0x2)
            {
                printf("x2 Proc APIC TABLE FOUND!\n");
                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_proc_lapic2_struct));
            }
        }
        initialize_memranges();
        initialize_cpus_domain();
        initialize_domain_cpus();
        describe_machine(machine);
    }
}
