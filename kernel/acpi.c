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

struct topology_allocator *t_mem;

struct machine *machine;
struct domain *domains;
struct cpu_desc *mycpus;
struct memrange *memranges;

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
    printf("CPUS: %d\n", count_cpus(machine));
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

void create_cpu_desc_by_apic_id(uint8 apic_id, uint8 domain)
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

void initial_domain_cpus()
{
    struct domain *dom = machine->all_domains;

    while (dom != NULL)
    {
        dom->cpus = get_cpus(dom->domain_id);
        dom = dom->next_domain;
    }
}

void initial_cpu_doms()
{

    struct cpu_desc *cpu_desc = machine->all_cpus;

    while (cpu_desc != NULL)
    {
        cpu_desc->domain = get_domain_by_id(cpu_desc->domain_id);
        cpu_desc = cpu_desc->next_cpu_desc;
    }
}
void createdomains(void)
{
    tinit();

    machine = (struct machine *)talloc(sizeof(struct machine));

    machine->all_domains = NULL;
    machine->all_cpus = NULL;
    machine->all_memranges = NULL;

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
        0, 0, 0};

    // uint8 srat_table[] = {
    //     83,
    //     82, 65, 84, 48, 1, 0, 0, 1, 62, 66,
    //     79, 67, 72, 83, 32, 66, 88, 80, 67, 32,
    //     32, 32, 32, 1, 0, 0, 0, 66, 88, 80,
    //     67, 1, 0, 0, 0, 1, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 16, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 16, 0, 1, 1, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     16, 0, 2, 1, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 16, 0, 3, 1,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 16, 0, 4, 1, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 16, 1,
    //     5, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 10, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
    //     0, 0, 0, 16, 0, 0, 0, 0, 0, 0,
    //     0, 240, 191, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    //     0, 0, 192, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 1, 40, 1, 0, 0, 0, 0,
    //     0, 0, 0, 0, 192, 1, 0, 0, 0, 0,
    //     0, 0, 128, 0, 0, 0, 0, 0, 0, 0,
    //     0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0};

    struct SRAT *srat = (struct SRAT *)kalloc();

    memmove(srat, srat_table, sizeof(srat_table));

    // do a checksum.
    if (verify_srat((struct RSDT *)srat))
    {
        // Grab the first address after the header.
        uint64 *addr = (uint64 *)((uint8 *)srat + sizeof(*srat));
        uint64 *srat_end = (uint64 *)((uint8 *)srat + srat->length);

        // int lapic_pos = 0, mem_aff_pos = 0;

        while (addr < srat_end)
        {
            uint8 value = *((uint8 *)(addr));

            if (value == 0x0)
            {
                struct SRAT_proc_lapic_struct *lapic = (struct SRAT_proc_lapic_struct *)(addr);

                create_cpu_desc_by_apic_id(lapic->APIC_ID, lapic->lo_DM);

                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_proc_lapic_struct));
            }
            else if (value == 0x1)
            {
                struct SRAT_mem_struct *mem = (struct SRAT_mem_struct *)(addr);
                create_domain_by_id(mem->domain);

                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_mem_struct));
            }
            else if (value == 0x2)
            {
                printf("x2 Proc APIC TABLE FOUND!\n");
                addr = (uint64 *)((uint8 *)addr + sizeof(struct SRAT_proc_lapic2_struct));
            }
        }
        initial_cpu_doms();
        initial_domain_cpus();
        describe_machine(machine);
    }
}
