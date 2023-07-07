#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/mm.h>

#define DRAIN_NUM 100
#define SIZE 32
// /sys/kernel/slab/kmalloc-32/min_partial
#define MIN_PARTIAL 5
// /sys/kernel/slab/filp/cpu_partial or set_cpu_partial()
#define CPU_PARTIAL 120
// /sys/kernel/slab/filp/objs_per_slab
#define OBJS_PER_SLAB 128
// ROUND_UP((120 * 2) / 128)
#define CPU_PARTIAL_SLAB 2

/**
[from kfree to discard_slab]
1. cpu: if the count of slabs is more than s->cpu_partial_slabs, all slab in cpu partial list will be moved to node partial list
2. node: if the count of slabs is more than s->min_partial, slabs not in partial list will be discarded

we need to find a number larger than or equal to MIN_PARTIAL + 1 and divisible by CPU_PARTIAL_SLAB
*/

struct stru {
    char data[SIZE];
};
static struct stru *sp[MIN_PARTIAL + 2][OBJS_PER_SLAB];

static int __init init_func(void)
{
    return 0;
}

static void breakpoint(void)
{
    pr_info("JUST BREAKPOINT");
}

extern struct kmem_cache *kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1];

static void __exit exit_func(void)
{
    struct page *pg;
    struct kmem_cache *cp;
    void *p;
    void *dummy;

    cp = kmalloc_caches[KMALLOC_NORMAL][5];

    for (int i = 0; i < DRAIN_NUM; i++)
        dummy = kmem_cache_alloc(cp, GFP_KERNEL);

    // Suppose there are some objects in original slab.
    
    // We need to allocate one more slab because the last slab is active.
    // If we free the object in the last slab, kernel will call the fast path.
    for (int i = 0; i < MIN_PARTIAL + 2; i++) {
        for (int j = 0; j < OBJS_PER_SLAB; j++) {
            sp[i][j] = kmem_cache_alloc(cp, GFP_KERNEL);
        }
    }

    // create MIN_PARTIAL partial slab
    for (int i = 0; i < MIN_PARTIAL - 2; i++) // 0, 1, 2
        kmem_cache_free(cp, sp[i][0]);

    breakpoint();
    for (int i = MIN_PARTIAL - 2; i < MIN_PARTIAL; i++) {
        for (int j = 0; j < OBJS_PER_SLAB; j++) {
            kmem_cache_free(cp, sp[i][j]);
        }
    }
    breakpoint();

    // it triggers discard_slab() and the target is released after discard_slab()
    kmem_cache_free(cp, sp[MIN_PARTIAL][OBJS_PER_SLAB - 1]); // last one

    pg = alloc_pages(GFP_KERNEL, 0);
    p = page_to_virt(pg);

    if (p <= (void *)sp[4][0] && p + 0x1000 > (void *)sp[4][0]) {
        pr_info("[+] new: %pK, old: %pK\n", p, sp[4][0]);
    } else {
        pr_info("[-] failed\n");
    }
}

module_init(init_func);
module_exit(exit_func);

MODULE_LICENSE("GPL");

