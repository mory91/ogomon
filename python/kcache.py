#!/usr/bin/env python3
import time
import sys
import argparse
from bcc import BPF
from bcc.utils import printb

kstime = time.time_ns() - time.monotonic_ns()

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", default=None)
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/kasan.h>

// memcg_cache_params is a part of kmem_cache, but is not publicly exposed in
// kernel versions 5.4 to 5.8.  Define an empty struct for it here to allow the
// bpf program to compile.  It has been completely removed in kernel version
// 5.9, but it does not hurt to have it here for versions 5.4 to 5.8.
struct memcg_cache_params {};

// introduce kernel interval slab structure and slab_address() function, solved
// 'undefined' error for >=5.16. TODO: we should fix this workaround if BCC
// framework support BTF/CO-RE.
struct slab {
    unsigned long __page_flags;

#if defined(CONFIG_SLAB)

    struct kmem_cache *slab_cache;
    union {
        struct {
            struct list_head slab_list;
            void *freelist; /* array of free object indexes */
            void *s_mem;    /* first object */
        };
        struct rcu_head rcu_head;
    };
    unsigned int active;

#elif defined(CONFIG_SLUB)

    struct kmem_cache *slab_cache;
    union {
        struct {
            union {
                struct list_head slab_list;
#ifdef CONFIG_SLUB_CPU_PARTIAL
                struct {
                    struct slab *next;
                        int slabs;      /* Nr of slabs left */
                };
#endif
            };
            /* Double-word boundary */
            void *freelist;         /* first free object */
            union {
                unsigned long counters;
                struct {
                    unsigned inuse:16;
                    unsigned objects:15;
                    unsigned frozen:1;
                };
            };
        };
        struct rcu_head rcu_head;
    };
    unsigned int __unused;

#elif defined(CONFIG_SLOB)

    struct list_head slab_list;
    void *__unused_1;
    void *freelist;         /* first free block */
    long units;
    unsigned int __unused_2;

#else
#error "Unexpected slab allocator configured"
#endif

    atomic_t __page_refcount;
#ifdef CONFIG_MEMCG
    unsigned long memcg_data;
#endif
};

// slab_address() will not be used, and NULL will be returned directly, which
// can avoid adaptation of different kernel versions
static inline void *slab_address(const struct slab *slab)
{
    return NULL;
}

#ifdef CONFIG_SLUB
#include <linux/slub_def.h>
#else
#include <linux/slab_def.h>
#endif

struct event {
        int pad;
        int size;
        u64 timestamp_ns;
};
BPF_RINGBUF_OUTPUT(events, 1 << 12);

int kprobe__kmem_cache_alloc(struct pt_regs *ctx, struct kmem_cache *cachep)
{
    u64 id = bpf_get_current_pid_tgid();
    if (id >> 32 != __PID__) { return 0; }
    int size = cachep->size;
    u64 time = bpf_ktime_get_ns();
    struct event event = {
        .size = size,
        .timestamp_ns = time
    };
    events.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}
"""

if args.pid is None:
    print("PID must set")
    exit(0)

bpf_text = bpf_text.replace("__PID__", args.pid)

# initialize BPF
b = BPF(text=bpf_text)


bpf = BPF(text=bpf_text)


def callback(ctx, data, size):
    event = bpf['events'].event(data)
    print("%d,%d" % (event.timestamp_ns + kstime, event.size))


bpf['events'].open_ring_buffer(callback)

while True:
    try:
       bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
    sys.stdout.flush()
