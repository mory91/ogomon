#!/usr/bin/env python

from bcc import BPF
from time import sleep
from datetime import datetime
import argparse
import subprocess
import os
import sys

class Allocation(object):
    def __init__(self, stack, size):
        self.stack = stack
        self.count = 1
        self.size = size

    def update(self, size):
        self.count += 1
        self.size += size

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, default=-1)
parser.add_argument("-s", "--sample-rate", default=500_000, type=int)

args = parser.parse_args()

pid = args.pid
sample_every_n = args.sample_rate

bpf_source = """
#include <uapi/linux/ptrace.h>

struct event {
        u64 size;
        u64 timestamp_ns;
};


BPF_ARRAY(sizes, u64, 1);
BPF_ARRAY(times, u64, 1);
BPF_RINGBUF_OUTPUT(events, 4096 * 8);

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
    u64 ts = bpf_ktime_get_ns();
    struct event event = {};
    event.size = size;
    event.timestamp_ns = ts;
    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

int malloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t size) {
        return gen_alloc_enter(ctx, nmemb * size);
}

int realloc_enter(struct pt_regs *ctx, void *ptr, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int mmap_enter(struct pt_regs *ctx) {
        size_t size = (size_t)PT_REGS_PARM2(ctx);
        return gen_alloc_enter(ctx, size);
}

int posix_memalign_enter(struct pt_regs *ctx, void **memptr, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int aligned_alloc_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int valloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int memalign_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int pvalloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}
"""

bpf_source = bpf_source.replace("SAMPLE_EVERY_N", str(sample_every_n))

stack_flags = "0"
stack_flags += "|BPF_F_USER_STACK"
bpf_source = bpf_source.replace("STACK_FLAGS", stack_flags)

bpf = BPF(text=bpf_source)

def callback(ctx, data, size):
    event = bpf['events'].event(data)
    print("%d\t%d" % (event.timestamp_ns, event.size))

bpf['events'].open_ring_buffer(callback)

def attach_probes(sym, fn_prefix=None, can_fail=False):
    if fn_prefix is None:
            fn_prefix = sym
    try:
            bpf.attach_uprobe(name="c", sym=sym,
                              fn_name=fn_prefix + "_enter",
                              pid=pid)
    except Exception:
            if can_fail:
                    return
            else:
                    raise

attach_probes("malloc")
attach_probes("calloc")
attach_probes("realloc")
attach_probes("mmap")
attach_probes("posix_memalign")
attach_probes("valloc", can_fail=True) # failed on Android, is deprecated in libc.so from bionic directory
attach_probes("memalign")
attach_probes("pvalloc", can_fail=True) # failed on Android, is deprecated in libc.so from bionic directory
attach_probes("aligned_alloc", can_fail=True)  # added in C11

while True:
    try:
        bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
    sys.stdout.flush()