from bcc import BPF
import sys


def get_bpf_source():
    return """
#include <uapi/linux/ptrace.h>

struct event {
        u64 size;
        u64 timestamp_ns;
};

BPF_RINGBUF_OUTPUT(events, 1 << 12);

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
int cudaMalloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}
int cudaMemcpy_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}
int cudaHostAlloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}
int cudaMallocAsync_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}
int cudaMemcpyAsync_enter(struct pt_regs *ctx, void* src, void* dst, size_t size) {
        return gen_alloc_enter(ctx, size);
}
"""


def attach_probes(bpf, sym, fn_prefix=None, can_fail=False, name="c", pid=-1):
    if fn_prefix is None:
        fn_prefix = sym
    try:
        bpf.attach_uprobe(name=name, sym=sym, fn_name=fn_prefix + "_enter", pid=pid)
    except Exception:
        if can_fail:
            return
        else:
            raise
