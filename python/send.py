#!/usr/bin/env python3
import time
from bcc import BPF

kstime = time.time_ns() - time.monotonic_ns()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event {
        int fd;
        int size;
        u64 timestamp_ns;
};
BPF_RINGBUF_OUTPUT(events, 1 << 12);

int send_entry(struct pt_regs* ctx, int fd) {
    u64 id = bpf_get_current_pid_tgid();
    if (id >> 32 != __PID__) { return 0; }
    u64 time = bpf_ktime_get_ns();
    struct event event = {
        .fd = fd,
        .timestamp_ns = time
    };
    events.ringbuf_output(&event, sizeof(event), 0);
    return true;
}

bool send_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    if (id >> 32 != __PID__) { return 0; }
    int size = PT_REGS_RC(ctx);
    u64 time = bpf_ktime_get_ns();
    struct event event = {
        .size = size,
        .timestamp_ns = time
    };
    events.ringbuf_output(&event, sizeof(event), 0);
    return true;
}
"""


def get_bpf(pid):
    bpf_pid_text = bpf_text.replace("__PID__", pid)
    return BPF(text=bpf_pid_text)


def get_call_back(bpf, with_fd=False, only_fd=False):
    def callback_only_fd(ctx, data, size):
        event = bpf['events'].event(data)
        print("%d,%d" % (event.timestamp_ns + kstime, event.fd))

    def callback_with_fd(ctx, data, size):
        event = bpf['events'].event(data)
        print("%d,%d,%d" % (event.timestamp_ns + kstime, event.size, event.fd))

    def callback(ctx, data, size):
        event = bpf['events'].event(data)
        print("%d,%d" % (event.timestamp_ns + kstime, event.size))

    if with_fd:
        return callback_with_fd

    if only_fd:
        return callback_only_fd

    return callback
