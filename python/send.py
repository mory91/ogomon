#!/usr/bin/env python
import argparse
import sys
import time
from bcc import BPF

kstime = time.time_ns() - time.monotonic_ns()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event {
        int pad;
        int size;
        u64 timestamp_ns;
};
BPF_RINGBUF_OUTPUT(events, 1 << 12);

static inline bool send_return(struct pt_regs *ctx)
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
    global bpf_text
    bpf_text = bpf_text.replace("__PID__", pid)
    return BPF(text=bpf_text)


def get_call_back(bpf):
    def callback(ctx, data, size):
        event = bpf['events'].event(data)
        print("%d,%d" % (event.timestamp_ns + kstime, event.size))
    return callback


parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", default=None)
args = parser.parse_args()

if args.pid is None:
    print("PID must set")
    exit(0)


bpf_obj = get_bpf(args.pid)
bpf_obj.attach_kretprobe(event="__sys_sendmsg", fn_name="send_return")
cb = get_call_back(bpf_obj)
bpf_obj['events'].open_ring_buffer(cb)

while True:
    try:
        bpf_obj.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
    sys.stdout.flush()
