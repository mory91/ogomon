#!/usr/bin/env python
import argparse
import sys
from bcc import BPF

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", default=None)
args = parser.parse_args()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event {
        u64 size;
        u64 timestamp_ns;
};
BPF_RINGBUF_OUTPUT(events, 1 << 12);

int kretprobe__sys_sendmsg(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    if (id >> 32 != __PID__) { return 0; }
    u64 size = PT_REGS_RC(ctx);
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

bpf = BPF(text=bpf_text)

def callback(ctx, data, size):
    event = bpf['events'].event(data)
    print("%d\t%d" % (event.timestamp_ns, event.size))

bpf['events'].open_ring_buffer(callback)

while True:
    try:
       bpf.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
    sys.stdout.flush()