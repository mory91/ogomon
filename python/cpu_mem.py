#!/usr/bin/env python

from bcc import BPF
import argparse
import sys
import time

from mem import get_bpf_source, attach_probes

kstime = time.time_ns() - time.monotonic_ns()

bpf_source = get_bpf_source()

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("-p", "--pid", type=int, default=-1)
parser.add_argument("-s", "--sample-rate", default=5000, type=int)

args = parser.parse_args()

pid = args.pid
sample_every_n = args.sample_rate

bpf_source = bpf_source.replace("SAMPLE_EVERY_N", str(sample_every_n))

bpf = BPF(text=bpf_source)
attach_probes(bpf, "malloc", pid=pid)
# attach_probes(bpf, "calloc", pid=pid)
# attach_probes(bpf, "realloc", pid=pid)
# attach_probes(bpf, "posix_memalign", pid=pid)
# attach_probes(bpf, "valloc", can_fail=True, pid=pid)
# attach_probes(bpf, "memalign", pid=pid)
# attach_probes(bpf, "pvalloc", can_fail=True, pid=pid)
# attach_probes(bpf, "aligned_alloc", can_fail=True, pid=pid)
# attach_probes(bpf, "mmap", pid=pid)


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
