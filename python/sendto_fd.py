#!/usr/bin/env python3

import argparse
import sys
from send import get_bpf, get_call_back

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", default=None)
args = parser.parse_args()

if args.pid is None:
    print("PID must set")
    exit(0)

bpf_obj = get_bpf(args.pid)
bpf_obj.attach_kprobe(event="__sys_sendto", fn_name="send_entry")
cb = get_call_back(bpf_obj, only_fd=True)
bpf_obj['events'].open_ring_buffer(cb)

while True:
    try:
        bpf_obj.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
    sys.stdout.flush()
