#!/usr/bin/env python

import sys
import argparse
from send import get_bpf, get_call_back

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", default=None)
args = parser.parse_args()

if args.pid is None:
    print("PID must set")
    exit(0)


bpf_obj = get_bpf(args.pid)
bpf_obj.attach_kretprobe(event="tcp_sendmsg", fn_name="send_return")
cb = get_call_back(bpf_obj)
bpf_obj['events'].open_ring_buffer(cb)

while True:
    try:
        bpf_obj.ring_buffer_consume()
    except KeyboardInterrupt:
        exit()
    sys.stdout.flush()
