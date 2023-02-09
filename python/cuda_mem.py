#!/usr/bin/env python

from bcc import BPF
import argparse
import sys

from mem import get_bpf_source, attach_probes


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("-p", "--pid", type=int, default=-1)
parser.add_argument("-s", "--sample-rate", default=5000, type=int)
args = parser.parse_args()
pid = args.pid
sample_every_n = args.sample_rate

bpf_source = get_bpf_source()
bpf_source = bpf_source.replace("SAMPLE_EVERY_N", str(sample_every_n))
bpf = BPF(text=bpf_source)
cudart_lib = "/home/morteza/anaconda3/envs/digger/lib/python3.10/site-packages/torch/lib/libcudart-a7b20f20.so.11.0"
cudart_lib2 = "/home/morteza/anaconda3/envs/digger/lib/python3.10/site-packages/torchvision.libs/libcudart.053364c0.so.11.0"
# attach_probes(bpf, "cudaMalloc", name=cudart_lib)
# attach_probes(bpf, "cudaHostAlloc", name=cudart_lib)
# attach_probes(bpf, "cudaMemcpy", name=cudart_lib)
# attach_probes(bpf, "cudaMallocAsync", name=cudart_lib)
attach_probes(bpf, "cudaMemcpyAsync", name=cudart_lib, pid=pid)


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
