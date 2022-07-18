// +build ignore

#include <linux/types.h>
#include <linux/byteorder.h>

#include <stddef.h>

// #include <linux/if_packet.h>

#include <linux/in.h>		// proto type
#include <linux/if_ether.h> // l2
#include <linux/ip.h>		// l3
#include <linux/tcp.h>		// l4 struct tcphdr
#include <linux/udp.h>		// l4 struct udphdr

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <bpf/ctx/skb.h>


// parse the tcp header
static __always_inline int parse_tcphdr(struct tcphdr tcphdr_l4, struct __sk_buff *skb)
{
	if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcphdr_l4, sizeof(struct tcphdr)) < 0) {
		char msg[] = "IM DONE :((( \n";
		bpf_trace_printk(msg, sizeof(msg));
		return -1;
	}

	return tcphdr_l4.dest;
}


struct event {
    __u64 sport;
    __u64 dport;
    __u64 len;
};
struct event *unused __attribute__((unused));

struct bpf_map_def SEC("maps") packet_frame_holder = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct event),
	.max_entries = 10000,
};

struct bpf_map_def SEC("maps") port_holder = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 2,
};

static __always_inline bool check_port(__u64 *src_port, __u64 *dest_port, struct tcphdr *tcphdr_l4, struct udphdr *udphdr_l4, struct event* ev)
{
	__u64 target_source = 0, target_dest = 0;
	if (tcphdr_l4 != NULL)
	{
		target_source = tcphdr_l4->source;
		target_dest = tcphdr_l4->dest;
	}
	if (udphdr_l4 != NULL)
	{
		target_source = udphdr_l4->source;
		target_dest = udphdr_l4->dest;
	}
	if (src_port && dest_port)
	{

		if (*src_port == bpf_ntohs(target_source) || *src_port == bpf_ntohs(target_dest))
		{
            ev->sport = bpf_ntohs(target_source);
            ev->dport = bpf_ntohs(target_dest);
			return true;
		}
		if (*dest_port == bpf_ntohs(target_source) || *dest_port == bpf_ntohs(target_dest))
		{
            ev->sport = bpf_ntohs(target_source);
            ev->dport = bpf_ntohs(target_dest);
			return true;
		}
	}
	return false;
}

SEC("socket")
int report_packet_size(struct __sk_buff *skb)
{
    __u64 src_key = 0;
    __u64 *src_port = bpf_map_lookup_elem(&port_holder, &src_key);
    __u64 dest_key = 1;
    __u64 *dest_port = bpf_map_lookup_elem(&port_holder, &dest_key);
	__u64 val = skb->len;
	__u64 key = bpf_ktime_get_ns();
	
    int proto_type;
   	struct tcphdr tcphdr_l4;
	
	proto_type = parse_tcphdr(tcphdr_l4, skb);

	char msg[] = "PORT %d SIZE %d \n";
	bpf_trace_printk(msg, sizeof(msg), bpf_ntohs(proto_type), skb->len);

	return -1;
}

char _license[] SEC("license") = "GPL";
