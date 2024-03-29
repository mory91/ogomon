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

#define INGRESS 1
#define EGRESS 2

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static __always_inline int parse_tcphdr(struct iphdr *iphdr_l3, struct tcphdr *tcphdr_l4, struct __sk_buff *skb)
{

	if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), tcphdr_l4, sizeof(struct tcphdr)) < 0) {
	    return -1;
	}
	if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), iphdr_l3, sizeof(struct iphdr)) < 0) {
	    return -1;
	}
	return 1;
}

struct event {
    __u64 sport;
    __u64 dport;
    __u64 len;
	__u64 direction;
	__u64 saddr;
	__u64 daddr;
};
struct event *unused __attribute__((unused));

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct event),
	.max_entries = 100000,
};

struct bpf_map_def SEC("maps") port_holder = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 2,
};

static __always_inline int create_ev(struct tcphdr *tcphdr_l4, struct iphdr *iphdr_l3, struct event* ev)
{
    __u64 target_source = 0, target_dest = 0;
    target_source = tcphdr_l4->source;
    target_dest = tcphdr_l4->dest;
    __u64 saddr = ((unsigned char*)(&(iphdr_l3->saddr)))[3];
    __u64 daddr = ((unsigned char*)(&(iphdr_l3->daddr)))[3];
    ev->sport = bpf_ntohs(target_source);
    ev->dport = bpf_ntohs(target_dest);
    ev->saddr = saddr;
    ev->daddr = daddr;
    return 1;
}

SEC("socket")
int report_packet_size(struct __sk_buff *skb)
{
    __u64 src_key = 0;
    __u64 dest_key = 1;
    __u64 *src_ip = bpf_map_lookup_elem(&port_holder, &src_key);
    __u64 *dest_ip = bpf_map_lookup_elem(&port_holder, &dest_key);

    __u64 val = skb->len;
    __u64 key = bpf_ktime_get_ns();
	
    int proto_type;
    struct iphdr iphdr_l3;
    struct tcphdr tcphdr_l4;
    struct event ev = {.len = val};
    
    // NO UDP SUPPORT FOR NOW
    if (parse_tcphdr(&iphdr_l3, &tcphdr_l4, skb)) {
	    if (create_ev(&tcphdr_l4, &iphdr_l3, &ev) > 0) {
		    bpf_map_update_elem(&events, &key, &ev, BPF_ANY);
	    }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
