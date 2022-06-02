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

// -----------------------

#include <bpf/ctx/skb.h>

#define XDPACL_DEBUG

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF 89
#endif

// cacheline alignment
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES 64
#endif

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

// likely optimization
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

// FIXED value
#define ETH_HDR_SIZE 14
#define IP_HDR_SIZE 20
#define TCP_HDR_SIZE 20
#define UDP_HDR_SIZE 8


struct hdr_cursor
{
	void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
										struct ethhdr **ethhdr_l2)
{
	*ethhdr_l2 = nh->pos;
	//  Byte-count bounds check; check if current pointer + size of header is after data_end.
	if ((void *)((*ethhdr_l2) + 1) > data_end)
	{
		return -1;
	}

	nh->pos += ETH_HDR_SIZE;

	return (*ethhdr_l2)->h_proto; // network-byte-order
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
									   void *data_end,
									   struct iphdr **iphdr_l3)
{
	*iphdr_l3 = nh->pos;
	if ((void *)((*iphdr_l3) + 1) > data_end)
	{
		return -1;
	}

	int hdrsize = ((*iphdr_l3)->ihl) << 2; // * 4

	// Sanity check packet field is valid
	if (hdrsize < IP_HDR_SIZE)
	{
		return -1;
	}

	// Variable-length IPv4 header, need to use byte-based arithmetic
	nh->pos += hdrsize;
	if (nh->pos > data_end)
	{
		return -1;
	}

	return (*iphdr_l3)->protocol;
}

// parse the udp header and return the length of the udp payload
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
										void *data_end,
										struct udphdr **udphdr_l4)
{
	*udphdr_l4 = nh->pos;
	if ((void *)((*udphdr_l4) + 1) > data_end)
	{
		return -1;
	}

	nh->pos += UDP_HDR_SIZE;

	int len = bpf_ntohs((*udphdr_l4)->len) - UDP_HDR_SIZE;
	if (len < 0)
	{
		return -1;
	}

	return len;
}

// parse the tcp header
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
										void *data_end,
										struct tcphdr **tcphdr_l4)
{
	*tcphdr_l4 = nh->pos;
	if ((void *)((*tcphdr_l4) + 1) > data_end)
	{
		return -1;
	}
	return 1;
}


const struct packet_frame *unused __attribute__((unused));

struct bpf_map_def SEC("maps") packet_frame_holder = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 10000,
};

struct bpf_map_def SEC("maps") port_holder = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 2,
};

static __always_inline bool check_port(__u64 *src_port, __u64 *dest_port, struct tcphdr *tcphdr_l4, struct udphdr *udphdr_l4)
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
			return true;
		if (*dest_port == bpf_ntohs(target_source) || *dest_port == bpf_ntohs(target_dest))
			return true;
	}
	return false;
}

SEC("classifier_tc_say")
int report_packet_size(struct __sk_buff *skb)
{
    __u64 src_key = 0;
    __u64 *src_port = bpf_map_lookup_elem(&port_holder, &src_key);
    __u64 dest_key = 0;
    __u64 *dest_port = bpf_map_lookup_elem(&port_holder, &dest_key);
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct hdr_cursor nh = {.pos = data};
    int proto_type;
   	struct ethhdr *ethhdr_l2;
   	proto_type = parse_ethhdr(&nh, data_end, &ethhdr_l2);
   	if (bpf_htons(ETH_P_IP) == proto_type)
   	{
   		struct iphdr *iphdr_l3;
   		proto_type = parse_iphdr(&nh, data_end, &iphdr_l3);
		// TCP
   		if (likely(IPPROTO_TCP == proto_type))
   		{
			struct tcphdr *tcphdr_l4;
			if (parse_tcphdr(&nh, data_end, &tcphdr_l4) < 0)
			{
				return TC_ACT_OK;
			}
			if (check_port(src_port, dest_port, tcphdr_l4, NULL))
			{
	            __u64 val = skb->data_end - skb->data;
	            __u64 key = bpf_ktime_get_ns();
	            bpf_map_update_elem(&packet_frame_holder, &key, &val, BPF_ANY);
    		}

    		return TC_ACT_OK;
    	}
		// UDP
   		if (likely(IPPROTO_UDP == proto_type))
   		{
			struct udphdr *udphdr_l4;
			if (parse_udphdr(&nh, data_end, &udphdr_l4) < 0)
			{
				return TC_ACT_OK;
			}
			if (check_port(src_port, dest_port, NULL, udphdr_l4))
			{
	            __u64 val = skb->data_end - skb->data;
	            __u64 key = bpf_ktime_get_ns();
	            bpf_map_update_elem(&packet_frame_holder, &key, &val, BPF_ANY);
    		}

    		return TC_ACT_OK;
    	}
    }
    else
    {
    	return TC_ACT_OK;
    }
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";