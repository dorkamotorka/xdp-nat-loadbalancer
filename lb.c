//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h"

#define MAX_TCP_CHECK_WORDS 750 // max 1500 bytes to check in TCP checksum. This is MTU dependent
#define NUM_BACKENDS 1
#define ETH_ALEN 6		/* Octets in one ethernet addr	 */

struct endpoint {
    __u32 ip;
    unsigned char mac[ETH_ALEN];
};

struct four_tuple_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Load Balancer IP and MAC address map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1); // Single load balancer
    __type(key, __u32);
    __type(value, struct endpoint);
} load_balancer SEC(".maps");

// Backend IPs and MAC addresses map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_BACKENDS);
    __type(key, __u32);
    __type(value, struct endpoint);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1); // Single flow always
    __type(key, struct four_tuple_t);
    __type(value, struct endpoint);
} flows SEC(".maps");

// FNV-1a hash for load balancing (no need for routing table)
static __u32 xdp_hash_tuple(struct four_tuple_t *tuple) {
    __u32 hash = 2166136261U;
    hash = (hash ^ tuple->src_ip) * 16777619U;
    hash = (hash ^ tuple->dst_ip) * 16777619U;
    hash = (hash ^ tuple->src_port) * 16777619U;
    hash = (hash ^ tuple->dst_port) * 16777619U;
    return hash;
}

static __u16 __always_inline recalc_tcp_checksum(struct tcphdr *tcp, struct iphdr *ip, void *data_end) {
    // Clear checksum
    tcp->check = 0;

    // Pseudo header checksum calculation
    __u32 sum = 0;
    sum += (__u16)(ip->saddr >> 16) + (__u16)(ip->saddr & 0xFFFF);
    sum += (__u16)(ip->daddr >> 16) + (__u16)(ip->daddr & 0xFFFF);
    sum += bpf_htons(IPPROTO_TCP);
    sum += bpf_htons((__u16)(data_end - (void *)tcp));

    // TCP header and payload checksum
    #pragma clang loop unroll_count(MAX_TCP_CHECK_WORDS)
    for (int i = 0; i <= MAX_TCP_CHECK_WORDS; i++) {
        __u16 *ptr = (__u16 *)tcp + i;
        if ((void *)ptr + 2 > data_end)
            break;
        sum += *(__u16 *)ptr;
    }

    // fold into 16 bit
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

static __u16 __always_inline csum_fold_helper(__u64 csum) {
    int i;
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __u16 __always_inline recalc_ip_checksum(struct iphdr *ip) {
    ip->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)ip, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	nh.pos = data;

	// Parse Ethernet header to extract source and destination MAC address
	struct ethhdr *eth;
	int eth_type = parse_ethhdr(&nh, data_end, &eth);
    	// For simplicity we only show IPv4 load-balancing
	if (eth_type != bpf_htons(ETH_P_IP)) {
        	return XDP_PASS;
	}

	// Parse IP header to extract source and destination IP
	struct iphdr *ip;
	int ip_type = parse_iphdr(&nh, data_end, &ip);
	if ((void*)(ip + 1) > data_end) {
		return XDP_PASS;
	}

	// For simplicity only load-balance TCP traffic
	if (ip->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}

	// Parse TCP header to extract source and destination port
	struct tcphdr *tcp;
	int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
	if ((void*)(tcp + 1) > data_end) {
		return XDP_PASS;
	}

	// TODO: remove this afterwards
	__u16 sport = bpf_ntohs(tcp->source);
	__u16 dport = bpf_ntohs(tcp->dest);
	if (!(sport == 8000 || dport == 8000)) {
		return XDP_PASS;
	}

	__u32 saddr_n = ip->saddr;  // already network order
	__u32 daddr_n = ip->daddr;  // already network order
	bpf_printk("Received Source MAC: %x:%x:%x:%x:%x:%x", 
			eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	bpf_printk("Received Destination MAC: %x:%x:%x:%x:%x:%x", 
			eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	bpf_printk("Received Source IP: %pI4", &saddr_n);
	bpf_printk("Received Destination IP: %pI4", &daddr_n);

	// Lookup flow information (backend -> client)
	// Check if it's either a:
	// - client request: Flow doesn't exists
	// - backend response: Flow exists
	struct four_tuple_t in;
	in.src_ip = ip->daddr; // Load Balancer IP - 2.0.16.172
	in.dst_ip = ip->saddr; // Client or Backend IP - 172.16.0.3
	in.src_port = bpf_ntohs(tcp->dest); // Load Balancer destination port
	in.dst_port = bpf_ntohs(tcp->source); // Client or Backend source port
	struct endpoint *out = bpf_map_lookup_elem(&flows, &in);
	if (!out) {
		bpf_printk("Packet from client because no such flow exists yet");	

		// Choose backend using consistent hashing (no routing table needed)
		// Hash the 4-tuple for flow based backend decision
		// Module with the number of backends which we hardcode for simplicity (2 backends)
		struct four_tuple_t four_tuple;
		four_tuple.src_ip = ip->saddr;
		four_tuple.dst_ip = ip->daddr;
		four_tuple.src_port = bpf_ntohs(tcp->source);
		four_tuple.dst_port = bpf_ntohs(tcp->dest);
		__u32 key = xdp_hash_tuple(&four_tuple) % NUM_BACKENDS;
		struct endpoint *backend = bpf_map_lookup_elem(&backends, &key);
		if (!backend) {
		    	return XDP_PASS;
		}

		__u32 ip_n = bpf_htonl(backend->ip);
		bpf_printk("Backend IP: %pI4, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		    &ip_n,
		    backend->mac[0], backend->mac[1], backend->mac[2],
		    backend->mac[3], backend->mac[4], backend->mac[5]);
		
		// Store flow (client -> backend)
		struct four_tuple_t in_loadbalancer;
		in_loadbalancer.src_ip = ip->daddr; // Load Balancer IP
		in_loadbalancer.dst_ip = bpf_ntohl(backend->ip); // Backend IP
		in_loadbalancer.src_port = bpf_ntohs(tcp->dest); // Load Balancer destination port
		in_loadbalancer.dst_port = bpf_ntohs(tcp->dest); // Backend destination port - same as Load Balancer destination port because we don't change it
		struct endpoint client;
		client.ip = ip->saddr; // Client IP
		__builtin_memcpy(client.mac, eth->h_source, ETH_ALEN); // Client MAC address
		int ret = bpf_map_update_elem(&flows, &in_loadbalancer, &client, BPF_ANY);
		if (ret != 0) {
			bpf_printk("Failed to update flows eBPF map");
		}

		// Replace destination IP with backends IP
		ip->daddr = bpf_ntohl(backend->ip);
		// Replace destination MAC with backends MAC address
		__builtin_memcpy(eth->h_dest, backend->mac, ETH_ALEN);
	} else {
		bpf_printk("Packet from backend because the flow exists - redirecting back to client");
                bpf_printk("Client IP: %pI4, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    out->ip,
                    out->mac[0], out->mac[1], out->mac[2],
                    out->mac[3], out->mac[4], out->mac[5]);
		
		// Redirect back to client source IP
		ip->daddr = out->ip;
		__builtin_memcpy(eth->h_dest, out->mac, ETH_ALEN);
		bpf_map_delete_elem(&flows, &out); // Delete flow
    	}

	// Retrieve Load Balancer endpoint (IP + MAC)
	// Update IP source address to the load balancer IP
	// Update Ethernet source MAC address to the load-balancer MAC
	__u32 key = 0;
	struct endpoint *lb = bpf_map_lookup_elem(&load_balancer, &key);
	if (!lb) {
		return XDP_PASS;
	}
	ip->saddr = bpf_ntohl(lb->ip);
	__builtin_memcpy(eth->h_source, lb->mac, ETH_ALEN);

	// Recalculate IP checksum
	ip->check = recalc_ip_checksum(ip);

	// Recalculate TCP checksum
	tcp->check = recalc_tcp_checksum(tcp, ip, data_end);

	__u32 saddr_new = bpf_ntohl(ip->saddr);  
        __u32 daddr_new = bpf_ntohl(ip->daddr); 
	bpf_printk("Redirecting packet from IP %pI4 to IP %pI4", &saddr_new, &daddr_new);
	bpf_printk("New Dest MAC: %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	bpf_printk("New Source MAC: %x:%x:%x:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

	// Return XDP_TX to transmit the modified packet back to the network
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
