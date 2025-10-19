//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h"

#define MAX_TCP_CHECK_WORDS 750 // max 1500 bytes to check in TCP checksum. This is MTU dependent
#define NUM_BACKENDS 1
#define ETH_ALEN 6		/* Octets in one ethernet addr	 */
#define AF_INET 2

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

// Backend IPs and MAC addresses map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_BACKENDS);
    __type(key, __u32);
    __type(value, struct endpoint);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2); 
    __type(key, struct four_tuple_t);
    __type(value, struct endpoint);
} conntrack SEC(".maps");

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

static __always_inline __u16 recalc_ip_checksum(struct iphdr *ip) {
    // Clear checksum
    ip->check = 0;

    // Compute incremental checksum difference over the header
    __u64 csum = bpf_csum_diff(0, 0, (unsigned int *)ip, sizeof(struct iphdr), 0);

    // fold 64-bit csum to 16 bits (the “carry add” loop)
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }

    return ~csum;
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

	// We could technically load-balance all the traffic but
	// we only focus on port 8000 to not impact any other network traffic
	// in the playground
	if (bpf_ntohs(tcp->source) != 8000 && bpf_ntohs(tcp->dest) != 8000) {
		return XDP_PASS;
	}

	// Print source and destination MAC addresses
	bpf_printk("SRC MAC %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC %02x:%02x:%02x:%02x:%02x:%02x",
	    eth->h_source[0], eth->h_source[1], eth->h_source[2],
	    eth->h_source[3], eth->h_source[4], eth->h_source[5],
	    eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
	    eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

	// Print source and destination IP addresses
	bpf_printk("SRC IP %pI4 -> DST IP %pI4", &ip->saddr, &ip->daddr);

	// Store Load Balancer IP for later 
	// It's always the destination IP because the XDP program
	// is attached at the LB on ingress
	__u32 lb_ip = ip->daddr;

	// Lookup conntrack (connection tracking) information - actually eBPF map (backend -> client)
	// Check if it's either a:
	// - client request: Connection doesn't yet exists
	// - backend response: Connection exists
	struct four_tuple_t in;
	in.src_ip = ip->daddr; // Load Balancer IP
	in.dst_ip = ip->saddr; // Client or Backend IP 
	in.src_port = bpf_ntohs(tcp->source); // Load Balancer destination port
	in.dst_port = bpf_ntohs(tcp->dest); // Client or Backend source port
	
	struct bpf_fib_lookup fib = {};
	struct endpoint *out = bpf_map_lookup_elem(&conntrack, &in);
	if (!out) {
		bpf_printk("Packet from client because no such connection exists yet");	

		// Choose backend using consistent hashing (no routing table needed)
		// Hash the 4-tuple for persistent backend routing 
		// (Could also be 5-tuple but we only showcase TCP traffic load balancing)
		// Perform modulo with the number of backends which we hardcode for simplicity
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

		fib.family = AF_INET;
		fib.ipv4_src = ip->daddr;
		fib.ipv4_dst = bpf_htonl(backend->ip);
		fib.l4_protocol = ip->protocol;
		fib.tot_len = bpf_ntohs(ip->tot_len);
		fib.ifindex = ctx->ingress_ifindex; /* start lookup from ingress */
		int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);

		if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
			bpf_printk("FIB success: ifindex=%d\n", fib.ifindex);
			bpf_printk("DMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				fib.dmac[0], fib.dmac[1], fib.dmac[2],
				fib.dmac[3], fib.dmac[4], fib.dmac[5]);
			bpf_printk("SMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				fib.smac[0], fib.smac[1], fib.smac[2],
				fib.smac[3], fib.smac[4], fib.smac[5]);
		} else {
			bpf_printk("FIB lookup failed: rc=%d\n", rc);
		}
		
		// Store connection in the conntrack eBPF map (client -> backend)
		struct four_tuple_t in_loadbalancer;
		in_loadbalancer.src_ip = ip->daddr; // Load Balancer IP - 2.0.16.172
		in_loadbalancer.dst_ip = bpf_htonl(backend->ip); // Backend IP - 3.0.16.172
		in_loadbalancer.src_port = bpf_ntohs(tcp->dest); // Load Balancer destination port
		in_loadbalancer.dst_port = bpf_ntohs(tcp->source); // Backend destination port - same as Load Balancer destination port because we don't change it
		struct endpoint client;
		client.ip = ip->saddr; // Client IP
		__builtin_memcpy(client.mac, eth->h_source, ETH_ALEN); // Client MAC address
		int ret = bpf_map_update_elem(&conntrack, &in_loadbalancer, &client, BPF_ANY);
		if (ret != 0) {
			bpf_printk("Failed to update conntrack eBPF map");
		}

		// Replace destination IP with backends IP
		ip->daddr = bpf_ntohl(backend->ip);
		// Replace destination MAC with backends MAC address
		__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
	} else {
		bpf_printk("Packet from backend because the connection exists - redirecting back to client");
                bpf_printk("Client IP: %pI4, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    out->ip,
                    out->mac[0], out->mac[1], out->mac[2],
                    out->mac[3], out->mac[4], out->mac[5]);
		fib.family = AF_INET;
		fib.ipv4_src = ip->daddr;
		fib.ipv4_dst = out->ip;
		fib.l4_protocol = ip->protocol;
		fib.tot_len = bpf_ntohs(ip->tot_len);
		fib.ifindex = ctx->ingress_ifindex; /* start lookup from ingress */
		int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);

		if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
			bpf_printk("FIB success: ifindex=%d\n", fib.ifindex);
			bpf_printk("DMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				fib.dmac[0], fib.dmac[1], fib.dmac[2],
				fib.dmac[3], fib.dmac[4], fib.dmac[5]);
			bpf_printk("SMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				fib.smac[0], fib.smac[1], fib.smac[2],
				fib.smac[3], fib.smac[4], fib.smac[5]);
		} else {
			bpf_printk("FIB lookup failed: rc=%d\n", rc);
		}
		
		// Redirect back to client source IP
		ip->daddr = out->ip;
		__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
    	}

	// Update IP source address to the load balancer IP
	// Update Ethernet source MAC address to the load-balancer MAC
	ip->saddr = lb_ip;
	__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);

	// Recalculate IP checksum
	ip->check = recalc_ip_checksum(ip);

	// Recalculate TCP checksum
	tcp->check = recalc_tcp_checksum(tcp, ip, data_end);

	__u32 saddr_new = ip->saddr;  
        __u32 daddr_new = ip->daddr; 
	bpf_printk("Redirecting packet from IP %pI4 to IP %pI4", &saddr_new, &daddr_new);
	bpf_printk("New Dest MAC: %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	bpf_printk("New Source MAC: %x:%x:%x:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

	// Return XDP_TX to transmit the modified packet back to the network
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
