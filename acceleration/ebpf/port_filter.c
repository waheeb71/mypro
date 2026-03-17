/*
 * Enterprise NGFW v2.0 - eBPF XDP Port Filter
 * 
 * High-performance port filtering at kernel level using XDP.
 * Provides both whitelist and blacklist modes with per-port statistics.
 * 
 * Features:
 * - TCP/UDP port filtering
 * - Whitelist/Blacklist modes
 * - Per-port packet/byte counters
 * - Zero-copy packet processing
 * - 10Gbps+ throughput
 * 
 * Author: Enterprise NGFW Team
 * License: Proprietary
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map Definitions */

// Port whitelist: key=port, value=1 (allowed)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, __u8);
} port_whitelist SEC(".maps");

// Port blacklist: key=port, value=1 (blocked)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, __u8);
} port_blacklist SEC(".maps");

// Port statistics: key=port, value=stats
struct port_stats {
    __u64 packets;
    __u64 bytes;
    __u64 drops;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, struct port_stats);
} port_statistics SEC(".maps");

// Global configuration
struct filter_config {
    __u8 mode;           // 0=disabled, 1=whitelist, 2=blacklist
    __u8 filter_tcp;     // Filter TCP traffic
    __u8 filter_udp;     // Filter UDP traffic
    __u8 log_drops;      // Log dropped packets
    __u32 default_action; // XDP_PASS or XDP_DROP
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct filter_config);
} config_map SEC(".maps");

/* Helper Functions */

static __always_inline __u16 parse_tcp_port(struct tcphdr *tcp, void *data_end, int is_src) {
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return 0;
    
    return is_src ? bpf_ntohs(tcp->source) : bpf_ntohs(tcp->dest);
}

static __always_inline __u16 parse_udp_port(struct udphdr *udp, void *data_end, int is_src) {
    if ((void *)udp + sizeof(*udp) > data_end)
        return 0;
    
    return is_src ? bpf_ntohs(udp->source) : bpf_ntohs(udp->dest);
}

static __always_inline void update_port_stats(__u16 port, __u64 bytes, int dropped) {
    struct port_stats *stats;
    struct port_stats new_stats = {0};
    
    stats = bpf_map_lookup_elem(&port_statistics, &port);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, bytes);
        if (dropped)
            __sync_fetch_and_add(&stats->drops, 1);
        stats->last_seen = bpf_ktime_get_ns();
    } else {
        // Create new entry
        new_stats.packets = 1;
        new_stats.bytes = bytes;
        new_stats.drops = dropped ? 1 : 0;
        new_stats.last_seen = bpf_ktime_get_ns();
        bpf_map_update_elem(&port_statistics, &port, &new_stats, BPF_ANY);
    }
}

static __always_inline int check_port_allowed(__u16 port, __u8 mode) {
    __u8 *val;
    
    if (mode == 0) {
        // Filtering disabled
        return 1;
    } else if (mode == 1) {
        // Whitelist mode: only listed ports allowed
        val = bpf_map_lookup_elem(&port_whitelist, &port);
        return val != NULL;
    } else if (mode == 2) {
        // Blacklist mode: listed ports blocked
        val = bpf_map_lookup_elem(&port_blacklist, &port);
        return val == NULL;
    }
    
    return 1; // Default: allow
}

static __always_inline int process_transport_layer(void *transport_hdr, void *data_end, 
                                                    __u8 protocol, __u64 packet_size,
                                                    struct filter_config *cfg) {
    __u16 src_port = 0, dst_port = 0;
    int allowed = 1;
    
    if (protocol == IPPROTO_TCP && cfg->filter_tcp) {
        struct tcphdr *tcp = transport_hdr;
        src_port = parse_tcp_port(tcp, data_end, 1);
        dst_port = parse_tcp_port(tcp, data_end, 0);
        
        if (src_port == 0 || dst_port == 0)
            return XDP_PASS; // Malformed packet
        
        // Check both source and destination ports
        allowed = check_port_allowed(src_port, cfg->mode) && 
                  check_port_allowed(dst_port, cfg->mode);
        
        // Update statistics
        update_port_stats(src_port, packet_size, !allowed);
        update_port_stats(dst_port, packet_size, !allowed);
        
    } else if (protocol == IPPROTO_UDP && cfg->filter_udp) {
        struct udphdr *udp = transport_hdr;
        src_port = parse_udp_port(udp, data_end, 1);
        dst_port = parse_udp_port(udp, data_end, 0);
        
        if (src_port == 0 || dst_port == 0)
            return XDP_PASS; // Malformed packet
        
        // Check both source and destination ports
        allowed = check_port_allowed(src_port, cfg->mode) && 
                  check_port_allowed(dst_port, cfg->mode);
        
        // Update statistics
        update_port_stats(src_port, packet_size, !allowed);
        update_port_stats(dst_port, packet_size, !allowed);
    } else {
        // Protocol not filtered
        return XDP_PASS;
    }
    
    return allowed ? XDP_PASS : XDP_DROP;
}

/* Main XDP Program */

SEC("xdp")
int xdp_port_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 packet_size = data_end - data;
    __u32 key = 0;
    
    // Get configuration
    struct filter_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return XDP_PASS; // No config, allow all
    
    if (cfg->mode == 0)
        return XDP_PASS; // Filtering disabled
    
    // Parse Ethernet header
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    
    // IPv4 processing
    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        
        // Check protocol
        __u8 protocol = iph->protocol;
        void *transport_hdr = (void *)iph + (iph->ihl * 4);
        
        if (transport_hdr > data_end)
            return XDP_PASS;
        
        return process_transport_layer(transport_hdr, data_end, protocol, 
                                       packet_size, cfg);
    }
    // IPv6 processing
    else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        
        __u8 protocol = ip6h->nexthdr;
        void *transport_hdr = (void *)(ip6h + 1);
        
        if (transport_hdr > data_end)
            return XDP_PASS;
        
        return process_transport_layer(transport_hdr, data_end, protocol, 
                                       packet_size, cfg);
    }
    
    // Non-IP traffic: pass through
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";