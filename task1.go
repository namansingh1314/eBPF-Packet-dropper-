#define KBUILD_MODNAME "xdp_nvme_drop"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static inline int parse_ipv4(void *data, uint64_t nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;
    if (data + nh_off + sizeof(struct iphdr) > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, uint64_t nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;
    if (data + nh_off + sizeof(struct ipv6hdr) > data_end)
        return 0;
    return ip6h->nexthdr;
}

SEC("xdp")
int nvme_drop(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    uint64_t total = data_end - data;
    struct ethhdr *eth = data;
    uint16_t h_proto;
    uint32_t cur = 0;
    struct tcphdr *tcph;
    uint32_t i;
    int nbzeros = 0;
    bool found = false;

    cur = sizeof(*eth);
    if (data + cur > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_IP)) {
        h_proto = parse_ipv4(data, cur, data_end);
        cur += sizeof(struct iphdr);
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        h_proto = parse_ipv6(data, cur, data_end);
        cur += sizeof(struct ipv6hdr);
    } else {
        return XDP_PASS;
    }

    if (cur > 100)
        return XDP_PASS;

    if (h_proto != IPPROTO_TCP)
        return XDP_PASS;

    if (data + cur + sizeof(*tcph) > data_end)
        return XDP_PASS;

    tcph = data + cur;
    if (tcph->doff > 10)
        return XDP_PASS;

    if (data + cur + tcph->doff * 4 > data_end)
        return XDP_PASS;

    cur += tcph->doff * 4;

    if (tcph->dest != 4040)
        return XDP_PASS;

    if (cur > total || cur > 100)
        return XDP_PASS;

    nbzeros = 0;
    for (i = cur; data + i < data_end; i++) {
        if (*((uint8_t *)(data + i)) == 0 && !found) {
            nbzeros++;
        } else {
            found = true;
            break;
        }
    }

    if (found && nbzeros > 50) {
        bpf_printk("found nvme pdu tail seq=%u\n", bpf_ntohs(tcph->seq));
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
