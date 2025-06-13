#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#define WATCH_PORT   8080                // original destination port      
#define TARGET_IP    0x0a000102          // 10.0.1.2 in network byte order 
#define TARGET_PORT  8083                // new destination port           

// RFC 1624 incremental IPv4 checksum update (daddr only)
static __always_inline void
ipv4_csum_replace_daddr(struct iphdr *iph, __be32 new_daddr)
{
    __u32 old = iph->daddr;
    // subtract old, add new, fold twice, complement 
    __u32 diff = (~old) + new_daddr;
    diff  = (diff & 0xffff) + (diff >> 16);
    diff  = (diff & 0xffff) + (diff >> 16);

    __u32 csum = (~iph->check & 0xffff) + diff;
    csum  = (csum & 0xffff) + (csum >> 16);

    iph->check = ~csum;
    iph->daddr = new_daddr;
}

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    // Ethernet 
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IPv4 
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_len = iph->ihl * 4;                 // header length in bytes
    if (ip_len < sizeof(struct iphdr))
        return XDP_PASS;
    if ((void *)iph + ip_len > data_end)
        return XDP_PASS;

    // UDP 
    struct udphdr *udph = (void *)iph + ip_len;
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(udph->dest) != WATCH_PORT)     // only packets to 8080   
        return XDP_PASS;
        
    // Log old destination before touching packet 
    __be32 old_ip = iph->daddr;
    __u16 old_port = bpf_ntohs(udph->dest);
    bpf_printk("old dst=0x%x:%u", bpf_ntohl(old_ip), old_port);

    // Rewrite 
    ipv4_csum_replace_daddr(iph, bpf_htonl(TARGET_IP));

    udph->dest = bpf_htons(TARGET_PORT);
    udph->check = 0;                             // 0 = OK for UDP/IPv4   
    
    // Log new destination after rewrite 
    __be32 new_ip = iph->daddr;
    __u16 new_port = TARGET_PORT;
    bpf_printk("new dst=0x%x:%u", bpf_ntohl(new_ip), new_port);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


