#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/inet.h>
#include <net/ip.h>

#define TARGET_IP "10.0.1.2"
#define TARGET_PORT 8083
#define WATCH_PORT 8080

// PRE-ROUTING HOOK: Modifies the packet
static unsigned int prerouting_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct udphdr *udph;
    __be32 new_daddr;
    int udplen;

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP) return NF_ACCEPT;
    udph = udp_hdr(skb);

    if (ntohs(udph->dest) == WATCH_PORT) {
        printk(KERN_INFO "FORWARD: UDP;%pI4:%u -> %pI4:%u\n", &iph->saddr, ntohs(udph->source), &iph->daddr, ntohs(udph->dest));

        in4_pton(TARGET_IP, -1, (u8 *)&new_daddr, '\0', NULL);
        iph->daddr = new_daddr;
        udph->dest = htons(TARGET_PORT);

        udplen = ntohs(udph->len);
        udph->check = 0;
        skb->csum = csum_partial((unsigned char *)udph, udplen, 0);
        udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udplen, IPPROTO_UDP, skb->csum);

        iph->check = 0;
        ip_send_check(iph);

        printk(KERN_INFO "MODIFIED: UDP;%pI4:%u -> %pI4:%u\n", &iph->saddr, ntohs(udph->source), &iph->daddr, ntohs(udph->dest));
    }
    return NF_ACCEPT;
}

// FORWARD HOOK: Logs the packet after routing
static unsigned int forward_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);

    if (iph && udph && ntohs(udph->dest) == TARGET_PORT) {
        printk(KERN_INFO "FORWARDING: UDP;%pI4:%u -> %pI4:%u\n", &iph->saddr, ntohs(udph->source), &iph->daddr, ntohs(udph->dest));
    }
    return NF_ACCEPT;
}

// POST-ROUTING HOOK: Logs the packet just before it leaves
static unsigned int postrouting_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);

    if (iph && udph && ntohs(udph->dest) == TARGET_PORT) {
        printk(KERN_INFO "POSTROUTING: UDP;%pI4:%u -> %pI4:%u\n", &iph->saddr, ntohs(udph->source), &iph->daddr, ntohs(udph->dest));
    }
    return NF_ACCEPT;
}

// Array of all hooks to register
static struct nf_hook_ops netfilter_hooks[] = {
    { .hook = prerouting_hook_func, .pf = PF_INET, .hooknum = NF_INET_PRE_ROUTING, .priority = NF_IP_PRI_FIRST },
    { .hook = forward_hook_func, .pf = PF_INET, .hooknum = NF_INET_FORWARD, .priority = NF_IP_PRI_FIRST },
    { .hook = postrouting_hook_func, .pf = PF_INET, .hooknum = NF_INET_POST_ROUTING, .priority = NF_IP_PRI_FIRST },
};

// Module initialization and exit
static int __init nf_module_init(void) {
    printk(KERN_INFO "Netfilter redirect module loaded.\n");
    nf_register_net_hooks(&init_net, netfilter_hooks, ARRAY_SIZE(netfilter_hooks));
    return 0;
}

static void __exit nf_module_exit(void) {
    nf_unregister_net_hooks(&init_net, netfilter_hooks, ARRAY_SIZE(netfilter_hooks));
    printk(KERN_INFO "Netfilter redirect module unloaded.\n");
}

module_init(nf_module_init);
module_exit(nf_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("REDZA");
MODULE_DESCRIPTION("A simple Netfilter module to redirect UDP packets with full debugging.");
