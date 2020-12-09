#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Natalia");
MODULE_DESCRIPTION("Network filtering by ports");

static struct nf_hook_ops* nfinf = NULL;
static struct nf_hook_ops* nfoutf = NULL;
static unsigned int funcIn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	printk(KERN_INFO "The filter is going to start working!\n");
	struct iphdr* iphead;
	struct tcphdr* tcphead;
	struct udphdr* udphead;
	if (!skb) {
		return NF_ACCEPT;
	}
	iphead = ip_hdr(skb);
	if (iphead->protocol == IPPROTO_UDP)
	{
		udphead = udp_hdr(skb);
		printk(KERN_INFO "Protocol UDP, input on port: %d", ntohs(udphead->dest));
		if (ntohs(udphead->dest) == 80)
		{
			printk(KERN_INFO "Inner packet: port 80, protocol: UDP, dropped\n");
			return NF_DROP;
		}
	}
	else if (iphead->protocol == IPPROTO_TCP)
	{
		tcphead = tcp_hdr(skb);
		printk(KERN_INFO "Protocol TCP, hook input on port: %d", ntohs(tcphead->dest));
		if (ntohs(tcphead->dest) == 80)
		{
			printk(KERN_INFO "Inner packet: port 80, protocol: TCP, dropped\n");
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}
static unsigned int funcOut(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	printk(KERN_INFO "The filter is going to start working!\n");
	struct iphdr* iphead;
	struct tcphdr* tcphead;
	struct udphdr* udphead;
	if (!skb) {
		return NF_ACCEPT;
	}
	iphead = ip_hdr(skb);
	if (iphead->protocol == IPPROTO_UDP)
	{
		udphead = udp_hdr(skb);
		printk(KERN_INFO "Protocol UDP, input on port: %d", ntohs(udphead->dest));
		if (ntohs(udphead->source) == 80)
		{
			printk(KERN_INFO "Out packet: port 80, protocol: UDP, dropped\n");
			return NF_DROP;
		}
	}
	else if (iphead->protocol == IPPROTO_TCP)
	{
		tcphead = tcp_hdr(skb);
		printk(KERN_INFO "Protocol TCP, hook input on port: %d", ntohs(tcphead->dest));
		if (ntohs(tcphead->source) == 80)
		{
			printk(KERN_INFO "Out packet: port 80, protocol: TCP, dropped\n");
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}
static int __init FilterInit(void) {
	//in
	nfinf= (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfinf->hook = (nf_hookfn*)funcIn;
	nfinf->hooknum = NF_INET_LOCAL_IN;
	nfinf->pf = PF_INET;
	nfinf->priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, nfinf);
	//out
	nfoutf = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfoutf->hook = (nf_hookfn*)funcOut;
	nfoutf->hooknum = NF_INET_LOCAL_OUT;
	nfoutf->pf = PF_INET;
	nfoutf->priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, nfoutf);
	printk(KERN_INFO "The filter is registered!\n");
	return 0;
}
static void __exit FilterExit(void) {
	printk(KERN_INFO "The filter is unregistered!\n");
	nf_unregister_net_hook(&init_net, nfinf);
	nf_unregister_net_hook(&init_net, nfoutf);
	kfree(nfinf);
	kfree(nfoutf);
}

module_init(FilterInit);
module_exit(FilterExit);