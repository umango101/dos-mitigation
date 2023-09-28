/*
eBPF implementation of SYN Padding
Egress program pad outgoing SYNs to a minimum of 80 bytes (including IP header)
Ingress program drops any SYNs with insufficient padding

Author: Samuel DeLaughter
Last Modified: 11/4/22
License: MIT

*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/pkt_cls.h>
#include "bpf_elf.h"
#include "bpf_helpers.h"

#ifndef __section
	#define __section(NAME)                  \
		__attribute__((section(NAME), used))
#endif

#ifndef __inline
	#define __inline                         \
		inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
	#define lock_xadd(ptr, val)              \
		((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
	#define BPF_FUNC(NAME, ...)              \
		(*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

const __u32 MIN_LENGTH = 80;
const __u16 DATA_OFFSET = 15;

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

struct bpf_elf_map acc_map __section("maps") = {
  .type           = BPF_MAP_TYPE_ARRAY,
  .size_key       = sizeof(uint32_t),
  .size_value     = sizeof(uint32_t),
  .pinning        = PIN_GLOBAL_NS,
  .max_elem       = 2,
};

static __inline int account_data(struct __sk_buff *skb, uint32_t dir, int act) {
  uint32_t *bytes;

  bytes = map_lookup_elem(&acc_map, &dir);
  if (bytes)
    lock_xadd(bytes, skb->len);
  return act;
}

static __inline int is_syn(struct tcphdr* tcph) {
	int ok = (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
	return ok;
}

static __inline __u32 syn_pad_needed(struct iphdr* iph, __u32 min_length) {
	__u32 bytes_needed = 0;
	__u32 tot_len = (__u32)ntohs(iph->tot_len);
	if (tot_len < min_length) {
		bytes_needed = min_length - tot_len;
	}
	return bytes_needed;
}

__section("ingress")
int tc_ingress(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *iph = data + sizeof(*eth);
	if ((void *)iph + sizeof(*iph) > data_end)
		return TC_ACT_OK;

	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	struct tcphdr *tcph = (void *)iph + sizeof(*iph);
	if ((void *)tcph + sizeof(*tcph) > data_end)
		return TC_ACT_OK;

	if (!is_syn(tcph))
		return TC_ACT_OK;

	if (syn_pad_needed(iph, MIN_LENGTH)) {
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

__section("egress")
int tc_egress(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *iph = data + sizeof(*eth);
	if ((void *)iph + sizeof(*iph) > data_end)
		return TC_ACT_OK;

	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	struct tcphdr *tcph = (void *)iph + sizeof(*iph);
	if ((void *)tcph + sizeof(*tcph) > data_end)
		return TC_ACT_OK;

	if (!is_syn(tcph))
		return TC_ACT_OK;

	// Determine the amount of padding needed
	__u32 bytes_needed = syn_pad_needed(iph, MIN_LENGTH);
	if (!bytes_needed)
		return TC_ACT_OK;

	// Expand the packet buffer
	__u64 flags = 0;
	__u32 new_len = sizeof(*eth) + MIN_LENGTH;
	long err = bpf_skb_change_tail(skb, new_len, flags);
	if (err != 0) {
		return TC_ACT_SHOT;
	}

	// Re-do sanity checks
	// If something goes wrong this time, drop instead of passing
	data = (void *)(long)skb->data;
	eth = data;
	data_end = (void *)(long)skb->data_end;
	if (data + sizeof(*eth) > data_end)
		return TC_ACT_SHOT;
	if (eth->h_proto != htons(ETH_P_IP))
		return TC_ACT_SHOT;
	iph = data + sizeof(*eth);
	if ((void *)iph + sizeof(*iph) > data_end)
		return TC_ACT_SHOT;
	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_SHOT;
  tcph = (void *)iph + sizeof(*iph);
	if ((void *)tcph + sizeof(*tcph) > data_end)
		return TC_ACT_SHOT;

	// Update packet length and data offset
	iph->tot_len = __constant_htons((__u16)MIN_LENGTH);
	tcph->doff = DATA_OFFSET;

	return TC_ACT_OK;
}

char __license[] __section("license") = "MIT";
