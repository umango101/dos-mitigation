#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
// #include <linux/skbuff.h>
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

#ifndef NULL
	#define NULL 0
#endif

#ifndef EOP
	#define EOP 0
#endif

#ifndef NOP
	#define NOP 1
#endif

#ifndef INGRESS
	#define INGRESS 0
#endif

#ifndef EGRESS
	#define EGRESS 1
#endif

const __u32 SEQ_NUM = 42;
const __u32 MIN_LENGTH = 80;
const bool PAD_INGRESS = 0;
const bool PAD_EGRESS = 1;
const char pad_bytes[40] = {
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
};
const char end_op = EOP;

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
	__u32 tot_len = (__u32)__constant_ntohs(iph->tot_len);
	if (tot_len >= min_length)
		return 0;
	__u32 bytes_needed = min_length - tot_len;
	return bytes_needed;
}

static __inline bool valid_syn_pad(struct iphdr* iph, __u32 min_length) {
	bool valid;
	__u32 len = (__u32)__constant_ntohs(iph->tot_len);
	valid = (len >= min_length);
	return valid;
}

static __inline int do_syn_pad(struct __sk_buff *skb, struct iphdr *iph, __u32 bytes_needed, __u32 offset) {
	// Expand the packet buffer
	__u32 new_length = sizeof(*skb) + bytes_needed;
	long err = bpf_skb_change_tail(skb, new_length, 0);
	if (err != 0) {
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;

	// Re-do sanity checks
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_SHOT;

	if (eth->h_proto != htons(ETH_P_IP))
		return TC_ACT_SHOT;

	iph = data + sizeof(*eth);
	if ((void *)iph + sizeof(*iph) > data_end)
		return TC_ACT_SHOT;

	iph->tot_len = (__u32)__constant_htons(MIN_LENGTH);

	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_SHOT;

	struct tcphdr *tcph = (void *)iph + sizeof(*iph);
	if ((void *)tcph + sizeof(*tcph) > data_end)
		return TC_ACT_SHOT;

	tcph->doff = 15;

	if (bytes_needed > 1) {
		#pragma unroll
		for (int i=0; i<bytes_needed-1; i++) {
			*((char *)offset + i) = NOP;
		}
	}
	*((char *)offset + (bytes_needed - 1)) = EOP;

	// bpf_skb_store_bytes(skb, offset, (void*)pad_bytes, bytes_needed, BPF_F_INVALIDATE_HASH);
	// bpf_skb_store_bytes(skb, offset + (bytes_needed - 1), (void*)&end_op, 1, BPF_F_RECOMPUTE_CSUM);
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

	// int n_tcp_op_bytes = (tcph->doff - 5) * 4;
	// char *tcp_ops = (void *)tcph + sizeof(*tcph);
  // if ((void *)tcp_ops <= data_end) {
	// 	char *payload = (void *)tcp_ops + n_tcp_op_bytes;
  // }

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


	tcph->seq = __constant_htonl(iph->tot_len);
	return TC_ACT_OK;

	// int n_tcp_op_bytes = (tcph->doff - 5) * 4;
	// char *tcp_ops = (void *)tcph + sizeof(*tcph);
  // if ((void *)tcp_ops <= data_end) {
	// 	char *payload = (void *)tcp_ops + n_tcp_op_bytes;
  // }

	// __u32 bytes_needed = syn_pad_needed(iph, MIN_LENGTH);
	// if (!bytes_needed)
	// 	return TC_ACT_OK;
	//
	// __u32 offset = (__u32)((void *)tcph + sizeof(*tcph)) + (tcph->doff * 4);
	// int action = do_syn_pad(skb, iph, bytes_needed, offset);
	// return action;
}

char __license[] __section("license") = "GPL";
