#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
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

const __u32 MIN_LENGTH = 80;
const bool PAD_INGRESS = 0;
const bool PAD_EGRESS = 1;
const char pad_bytes[80] = {
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP
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

enum Maps {DROP_MAP, PASS_MAP, ITERS_MAP};

static __inline int account_data(struct __sk_buff *skb, uint32_t dir, int act) {
  uint32_t *bytes;

  bytes = map_lookup_elem(&acc_map, &dir);
  if (bytes)
    lock_xadd(bytes, skb->len);
  return act;
}

static __inline bool is_tcp(struct ethhdr *ethh, struct iphdr *iph) {
	return (ethh->h_proto == __constant_htons(ETH_P_IP) && iph->protocol == IPPROTO_TCP);
}

static __inline bool is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

static __inline bool valid_syn_pad(struct iphdr* iph, __u32 min_length) {
	bool valid;
	__u32 len = (__u32)__constant_ntohs(iph->tot_len);
	valid = (len >= min_length);
	return valid;
}

static __inline int do_syn_pad(struct __sk_buff *skb, struct iphdr *iph, __u32 new_length) {
	__u32 bytes_needed = new_length - iph->tot_len;
  if (bytes_needed <= 0) {
    return TC_ACT_OK;
	}

	// Expand the packet buffer
	long err = bpf_skb_change_tail(skb, new_length, 0);
	if (err != 0) {
		return TC_ACT_SHOT;
	}

	// Re-do sanity checks
	void *data = (void *)(uintptr_t)skb->data;
	void *data_end = (void *)(uintptr_t)skb->data_end;
	struct ethhdr *ethh = data;
	iph = (struct iphdr *)(ethh + 1);
	struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

	/* sanity check needed by the eBPF verifier */
	if ((void *)tcph >= data_end) {
		return TC_ACT_SHOT;
	}

	__u32 offset = (__u32)(data_end - data) - bytes_needed;
	__u32 len = bytes_needed;
	bpf_skb_store_bytes(skb, offset, (void*)pad_bytes, len, BPF_F_INVALIDATE_HASH);
	bpf_skb_store_bytes(skb, offset + (bytes_needed - 1), (void*)&end_op, 1, BPF_F_RECOMPUTE_CSUM);
}

__section("ingress")
int tc_ingress(struct __sk_buff *skb) {
	void *data = (void *)(uintptr_t)skb->data;
	void *data_end = (void *)(uintptr_t)skb->data_end;
	struct ethhdr *ethh = data;
	struct iphdr *iph = (struct iphdr *)(ethh + 1);
	struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

	/* sanity check needed by the eBPF verifier */
	if ((void *)tcph >= data_end)
		return TC_ACT_OK;

	/* skip non-TCP packets */
	if (!is_tcp(ethh, iph))
		return TC_ACT_OK;

	if (!is_syn(tcph))
		return TC_ACT_OK;

	if (!valid_syn_pad(iph, MIN_LENGTH)) {
		if (PAD_INGRESS) {
			int action = do_syn_pad(skb, iph, MIN_LENGTH);
      return action;
		} else {
			return TC_ACT_SHOT;
		}
	}
	return TC_ACT_OK;
}

__section("egress")
int tc_egress(struct __sk_buff *skb) {
	void *data = (void *)(uintptr_t)skb->data;
	void *data_end = (void *)(uintptr_t)skb->data_end;
	struct ethhdr *ethh = data;
	struct iphdr *iph = (struct iphdr *)(ethh + 1);
	struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

	/* sanity check needed by the eBPF verifier */
	if ((void *)(tcph + 1) > data_end)
		return TC_ACT_OK;

	/* skip non-TCP packets */
	if (!is_tcp(ethh, iph))
		return TC_ACT_OK;

	/* skip non-SYN packets */
	if (!is_syn(tcph))
		return TC_ACT_OK;

	if (!valid_syn_pad(iph, MIN_LENGTH)) {
		if (PAD_EGRESS) {
			int action = do_syn_pad(skb, iph, MIN_LENGTH);
			return action;
		} else {
			return TC_ACT_SHOT;
		}
	}

	return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
