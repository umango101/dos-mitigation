#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
// #include <float.h>
#include "bpf_elf.h"

#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
        inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
        ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
        (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#if !defined (get16bits)
#define get16bits(d) ((((unsigned long)(((const unsigned char *)(d))[1])) << 8)\
                       +(unsigned long)(((const unsigned char *)(d))[0]) )
#endif

#ifndef NULL
# define NULL 0
#endif

// const unsigned long POW_THRESHOLD = 0; // k=1
// const unsigned long POW_THRESHOLD  = 2147483648; // k=2
// const unsigned long POW_THRESHOLD = 3221225472; // k=4
// const unsigned long POW_THRESHOLD  = 3758096384; // k=8
// const unsigned long POW_THRESHOLD  = 4026531840; // k=16
// const unsigned long POW_THRESHOLD  = 4160749568; // k=32
// const unsigned long POW_THRESHOLD  = 4227858432; // k=64

// theta = (2^32) * (k - 1) / k)
// #if POW_ITERS > 0
// 	float POW_THRESHOLD = 4294967296.0 * (((float)POW_ITERS-1.0)/(float)POW_ITERS);
// #else
// 	float POW_THRESHOLD = 0.0;
// #endif

// const unsigned long POW_THRESHOLD = 4278190080;
const unsigned short MAX_ITERS = 256;

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

struct bpf_elf_map acc_map __section("maps") = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 2,
};

// enum Maps {DROP_MAP, PASS_MAP, ITERS_MAP};

static __inline int account_data(uint32_t dir, int amt) {
  uint32_t *bytes;

  bytes = map_lookup_elem(&acc_map, &dir);
  if (bytes)
    lock_xadd(bytes, amt);
  return amt;
}

struct message_digest {
	unsigned long saddr;
	unsigned long daddr;
	unsigned short sport;
	unsigned short dport;
	unsigned long seq;
	unsigned long ack_seq;
};

static __inline bool is_tcp(struct ethhdr *ethh, struct iphdr *iph) {
	return (ethh->h_proto == __constant_htons(ETH_P_IP) && iph->protocol == IPPROTO_TCP);
}

static __inline bool is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

static __inline unsigned long SuperFastHash (const char* data, int len) {
	uint32_t hash = len, tmp;
	int rem;

	if (len <= 0 || data == NULL) return 0;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
	for (;len > 0; len--) {
		hash  += get16bits (data);
		tmp    = (get16bits (data+2) << 11) ^ hash;
		hash   = (hash << 16) ^ tmp;
		data  += 2*sizeof (uint16_t);
		hash  += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
    	case 3: hash += get16bits (data);
            hash ^= hash << 16;
            hash ^= ((signed char)data[sizeof (uint16_t)]) << 18;
            hash += hash >> 11;
            break;
    	case 2: hash += get16bits (data);
            hash ^= hash << 11;
            hash += hash >> 17;
            break;
    	case 1: hash += (signed char)*data;
            hash ^= hash << 10;
            hash += hash >> 1;
  	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}

static __inline unsigned long syn_hash(struct message_digest* digest) {
	return SuperFastHash((const char *)digest, sizeof(struct message_digest));
}

static __inline bool valid_syn_pow(struct iphdr* iph, struct tcphdr* tcph) {
	struct message_digest digest;
	digest.saddr = iph->saddr;
	digest.daddr = iph->daddr;
	digest.sport = tcph->source;
	digest.dport = tcph->dest;
	digest.seq = tcph->seq;
	digest.ack_seq = tcph->ack_seq;

	unsigned long hash = syn_hash(&digest);
	bool valid = (hash >= (unsigned long) POW_THRESHOLD);
	return valid;
}

static __inline unsigned short do_syn_pow(struct iphdr* iph, struct tcphdr* tcph) {
	unsigned long hash = 0;
	unsigned long best_hash = 0;
	unsigned short hash_iters = 0;
	// unsigned long nonce = bp, __u32 old_ack_seqf_get_prandom_u32();
	unsigned long nonce = 1;
	// unsigned long nonce = (unsigned long)(e->start_ts & 0xffffffff);
	unsigned long best_nonce = nonce;

	struct message_digest digest;
	digest.saddr = iph->saddr;
	digest.daddr = iph->daddr;
	digest.sport = tcph->source;
	digest.dport = tcph->dest;
	digest.seq = tcph->seq;

	if (POW_THRESHOLD > 0) {
		#pragma unroll
		for (unsigned short i=0; i<MAX_ITERS; i++) {
			digest.ack_seq = __constant_htonl(nonce + i);
			hash = syn_hash(&digest);
			hash_iters += 1;
			if (hash > best_hash) {
				best_nonce = nonce + i;
				best_hash = hash;
				if (best_hash >= POW_THRESHOLD) {
					break;
				}
			}
		}
		tcph->ack_seq = __constant_htonl(best_nonce);
	}
	return hash_iters;
}

__section("ingress")
int tc_ingress(struct __sk_buff *skb) {
	void *data = (void *)(uintptr_t)skb->data;
	struct ethhdr *ethh = data;
	void *data_end = (void *)(uintptr_t)skb->data_end;

	if (data + sizeof(*ethh) > data_end)
		return TC_ACT_OK;

	if (ethh->h_proto != htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *iph = data + sizeof(*ethh);
	if ((void *)iph + sizeof(*iph) > data_end)
		return TC_ACT_OK;

	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	struct tcphdr *tcph = (void *)iph + sizeof(*iph);
	if ((void *)tcph + sizeof(*tcph) > data_end)
		return TC_ACT_OK;

	if (!is_syn(tcph))
		return TC_ACT_OK;

	bool valid = valid_syn_pow(iph, tcph);

	if (!valid) {
		// account_data(1, 1);
		return TC_ACT_SHOT;
	}

	// account_data(0, 1);
	return TC_ACT_OK;
}

__section("egress")
int tc_egress(struct __sk_buff *skb) {
	void *data = (void *)(uintptr_t)skb->data;
	struct ethhdr *ethh = data;
	void *data_end = (void *)(uintptr_t)skb->data_end;

	if (data + sizeof(*ethh) > data_end)
		return TC_ACT_OK;

	if (ethh->h_proto != htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *iph = data + sizeof(*ethh);
	if ((void *)iph + sizeof(*iph) > data_end)
		return TC_ACT_OK;

	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	struct tcphdr *tcph = (void *)iph + sizeof(*iph);
	if ((void *)tcph + sizeof(*tcph) > data_end)
		return TC_ACT_OK;

	if (!is_syn(tcph))
		return TC_ACT_OK;

	uint32_t iters = (uint32_t)do_syn_pow(iph, tcph);

	// uint32_t *past_iters;
	// uint32_t dir = 1;
	// past_iters = map_lookup_elem(&acc_map, &dir);
	// if (past_iters)
	// 	lock_xadd(past_iters, tcph->ack_seq);

	return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
