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

static __inline void account_data(uint32_t dir) {
  uint32_t *bytes = map_lookup_elem(&acc_map, &dir);
  if (bytes) {
    lock_xadd(bytes, 1);
	}
}

static __inline int is_syn(struct tcphdr* tcph) {
	return (tcph->syn && !(tcph->ack) && !(tcph->fin) &&!(tcph->rst) &&!(tcph->psh));
}

__section("ingress")
int tc_ingress(struct __sk_buff *skb) {
	account_data(0);
	return TC_ACT_OK;
}

__section("egress")
int tc_egress(struct __sk_buff *skb) {
	account_data(1);
	return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
