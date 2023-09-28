#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include "bpf_elf.h"

#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
        inline __attribute__((always_inline))
#endif

__section("ingress")
int tc_ingress(struct __sk_buff *skb) {
  return TC_ACT_OK;
}

__section("egress")
int tc_egress(struct __sk_buff *skb) {
  return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
