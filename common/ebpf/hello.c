#include <linux/bpf.h>

#ifndef __section
  #define __section(x)  __attribute__((section(x), used))
#endif

__section("classifier") int main(struct __sk_buff *skb) {
  return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
