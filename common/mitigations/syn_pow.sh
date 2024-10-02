#!/bin/bash

_toggle=$1
_iters=$2

if [ -z "$3" ]; then
    _devs=($(/usr/local/dos-mitigation/common/bin/list_exp_devs))
else
    _devs=($3)
fi

for _dev in "${_devs[@]}"; do
  /usr/local/dos-mitigation/common/ebpf/bin/tc_clear $_dev
  if [[ $_toggle -eq 1 ]]; then
    clang -O2 -target bpf -D POW_ITERS=$_iters -c /usr/local/dos-mitigation/common/ebpf/syn_pow.c -o syn_pow\
      -I /usr/include/bpf\
      -I /usr/include/iproute2\
      -I /usr/include/x86_64-linux-gnu\
      -Wno-int-to-void-pointer-cast

    /usr/local/dos-mitigation/common/ebpf/bin/tc_load syn_pow $interface
  fi
done
