#!/bin/bash

_toggle=$1

if [ -z "$2" ]; then
    _devs=($(/usr/local/dos-mitigation/common/bin/list_exp_devs))
else
    _devs=($2)
fi

for _dev in "${_devs[@]}"; do
  /usr/local/dos-mitigation/common/ebpf/bin/tc_clear $_dev
  if [[ $_toggle -eq 1 ]]; then
    clang -O2 -target bpf -c /usr/local/dos-mitigation/common/ebpf/syn_pad.c -o syn_pad\
      -I /usr/include/bpf\
      -I /usr/include/iproute2\
      -I /usr/include/x86_64-linux-gnu\
      -Wno-int-to-void-pointer-cast
      
    /usr/local/dos-mitigation/common/ebpf/bin/tc_load_egress syn_pad $interface
  fi
done
