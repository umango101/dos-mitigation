#!/bin/bash
set -euo pipefail

_toggle=$1
_iters=$2

_offset_interval_us=${POW_OFFSET_INTERVAL_US:-2000}

_freshness_ms=${POW_FRESHNESS_MS:-100}

if [ -z "${3:-}" ]; then
    _devs=($(/usr/local/dos-mitigation/common/bin/list_exp_devs))
else
    _devs=($3)
fi

for _dev in "${_devs[@]}"; do
  /usr/local/dos-mitigation/common/ebpf/bin/tc_clear $_dev
  if [[ $_toggle -eq 1 ]]; then
    # theta = 2^32 * ((k-1) / k)
    pow_threshold=$(echo "(($_iters - 1) / $_iters) * 4294967295.0" | bc -l)
    # strip decimals
    pow_threshold=${pow_threshold%.*}

    if [ -z "$pow_threshold" ]; then
        pow_threshold=0
    fi

    clang -O2 -target bpf -D POW_THRESHOLD=$pow_threshold -D POW_FRESHNESS_MS=${_freshness_ms}ULL -c /usr/local/dos-mitigation/common/ebpf/dns_pow.c -o dns_pow\
      -I /usr/include/bpf\
      -I /usr/include/iproute2\
      -I /usr/include/x86_64-linux-gnu\
      -Wno-int-to-void-pointer-cast

    if [ $? -ne 0 ]; then
        echo "Failed to compile dns_pow.c with POW_THRESHOLD=$pow_threshold"
        exit 1
    fi

    echo "pow_threshold: $pow_threshold"
    echo "freshness window: ${_freshness_ms} ms"

    /usr/local/dos-mitigation/common/ebpf/bin/tc_load_ingress dns_pow $_dev
    OFFSETD=/usr/local/dos-mitigation/common/bin/dns_pow_offsetd
    if [ -x "$OFFSETD" ]; then
        # Kill any stale instance.
        pkill -f "$OFFSETD" 2>/dev/null || true
        # Brief settle, then launch detached. Logs to /var/log if writable,
        # else /tmp.
        sleep 0.05
        LOG=/var/log/dns_pow_offsetd.log
        if ! touch "$LOG" 2>/dev/null; then
            LOG=/tmp/dns_pow_offsetd.log
        fi
        nohup "$OFFSETD" --interval "$_offset_interval_us" --verbose \
            >> "$LOG" 2>&1 &
        disown || true
        echo "offset daemon: running (pid $!), interval ${_offset_interval_us} us, log $LOG"
    else
        echo "WARNING: $OFFSETD not found or not executable. Build it before running."
        echo "         All DNS packets will be dropped until the daemon is running."
    fi
  else
    # Toggle off: also stop the offset daemon if we know about it.
    pkill -f /usr/local/dos-mitigation/common/bin/dns_pow_offsetd 2>/dev/null || true
  fi
done
