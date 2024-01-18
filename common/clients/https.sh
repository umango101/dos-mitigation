#!/bin/bash

# Simple HTTP Client

server_ip=$1
server_port=443
request_interval=$2
file_size=$3

log_dir=/tmp/logs/
mkdir -p $log_dir
log_file="$log_dir/https.csv"

url="https://$server_ip:$server_port/junk.bin"

echo "status, start, end" >$log_file
while true; do
    start="$(date +%s%N)"
    curl -s -k --create-dirs --no-keepalive -H 'Cache-Control: no-cache' $url -o /tmp/http_junk -r 1-$file_size
    ok=$?
    end="$(date +%s%N)"
    echo "$ok,$start,$end" >>$log_file
    sleep $request_interval
done

