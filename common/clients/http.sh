#!/bin/bash

# Simple HTTP Client

server_name=$1
server_ip=$(/usr/local/dos-mitigation/common/bin/hostname_to_ip $server_name)
server_port=80
request_interval=$2
file_size=$3

log_dir=/tmp/logs/
mkdir -p $log_dir
log_file="$log_dir/http.csv"

url="http://$server_ip:$server_port/junk.bin"

echo "status, start, end" >$log_file
while true; do
    start="$(date +%s%N)"
    curl -s --create-dirs --no-keepalive -H 'Cache-Control: no-cache' $url -o /tmp/http_junk -r 1-$file_size --cacert /usr/local/dos-mitigation/server.crt
    ok=$?
    end="$(date +%s%N)"
    echo "$ok,$start,$end" >>$log_file
    sleep $request_interval
done

