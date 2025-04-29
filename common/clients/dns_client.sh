#!/bin/bash

# Simple DNS Client

server_name=auth0
server_ip="10.0.1.1"
server_port=53
request_interval=$2
query_domain="www.google.com"

log_dir=/tmp/logs/
# mkdir -p $log_dir
# log_file="$log_dir/dns.csv"
mkdir -p $log_dir
log_file="$log_dir/http.csv"

# url="http://$server_ip:$server_port/junk/foo.bin"

echo "status, start, end" >$log_file
while true; do
    start="$(date +%s%N)"
#    curl -s --create-dirs --no-keepalive -H 'Cache-Control: no-cache' $url -o /tmp/http_junk -r 1-$file_size --cacert /usr/local/dos-mitigation/server.pem
    dig @$server_ip $query_domain +norecurse +time=2 +tries=1 > /dev/null
    ok=$?
    end="$(date +%s%N)"
    echo "$ok,$start,$end" >>$log_file
#    if dig +short @$server_ip "$query_domain" > /dev/null 2>&1; then
#      echo "$query_domain resolved successfully."
#    else
#      echo "Failed to resolve $query_domain."
#    fi
    sleep $request_interval
done

