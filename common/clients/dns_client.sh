#!/bin/bash

# Simple DNS Client

server_name=auth0
server_ip="10.0.1.1"
server_port=53
request_interval=$2
query_domain="www.google.com"
threshold=$3
log_dir=/tmp/logs/
# mkdir -p $log_dir
# log_file="$log_dir/dns.csv"
mkdir -p $log_dir
log_file="$log_dir/dns.csv"
source_file="./common/clients/dns_pow_client.c"
client_bin="./common/clients/dns_pow_client"

# url="http://$server_ip:$server_port/junk/foo.bin"
echo "[INFO] Compiling $source_file..."
gcc -o "$client_bin" "$source_file"
if [ $? -ne 0 ]; then
    echo "[ERROR] Compilation failed. Exiting."
    exit 1
fi
echo "[INFO] Compilation successful."


echo "status, start, end" >$log_file
while true; do
    start="$(date +%s%N)"
#    curl -s --create-dirs --no-keepalive -H 'Cache-Control: no-cache' $url -o /tmp/http_junk -r 1-$file_size --cacert /usr/local/dos-mitigation/server.pem
#    dig @$server_ip $query_domain +norecurse +time=2 +tries=1 > /dev/null
    $client_bin "$server_ip" "$threshold"

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

