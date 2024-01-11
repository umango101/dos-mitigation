#!/bin/bash

# Simple HTTP-3/QUIC Client

server_ip=$1
server_port=443
file_size=$2

remote_path="junk/$file_size"
url="https://$server_ip:$server_port/$remote_path"

curl -k --http3-only --create-dirs --no-keepalive -H 'Cache-Control: no-cache' $url -o /tmp/http_junk

