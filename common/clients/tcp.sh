#!/bin/bash

# Simple TCP Client

server_ip=$1
server_port=80
request_interval=$2

log_dir=/tmp/logs/
mkdir -p $log_dir

file_name="tcp.csv"

echo "status, start, end" >$log_dir/$file_name
while true; do
    start="$(date +%s%N)"
    nc -w 1 -z $server_ip 80
    ok=$?
    end="$(date +%s%N)"
    echo "$ok,$start,$end" >>$log_dir/$file_name
    sleep $request_interval
done
