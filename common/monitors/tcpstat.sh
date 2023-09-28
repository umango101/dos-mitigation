#!/bin/bash

_dev=$1
_dst=$2
_port=$3


log_dir=/tmp/logs
mkdir -p $log_dir

file_name="tcpstat.csv"

echo "bps, pps" >$log_dir/$file_name
sudo tcpstat -i $_dev -f "dst $_dst and port $_port" -o "%b, %p\n" 1 >>$log_dir/$file_name