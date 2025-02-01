#!/bin/bash

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y bind9 bind9utils bind9-doc net-tools firewalld
cp named.conf.local /etc/bind/named.conf.local
cp named.conf.options.auth0 /etc/bind/named.conf.options
mkdir /etc/bind/zones
cp db.google.com /etc/bind/zones
cp db.10 /etc/bind/zones
service bind9 restart
named-checkconf
firewall-cmd --permanent --add-service=dns
firewall-cmd --reload
systemctl enable --now named

new_hostname=$(hostname)

sudo sed -i "s/127.0.1.1\tdebian/127.0.1.1\t$new_hostname/" /etc/hosts
echo "Hostname is /etc/hosts updated to $new_hostname"
