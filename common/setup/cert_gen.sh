#!/bin/bash

cd
sudo snap install --classic certbot
openssl genrsa -aes256 -passout pass:gsahdg -out server.pass.key 4096
openssl rsa -passin pass:gsahdg -in server.pass.key -out server.key
rm server.pass.key
common_name=$(/usr/local/dos-mitigation/common/bin/hostname_to_ip $(hostname -s))
openssl req -new -key server.key -out server.csr -subj /CN=${common_name}/
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
sudo mkdir -p /usr/local/nginx/certs
sudo mv server.key /usr/local/nginx/certs/server.key
sudo mv server.crt /usr/local/nginx/certs/server.crt

sudo cp -a /usr/local/dos-mitigation/common/setup/nginx.service /lib/systemd/system/nginx.service
sudo cp -a /usr/local/dos-mitigation/common/setup/nginx.conf /usr/local/nginx/conf/nginx.conf

sudo systemctl start nginx