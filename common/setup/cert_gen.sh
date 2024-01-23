#!/bin/bash

cd
sudo snap install --classic certbot
openssl genrsa -aes256 -passout pass:gsahdg -out server.pass.key 4096
openssl rsa -passin pass:gsahdg -in server.pass.key -out server.key
rm server.pass.key
server_ip=$(/usr/local/dos-mitigation/common/bin/hostname_to_ip $(hostname -s))
openssl req -new -key server.key -out server.csr -subj /CN=${server_ip}/
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
openssl x509 -in server.crt -out server.pem -outform PEM
sudo mkdir -p /usr/local/nginx/certs
sudo mv server.key /usr/local/nginx/certs/server.key
sudo mv server.crt /usr/local/nginx/certs/server.crt
sudo mv server.pem /usr/local/nginx/certs/server.pem

sudo cp -a /usr/local/dos-mitigation/common/setup/nginx.service /lib/systemd/system/nginx.service
sudo cp -a /usr/local/dos-mitigation/common/setup/nginx.conf /usr/local/nginx/conf/nginx.conf

sudo systemctl restart nginx