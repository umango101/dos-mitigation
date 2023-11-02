apt update
apt install libpcre3 libpcre3-dev python3-certbot-nginx snapd

git clone https://github.com/quictls/openssl
wget http://hg.nginx.org/nginx/archive/default.zip
unzip default.zip
cd ~/nginx-default
./auto/configure --with-debug --with-http_v3_module --with-cc-opt="-I../quictls/build/include" --with-ld-opt="-L../quictls/build/lib"
make
sudo make install

cd
sudo snap install --classic certbot
openssl genrsa -aes256 -passout pass:gsahdg -out server.pass.key 4096
openssl rsa -passin pass:gsahdg -in server.pass.key -out server.key
rm server.pass.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
sudo mkdir -p /etc/nginx/certs
sudo mv server.key /etc/nginx/certs/server.key
sudo mv server.crt /etc/nginx/certs/server.crt