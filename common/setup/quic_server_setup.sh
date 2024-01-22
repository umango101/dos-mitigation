sudo apt update
yes | sudo apt install git libpcre3 libpcre3-dev make python3-certbot-nginx snapd
yes | sudo apt purge nginx nginx-common nginx-core

cd
rm -rf openssl
git clone --depth 1 -b openssl-3.1.4+quic https://github.com/quictls/openssl
cd openssl
mkdir build
./config enable-tls1_3 --prefix=$HOME/quictls/build
make
sudo make install

cd ..
rm -rf nginx-*
wget http://hg.nginx.org/nginx/archive/tip.zip
unzip tip.zip
cd nginx-*
./auto/configure --with-debug --with-http_ssl_module --with-http_v2_module  --with-http_v3_module --with-cc-opt="-I../quictls/build/include" --with-ld-opt="-L../quictls/build/lib64"
make
sudo make install
sudo ldconfig ~/quictls/build/lib64
sudo ln -s /usr/local/nginx/sbin/nginx /usr/sbin/nginx

cd ..
sudo snap install --classic certbot
openssl genrsa -aes256 -passout pass:gsahdg -out server.pass.key 4096
openssl rsa -passin pass:gsahdg -in server.pass.key -out server.key
rm server.pass.key
# common_name=$(/usr/local/dos-mitigation/common/bin/hostname_to_ip $(hostname -s))
openssl req -new -key server.key -out server.csr -subj /CN=${hostname -s}/
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
sudo mkdir -p /usr/local/nginx/certs
sudo mv server.key /usr/local/nginx/certs/server.key
sudo mv server.crt /usr/local/nginx/certs/server.crt

sudo cp -a /usr/local/dos-mitigation/common/setup/nginx.service /lib/systemd/system/nginx.service
sudo cp -a /usr/local/dos-mitigation/common/setup/nginx.conf /usr/local/nginx/conf/nginx.conf

sudo systemctl start nginx