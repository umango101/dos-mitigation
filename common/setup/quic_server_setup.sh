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

cd
rm -rf nginx-*
wget http://hg.nginx.org/nginx/archive/tip.zip
unzip tip.zip
rm tip.zip
cd nginx-*
./auto/configure --with-debug --with-http_ssl_module --with-http_v2_module  --with-http_v3_module --with-cc-opt="-I../quictls/build/include" --with-ld-opt="-L../quictls/build/lib64"
make
sudo make install
sudo ldconfig ~/quictls/build/lib64
sudo ln -s /usr/local/nginx/sbin/nginx /usr/sbin/nginx