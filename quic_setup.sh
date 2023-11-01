apt update
apt install libpcre3 libpcre3-dev

git clone https://github.com/quictls/openssl
wget http://hg.nginx.org/nginx/archive/default.zip
unzip default.zip
cd ~/nginx-default
./auto/configure --with-debug --with-http_v3_module --with-cc-opt="-I../quictls/build/include" --with-ld-opt="-L../quictls/build/lib"
make