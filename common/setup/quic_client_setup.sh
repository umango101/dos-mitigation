sudo apt update
yes | sudo apt install autoconf git libtool make pkg-config libpsl-dev

cd
rf -rf openssl
git clone --depth 1 -b openssl-3.1.4+quic https://github.com/quictls/openssl
cd openssl
mkdir build
./config enable-tls1_3 --prefix=$HOME/openssl/build
make
sudo make install

cd ..
rf -rf nghttp3
git clone -b v1.0.0 https://github.com/ngtcp2/nghttp3
cd nghttp3
autoreconf -fi
mkdir build
./configure --prefix=$HOME/nghttp3/build --enable-lib-only
make
sudo make install

cd ..
rm -rf ngtcp2
git clone -b v1.0.1 https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -fiß
mkdir build
./configure PKG_CONFIG_PATH=$HOME/openssl/build/lib64/pkgconfig:$HOME/ßnghttp3/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$HOME/openssl/build/lib64" --prefix=$HOME/ngtcp2/build --enable-lib-only
make
sudo make install

cd ..
rm -rf curl
git clone https://github.com/curl/curl
cd curl
autoreconf -fi
LDFLAGS="-Wl,-rpath,$HOME/openssl/build/lib64" ./configure --with-openssl=$HOME/openssl/build --with-nghttp3=$HOME/nghttp3/build --with-ngtcp2=$HOME/ngtcp2/build
make
sudo make install

sudo ldconfig

# cd
# curl --http3-only https://cloudflare-quic.com -o quic-test.html