# Cloud-Server

## Install opaque

install libsodium-dev and pkgconf
download https://github.com/stef/liboprf
cd src
make DESTDIR=/usr
sudo make install DESTDIR=/usr
download https://github.com/stef/libopaque
cd src
make
sudo make install
sudo /sbin/ldconfig -v

### For Debain:

```console
sudo apt update
sudo apt install libsodium-dev pkgconf
wget https://github.com/stef/liboprf/archive/refs/tags/v0.2.0.tar.gz
wget https://github.com/stef/libopaque/archive/refs/tags/v0.99.3.tar.gz
tar -xf v0.2.0.tar.gz
tar -xf v0.99.3.tar.gz
cd liboprf-0.2.0/src
make DESTDIR=/usr
sudo make install DESTDIR=/usr
cd ../../libopaque-0.99.3/src
make
sudo make install
sudo /sbin/ldconfig -v
```

