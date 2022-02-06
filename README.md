# wakeonlan
Simple Wake-on-LAN utility

## Usage
```bash
wakeonlan aa:bb:cc:dd:ee:ff

# or specify interface
wakeonlan -i eth0 aa:bb:cc:dd:ee:ff
```

## Building on ARM
```bash
apt-get install gcc-arm-linux-gnueabi byacc flex libpcap-dev

pushd /tmp
export PCAPV=1.8.1
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar xvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
export CC=arm-linux-gnueabi-gcc
./configure --host=arm-linux --with-pcap=linux
make
popd

CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 CGO_LDFLAGS="-L/tmp/libpcap-$PCAPV -static" GOOS=linux GOARCH=arm go build .
```
