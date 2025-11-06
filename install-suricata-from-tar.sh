# Automatically remove old version
SURICATA_VERSION=suricata-7.0.10
# rm -fr ./$SURICATA_VERSION # Optinonally delete directory
rm -f $SURICATA_VERSION.tar.gz

sudo apt -y install autoconf automake build-essential cargo \
    cbindgen libjansson-dev libpcap-dev libpcre2-dev libtool \
    libyaml-dev make pkg-config rustc zlib1g-dev
wget https://www.openinfosecfoundation.org/download/$SURICATA_VERSION.tar.gz
tar xzvf $SURICATA_VERSION.tar.gz
cd $SURICATA_VERSION
./configure
make
sudo make install
