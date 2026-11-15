apt update 
apt install -y build-essential libgtk2.0-dev libpcap-dev libnet1-dev autoconf automake libtool libncurses-dev

./autogen.sh
./configure
make
make install

cp src/yersinia .
echo "Feel free to run sudo ./yersinia -G"