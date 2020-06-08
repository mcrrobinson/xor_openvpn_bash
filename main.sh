# Install updates.
sudo apt-get update
sudo apt-get upgrade

# Go to root.
sudo su

# Add lines to the file.
cat <<EOF >>/etc/sysctl.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

# Apply changes.
sysctl -p

# Set the ip tables.
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
sudo apt-get install -y iptables-persistent

# Create downloads for the wgets.
mkdir ~/Downloads
cd ~/Downloads

wget https://swupdate.openvpn.org/community/releases/openvpn-2.4.9.tar.gz
tar xvf openvpn-2.4.9.tar.gz

wget https://github.com/Tunnelblick/Tunnelblick/archive/master.zip
sudo apt-get install -y unzip
unzip master.zip

# Copy files to this folder.
cp Tunnelblick-master/third_party/sources/openvpn/openvpn-2.4.9/patches/*.diff openvpn-2.4.9
cd openvpn-2.4.9/

# Apply all patches
patch -p1 < 02-tunnelblick-openvpn_xorpatch-a.diff
patch -p1 < 03-tunnelblick-openvpn_xorpatch-b.diff
patch -p1 < 04-tunnelblick-openvpn_xorpatch-c.diff
patch -p1 < 05-tunnelblick-openvpn_xorpatch-d.diff
patch -p1 < 06-tunnelblick-openvpn_xorpatch-e.diff

# Install prereqs
sudo apt-get install -y build-essential libssl-dev iproute2 liblz4-dev liblzo2-dev libpam0g-dev libpkcs11-helper1-dev libsystemd-dev resolvconf pkg-config

# Build openvpn
./configure --enable-systemd --enable-async-push --enable-iproute2
make
sudo make install

# Create directories, these may already exist.
sudo mkdir /etc/openvpn
sudo mkdir /etc/openvpn/server
sudo mkdir /etc/openvpn/client

cd ~/Downloads

# Download Easy-Rsa.
wget https://github.com/OpenVPN/easy-rsa/archive/v3.0.7.tar.gz
tar -xvzf v3.0.7.tar.gz

# Create easy-rsa directories. There always seems to be a clone...
sudo mkdir -p /usr/share/easy-rsa/3
sudo cp -rf easy-rsa-3.0.7/* /usr/share/easy-rsa/3
sudo cp -rf easy-rsa-3.0.7/* /usr/share/easy-rsa/3/easyrsa3

# Make the example the real file.
cd /usr/share/easy-rsa/3/easyrsa3
sudo cp vars.example vars

# Add lines to the file.
cat <<EOF >> vars
set_var EASYRSA_DN "org"
set_var EASYRSA_REQ_COUNTRY "CN"
set_var EASYRSA_REQ_PROVINCE "Guangdong"
set_var EASYRSA_REQ_CITY "Shenzhen"
set_var EASYRSA_REQ_ORG "Test Org"
set_var EASYRSA_REQ_EMAIL "test@example.com"
EOF

# Generate easyrsa.
./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa gen-req 34.34.34.34 nopass
./easyrsa sign-req server 34.34.34.34
./easyrsa gen-req adminpc nopass
./easyrsa sign-req client adminpc
./easyrsa gen-dh

# Copy pki files to the opencpn server and client.
cp pki/ca.crt /etc/openvpn
cp pki/dh.pem /etc/openvpn/server
cp pki/issued/34.34.34.34.crt /etc/openvpn/server
cp pki/issued/adminpc.crt /etc/openvpn/client
cp pki/private/ca.key /etc/openvpn
cp pki/private/34.34.34.34.key /etc/openvpn/server
cp pki/private/adminpc.key /etc/openvpn/client

# Generate encryption key.
cd /etc/openvpn
openvpn --genkey --secret tls-crypt.key

# Give read permissions.
chmod +r ca.crt
chmod +r client/adminpc.crt
chmod +r client/adminpc.key
chmod +r tls-crypt.key

# Create hash.
cd /etc/openvpn
openssh_hash=$(openssl rand -base64 24)

# Add scrable hash to the server configuration file.
cat << EOF > server/34.34.34.34.conf
port 443
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server/34.34.34.34.crt
key /etc/openvpn/server/34.34.34.34.key
dh /etc/openvpn/server/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 10 120
cipher AES-256-GCM
tls-crypt /etc/openvpn/tls-crypt.key
persist-key
persist-tun
status openvpn-status.log
verb 3
scramble obfuscate $openssh_hash
EOF

# Copy files from the downloads to the service.
sudo cp ~/Downloads/openvpn-2.4.9/distro/systemd/openvpn-server@.service.in /lib/systemd/system/openvpn-server@.service

# Overwrite current service file to have the actual execstart directory.
cat << EOF > /lib/systemd/system/openvpn-server@.service
[Unit]
Description=OpenVPN service for %I
After=syslog.target network-online.target
Wants=network-online.target
Documentation=man:openvpn(8)
Documentation=https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
Documentation=https://community.openvpn.net/openvpn/wiki/HOWTO

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn/server
ExecStart=/usr/local/sbin/openvpn --status %t/openvpn-server/status-%i.log --status-version 2 --suppress-timestamps --confi>
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SYS_CHROO>
LimitNPROC=10
DeviceAllow=/dev/null rw
DeviceAllow=/dev/net/tun rw
ProtectSystem=true
ProtectHome=true
KillMode=process
RestartSec=5s
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Start service.
sudo systemctl start openvpn-server@34.34.34.34
sudo systemctl enable openvpn-server@34.34.34.34
sudo systemctl status openvpn-server@34.34.34.34

# Show conncetions.
sudo ss -tulpn | grep 443

exit