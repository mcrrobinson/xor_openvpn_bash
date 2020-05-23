# Get the latest packages.
sudo apt-get -y update
sudo apt-get -y upgrade

# This will be static later on.
open_server_ip=34.34.34.34

# Append the following to the system file.
cat <<EOF >>/etc/sysctl.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

# Restart sysctl in order for the changes to take effect.
sudo sysctl -p

# Adjust IP tables to allow forwarding.
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
sudo apt-get install -y build-essential openssl libssl-dev iproute2 liblz4-dev liblzo2-dev libpam0g-dev libpkcs11-helper1-dev libsystemd-dev resolvconf pkg-config unzip cmake iptables-persistent

# Create a temporary directory for installation media.
mkdir ~/Installation
cd ~/Installation

# Install targz release of openvpn, this can be modular in the future.
wget https://swupdate.openvpn.org/community/releases/openvpn-2.4.8.tar.gz
tar xvf openvpn-2.4.8.tar.gz

# Get the Tunnelblick files for the patch.
wget https://github.com/Tunnelblick/Tunnelblick/archive/master.zip

# In order to unzip the file install unzip
unzip master.zip

# Copy all files from this colder to openvpn directory.
cp Tunnelblick-master/third_party/sources/openvpn/openvpn-2.4.8/patches/*.diff openvpn-2.4.8
cd openvpn-2.4.8

# Apply the patches with the patch command.
patch -p1 < 02-tunnelblick-openvpn_xorpatch-a.diff
patch -p1 < 03-tunnelblick-openvpn_xorpatch-b.diff
patch -p1 < 04-tunnelblick-openvpn_xorpatch-c.diff
patch -p1 < 05-tunnelblick-openvpn_xorpatch-d.diff
patch -p1 < 06-tunnelblick-openvpn_xorpatch-e.diff

# Configure IP tables.
./configure --enable-systemd --enable-async-push --enable-iproute2

# Incomplete, no make medium yet.
make

sudo make install
sudo mkdir /etc/openvpn
sudo mkdir /etc/openvpn/server
sudo mkdir /etc/openvpn/client

# Navigate back to the installation media folder.
cd ~/Installation

# Download the release of EasyRSA for security purposes when connecting the VPN
wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.5/EasyRSA-nix-3.0.5.tgz
tar -xvzf EasyRSA-nix-3.0.5.tgz

# Create a temporary directory in order to setup easy rsa.
sudo mkdir -p /usr/share/easy-rsa/3

# Copy the folders from the extracted tar and copy them over to the created directory.
sudo cp -rf EasyRSA-3.0.5/* /usr/share/easy-rsa/3
cd /usr/share/easy-rsa/3

# Sets a baseline for the vars example.
sudo cp vars.example vars

# Adds the user input to the variables to interact with EasyRSA
# In fairness these variables are not checked against and can be random.
# There is no email verification included.
echo "Country Input:"
read easy_rsa_country
echo "Province Input: "
read easy_rsa_province
echo "City Input: "
read easy_rsa_city
echo "Organisation Input: "
read easy_rsa_organisation
echo "Email Input: "
read easy_rsa_email
echo "Organisation Unit (Useless) Input: "
read easy_rsa_ou

# Set the EasyRSA variables
cat <<EOF >> vars
set_var EASYRSA_REQ_COUNTRY     "$easy_rsa_country"
set_var EASYRSA_REQ_PROVINCE    "$easy_rsa_province" 
set_var EASYRSA_REQ_CITY        "$easy_rsa_city"
set_var EASYRSA_REQ_ORG         "$easy_rsa_organisation"
set_var EASYRSA_REQ_EMAIL       "$easy_rsa_email"
set_var EASYRSA_REQ_OU          "$easy_rsa_ou"
EOF

# Next to create the certificates and keys. This may require changing to root.
cd /usr/share/easy-rsa/3

# Now to create the public key.
sudo ./easyrsa init-pki
sudo ./easyrsa build-ca nopass

# This IP can be changed later on. Additionally this may require user interaction.
sudo ./easyrsa gen-req $open_server_ip
sudo ./easyrsa gen-req adminpc nopass
sudo ./easyrsa sign-req client adminpc
sudo ./easyrsa gen-dh

# Required to copy the keys into the OpenVPN directories.
sudo cp pki/ca.crt /etc/openvpn
sudo cp pki/dh.pem /etc/openvpn/server
sudo cp pki/issued/$open_server_ip.crt /etc/openvpn/server
sudo cp pki/issued/adminpc.crt /etc/openvpn/client
sudo cp pki/private/ca.key /etc/openvpn
sudo cp pki/private/$open_server_ip.key /etc/openvpn/server
sudo cp pki/private/adminpc.key /etc/openvpn/client

# Generate the TLS crypt key.
cd /etc/openvpn
sudo openvpn --genkey --secret tls-crypt.key

# Need to set permissions to be read only so that a non root user cannot modify files.
sudo chmod +r ca.crt
sudo chmod +r client/adminpc.crt
sudo chmod +r client/adminpc.key
sudo chmod +r tls-crypt.key
cd /etc/openvpn

# This should be installed on boot but just in case install in the script.
# The result of the openSSL should be a hash in base64.
openssh_hash=openssl rand -base64 24

# Not familiar with the cat syntax, hopefully this should pull the variable in.
# The port is currently 443, not sure why this is the case in the example I pulled.
# I can understand it if it was a TCP connection but it's under UDP ...
# Maybe change later on.
cat <<EOF >> server/$open_server_ip.conf
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

# Next to run on SystemD so it has persistence.
sudo cp ~/Installation/openvpn-2.4.8/distro/systemd/openvpn-server@.service.in /lib/systemd/system/openvpn-server@.server

# Not complete yet.

# Change sbindir to /usr/local/sbin
# cat << EOF >>/lib/systemd/system/openvpn-server@.service
# EOF

# # Start openVPN server
# sudo systemctl start openvpn-server@$open_server_ip
# sudo systemctl enable openvpn-server@$open_server_ip
# sudo systemctl status openvpn-server@$open_server_ip
# sudo ss -tulpn | grep 443

# # Indicate that the setup is finally complete.
# echo "[Success] Setup is finally complete."