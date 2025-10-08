sudo apt-install tcptraceroute

sudo apt-get install libpcap-dev

curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | \
  sudo gpg --dearmor -o /etc/apt/keyrings/ngrok.gpg && \
  echo "deb [signed-by=/etc/apt/keyrings/ngrok.gpg] https://ngrok-agent.s3.amazonaws.com buster main" | \
  sudo tee /etc/apt/sources.list.d/ngrok.list && \
sudo apt update && sudo apt install ngrok
ngrok config add-authtoken 2mMC3VPnQwGgg8TIn6PZ7uIb6TN_28RN6VaNDHGYrKfajwQVY

wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb
# ./cloudflared-linux-amd64 tunnel login
# ./cloudflared-linux-amd64 tunnel run sanchaar

curl -O https://pagekite.net/pk/pagekite.py

curl https://get.telebit.io/ | bash

sudo apt install cargo
cargo install bore-cli

npm install -g localtunnel

pnpm install loclx

sudo apt install composer
composer global require beyondcode/expose
# add expose to .bashrc
expose token 64fe28db-1ac6-4f4c-9115-82d6c473a5bd

wget https://github.com/loophole/cli/releases/download/1.0.0-beta.15/loophole-cli_1.0.0-beta.15_linux_64bit.tar.gz
tar -xvf loophole-cli_1.0.0-beta.15_linux_64bit.tar.gz
mv ./loophole-cli_1.0.0-beta.15_linux_64bit/loophole .
chmod +x loophole
# ./loophole account login
# auth

curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list
sudo apt-get update
sudo apt-get install tailscale
# sudo tailscale up

sudo apt install wireguard-tools
curl https://tunnel.pyjam.as/3000 > tunnel.conf

curl -sSLfo ./zrok-install.bash https://get.openziti.io/install.bash
sudo apt install zrok

sudo apt  install golang-go
wget https://github.com/ntnj/tunwg/releases/latest/download/tunwg
chmod +x tunwg

wget https://github.com/jkuri/bore/releases/download/v0.4.2/bore-server_linux_amd64 o bore-digital
chmod +x bore-digital

wget https://download.packetriot.com/linux/debian/buster/stable/non-free/binary-amd64/pktriot-0.15.1.amd64.deb
sudo dpkg -i pktriot-0.15.1.amd64.deb
# Tunnel configuration:
#   Hostname: old-sound-23918.pktriot.net
#   Server: asia-south-36774.packetriot.net
#   IPv4: 139.59.36.70
#   IPv6: 2400:6180:100:d0::9c9:b001

wget https://openport.io/static/releases/openport_2.2.2-1_amd64.deb
sudo dpkg -i openport_2.2.2-1_amd64.deb

wget https://launchpadlibrarian.net/19452503/paris-traceroute_0.92-dev-2_amd64.deb
sudo dpkg -i paris-traceroute_0.92-dev-2_amd64.deb

wget https://openport.io/download/debian64/latest.deb
sudo dpkg -i latest.deb

curl -sL https://aka.ms/DevTunnelCliInstall | bash
devtunnel user login

onionpipe
ephemeral
ngtor
# openport
# playit

wget https://github.com/raaz714/btunnel-releases/releases/latest/download/bored-tunnel-client_Linux_x86_64.tar.gz
tar -xvf bored-tunnel-client_Linux_x86_64.tar.gz

R3_REGISTRATION_CODE="C6AAE201-29E3-556C-A830-E614C6BCCCB6" sh -c "$(curl -L https://downloads.remote.it/remoteit/install_agent.sh)"

cargo install onionpipe
