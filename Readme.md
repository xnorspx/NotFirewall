# NotFirewall
This is a crutch to help me deploy firewall rules via UFW on multiple machines.

## What this script does?
Fetch UFW rules from the url that you assigned and apply it. It won't interfere with existing rules, so make sures you are ok with the existing rules in UFW.

## Usage
> P.S. Only tested on ubuntu-22.04
1. Ensures `git`, `python3`, `crontab`, and `ufw` is installed on your machine.
```bash
# For debian stream
apt install python3-pip python3-venv git ufw
```
2. Clone this repo to your `root` account's home directory.
```bash
git clone https://github.com/tszykl05/NotFirewall.git /root/NotFirewall
```
3. Create venv and install dependent package.
```bash
cd /root/NotFirewall
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```
4. Ensures `main.py` is owned by `root` and not editable by other users.
```bash
chmod 644 -R /root/NotFirewall/
chown root:root -R /root/NotFirewall/
```
5. Change the `ufw_rule_url` in `main.py` to your rule's url.
6. Add `python3 /root/NotFirewall/main.py` to your crontab with execution frequency you like.

## Rules examples
```
# Tailscale
Interface: tailscale0
# IPv4 - HTTP(S) access from Cloudflare
TCP-80: 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20, 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22
TCP-443: 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20, 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22
# IPv6 - HTTP(S) access from Cloudflare
TCP-80: 2400:cb00::/32, 2606:4700::/32, 2803:f800::/32, 2405:b500::/32, 2405:8100::/32, 2a06:98c0::/29, 2c0f:f248::/32
TCP-443: 2400:cb00::/32, 2606:4700::/32, 2803:f800::/32, 2405:b500::/32, 2405:8100::/32, 2a06:98c0::/29, 2c0f:f248::/32
# Minecraft access from Public
TCP-25565: 0.0.0.0/0
TCP-25565: ::/0
```
```
# Tailscale
Interface: tailscale0
# SAMBA
TCP-445: 192.168.1.0/24
# Proxmox
TCP-8006: 192.168.1.0/24
TCP-8007: 192.168.1.0/24
# Netdata
TCP-19999: 192.168.1.0/24
```
