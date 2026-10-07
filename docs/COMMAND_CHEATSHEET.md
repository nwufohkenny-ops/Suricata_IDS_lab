# Suricata IDS Lab — Command Cheat Sheet

> Replace `<SURICATA_IP>`, `<CLIENT_IP>`, and `<INTERFACE>`.

## Install

```bash
sudo apt update
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata jq netcat-openbsd
suricata --build-info
```

## Identify network settings

```bash
ip -br addr
ip route
ip -br addr | grep '<SURICATA_IP>'
```

## Validate configuration

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

## Run IDS in foreground

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i <INTERFACE>
```

## Service mode

```bash
sudo systemctl restart suricata
sudo systemctl status suricata --no-pager
```

## Listener

```bash
sudo nc -lvnp 9999
sudo ss -lntp | grep ':9999'
```

## Generate traffic

```bash
printf 'SURICATA-LAB-TEST\n' | nc -nv -w 3 <SURICATA_IP> 9999
```

or:

```bash
./scripts/generate_traffic.sh <SURICATA_IP>
```

## Observe packets

```bash
sudo tcpdump -ni <INTERFACE> tcp port 9999
sudo tcpdump -ni <INTERFACE> -A tcp port 9999
```

## fast.log

```bash
sudo tail -n 20 /var/log/suricata/fast.log
sudo grep -i "LOCAL LAB Netcat" /var/log/suricata/fast.log
```

## EVE JSON

```bash
sudo grep '"event_type":"alert"' /var/log/suricata/eve.json | tail
sudo grep '"signature_id":1000001' /var/log/suricata/eve.json
sudo jq 'select(.event_type=="alert")' /var/log/suricata/eve.json | tail -n 1
```

## SOC-style extraction

```bash
sudo jq -r '
select(.event_type=="alert") |
[.timestamp,.src_ip,.src_port,.dest_ip,.dest_port,.proto,
 .alert.signature,.alert.severity,.alert.signature_id] | @tsv
' /var/log/suricata/eve.json | tail -n 10
```

## Troubleshooting

```bash
ping -c 3 <SURICATA_IP>
ip route
sudo ss -lntp | grep ':9999'
pgrep -a suricata
sudo grep -n "local.rules" /etc/suricata/suricata.yaml
sudo suricata -T -c /etc/suricata/suricata.yaml
```
