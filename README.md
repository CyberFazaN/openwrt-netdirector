# openwrt-netdirector

`openwrt-netdirector` is a POSIX shell utility for OpenWrt that configures `fw4` / `nftables` rules for transparent traffic redirection on a LAN.

It is intended for lab and analysis environments where traffic from client devices needs to be sent through a dedicated inspection host without changing proxy settings on the clients themselves.

## What it is useful for

- redirect HTTP and HTTPS traffic to a transparent proxy
- force DNS traffic to a dedicated DNS server[^dns]
- block QUIC (`UDP/443`) to reduce HTTPS bypass paths
- optionally block IPv6 when inspection is performed only over IPv4
- apply rules to all clients or only selected hosts
- save repeatable configurations as profiles

[^dns]: DNS interception is disabled by default and must be enabled explicitly with `--dns on`.

It is especially useful for devices on which it is difficult or impossible to configure traffic proxying, such as IoT devices, mobile apps, embedded systems, and closed appliances.

Repository:  
https://github.com/CyberFazaN/openwrt-netdirector

## How it works

The script generates a managed `fw4` include file at:

```
/etc/nftables.d/90-netdirector.nft
```

The rules are loaded into:

```
table inet fw4
```

## Features

- POSIX shell implementation
- OpenWrt `fw4` / `nftables` integration
- transparent HTTP/HTTPS redirection
- forced DNS redirection
- optional QUIC and IPv6 blocking
- interface-based filtering
- client-specific filtering
- reusable profiles

## Requirements

- OpenWrt with `fw4`
- `nftables`
- root access
- dedicated LAN host for proxy and/or DNS inspection

Required utilities:

```
fw4 nft mktemp grep sed sort uniq mv rm cat mkdir id tr basename dirname
```

## CLI Reference

```
Commands:
  on                     Generate rules, write managed file, and reload fw4
  off                    Remove managed rules and reload fw4
  status                 Show managed file and runtime chain status
  print                  Print generated nftables fragment to stdout
  check                  Validate configuration without applying it
  save-profile <name>    Save effective configuration as a profile
  load-profile <name>    Load a profile and apply it
  list-profiles          List available profiles
  delete-profile <name>  Delete a profile
  show-profile <name>    Show raw profile contents
  help                   Show help

Options:
  --profile <name>           Load profile before applying CLI overrides
  --intercept-ip <ipv4>      Interception host IPv4 address
  --intercept-port <port>    Interception host port
  --dns-ip <ipv4>            DNS server IPv4 address
  --dns-port <port>          DNS server port
  --iface <ifname>           Interface to match, may be used multiple times
  --client <ipv4>            Client IPv4 to match, may be used multiple times
  --http on|off              Enable or disable HTTP interception
  --https on|off             Enable or disable HTTPS interception
  --dns on|off               Enable or disable DNS interception
  --quic ignore|block        UDP/443 handling mode
  --ipv6 ignore|block        IPv6 handling mode
  --verbose                  Enable verbose output
  -h, --help                 Show help
  --version                  Show version
```

## Basic usage

Enable redirection for all clients:

```
netdirector on \
  --intercept-ip 192.168.30.2 \
  --intercept-port 8080 \
  --dns on \
  --dns-ip 192.168.30.2 \
  --dns-port 53 \
  --iface br-lan \
  --quic block \
  --ipv6 block
```

Enable redirection for one client only:

```
netdirector on \
  --intercept-ip 192.168.30.2 \
  --intercept-port 8080 \
  --dns on \
  --dns-ip 192.168.30.2 \
  --dns-port 53 \
  --iface br-lan \
  --client 192.168.30.101
```

Disable rules:

```
netdirector off
```

Show current status:

```
netdirector status --verbose
```

## Profiles

Profiles store a base configuration so it can be reused without repeating the full command line every time.

Typical profile contents:

- intercept host IP/Port
- DNS server IP/Port
- interface
- default flags

Save a profile from an explicit configuration:

```
netdirector save-profile lab \
  --intercept-ip 192.168.30.2 \
  --intercept-port 8080 \
  --dns on \
  --dns-ip 192.168.30.2 \
  --dns-port 53 \
  --iface br-lan \
  --quic block
```

Load a saved profile:

```
netdirector load-profile lab
```

Load a profile and override selected options, for example target clients:

```
netdirector load-profile lab \
  --client 192.168.30.101
```

Profiles are stored in:

```
/etc/netdirector/profiles
```

## Validation

The `check` command validates configuration before applying rules. This includes:

- IPv4 format
- port ranges
- interface names
- option consistency
- rule generation

It does not modify the active firewall configuration.

## Important notes

#### Transparent proxy support is required

This tool does not make a SOCKS5 proxy transparently intercept HTTP or HTTPS traffic.

If traffic on TCP/80 or TCP/443 is redirected to a plain SOCKS5 listener, it will not work. The target service must support transparent interception or otherwise be able to handle redirected traffic correctly.

#### HTTPS interception requires trust on the client

To inspect HTTPS, the proxy CA certificate usually must be installed on the client device. Without that, TLS validation will fail and most applications will reject the connection.

Some applications disable certificate validation internally. In those cases, HTTPS may still be observable, but that behavior depends entirely on the client.

#### DNS redirection in the same LAN

When DNS is redirected to a server in the same LAN, postrouting masquerade is required so replies return correctly.

In this setup, DNS redirection is reliable, but the DNS server will usually see the router IP instead of the original client IP.

If you need the real client IP at the DNS server, place the DNS server in another subnet/VLAN or distribute it through DHCP instead of forced redirect.

## Typical lab setup

Example:

```
inspection host: 192.168.30.2
proxy port: 8080
dns port: 53
openwrt lan: br-lan
```

Confirmed working inspection tools:

- Reqable
- Technitium DNS Server

Other transparent inspection proxies and DNS services may also work if they support the required mode of operation.

## What this script does not do

- generic SOCKS5 transparent tunneling
- MAC filtering
- VLAN filtering
- domain routing
- IPv6 interception
- packet logging
- DPI

The script intentionally focuses on a small controlled use case.

## Safety

Use only in networks where you are authorized to inspect traffic.

Transparent interception changes traffic behavior for clients.

## Author

[CyberFazaN](https://github.com/CyberFazaN)