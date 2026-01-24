# Gluetun VPN Configuration

This directory contains the gluetun VPN configuration for routing traffic through the HackTheBox VPN.

## Overview

Gluetun provides a containerized VPN client that other containers (like hexstrike-recon) use via `network_mode: "service:gluetun"` to route their traffic through the HTB VPN tunnel.

## Configuration Decisions

### Health Check Configuration

**Problem:** Gluetun's default health checks try to reach external hosts (cloudflare.com, github.com) via TCP+TLS. Within the HTB VPN network, these hosts aren't directly reachable, causing health check failures and VPN restarts.

**Solution (PoC):**
```yaml
# Allow DNS outside VPN for health checks
FIREWALL_OUTBOUND_SUBNETS: 172.19.0.0/16,172.17.0.0/16,1.1.1.1/32

# Disable built-in DNS server, use host DNS
DNS_SERVER: off
DNS_KEEP_NAMESERVER: on

# Health check targets (VPN server for TCP, gateway for ICMP)
HEALTH_TARGET_ADDRESSES: 38.46.226.72:1337
HEALTH_ICMP_TARGET_IPS: 10.10.14.1

# Don't restart VPN on health check failures
HEALTH_RESTART_VPN: off
```

### DNS Leak Warning

The current configuration intentionally allows DNS traffic (to 1.1.1.1) outside the VPN tunnel. This is acceptable for the PoC because:

1. This is an offensive security tool, not a privacy-focused setup
2. DNS queries to resolve HTB machine hostnames don't need to be hidden
3. The VPN is for accessing HTB's internal network, not for anonymity

**Warning in logs (expected):**
```
WARN [dns] keeping the default container nameservers, this will likely leak DNS traffic outside the VPN
```

## Future Improvements

> **TODO:** Clean up DNS leak for production use

For a production deployment, consider:

1. **Internal DNS Server:** Set up a DNS server within the HTB network (if available) and configure gluetun to use it
2. **DNS over VPN:** Configure gluetun to route DNS through the VPN tunnel by:
   - Finding DNS servers accessible within HTB network
   - Using `DNS_SERVER=on` with proper upstream configuration
3. **Custom Health Checks:** Identify TCP services within HTB network that can serve as health check targets

## Files

- `htb.ovpn` - HackTheBox OpenVPN configuration file
- `servers.json` - Gluetun server cache (auto-generated)

## Related Documentation

- [Gluetun Wiki - Health Check](https://github.com/qdm12/gluetun-wiki/blob/main/faq/healthcheck.md)
- [Gluetun Wiki - DNS Options](https://github.com/qdm12/gluetun-wiki/blob/main/setup/options/dns.md)
