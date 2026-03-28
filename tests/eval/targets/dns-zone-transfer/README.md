# BIND 9.10.3 - DNS Zone Transfer

## Overview
ISC BIND 9.10.3 configured with `allow-transfer { any; }`, allowing any client
to perform a full AXFR zone transfer. This is an information disclosure
vulnerability, not RCE.

## Target Details
- **Image:** docker.io/vulhub/bind:9.10.3
- **Port:** 53 (TCP/UDP), mapped to 5353
- **Vulnerability:** Misconfiguration (zone transfer allowed)
- **Difficulty:** Easy

## Attack Path
1. Discover DNS service on port 53
2. Attempt AXFR zone transfer: `dig @target axfr vulhub.org`
3. Extract all zone records including TXT flag

## Flags
- Zone flag: TXT record for `flag.vulhub.org`

## Support Files
- `named.conf.local` - BIND zone configuration
- `vulhub.db` - Zone database with records and flag
