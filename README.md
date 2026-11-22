# Home Command

A single web page for a home network: who is touching your public domains, what the gateway turned away,
what every device (especially smart-home devices) talks to, which sites the household looks up, internet
speed and usage, plus alerts you can act on: ban an address, block a device, block a country.

It is one small Python program with a built-in database. No Grafana, Prometheus or log stack.

## What it works with

| Piece | Supported | Needed? |
|---|---|---|
| Gateway | UniFi gateways running UniFi Network 9 or 10 (UDM, UDM Pro, UCG, UXG with a controller) | Yes |
| Reverse proxy | Nginx Proxy Manager, Traefik, Caddy, plain nginx/Apache | Optional |
| DNS filter | AdGuard Home, Pi-hole 6+ | Optional |
| Attack blocking | CrowdSec (with a firewall bouncer on the proxy machine) | Optional |
| Packet-level detail | NetFlow from the gateway into an Elasticsearch server you provide | Optional |

Other gateways (pfSense, OPNsense, MikroTik) are not supported.

## Install

Pick one. Both end with a web page on port 3000 that walks you through the rest.

### Docker

    docker compose up -d

The compose file uses host networking so the portal sees real source addresses. Data is kept in the Docker volume `homecommand-data`.

### Debian or Ubuntu, as a system service

    sudo ./install.sh

Installs to `/opt/homecommand`, keeps data in `/var/lib/homecommand`, and runs as its own unprivileged user.

## First run

Open `http://THE-MACHINE:3000`. You are asked to choose the portal's password, then the walkthrough
connects, in order: the UniFi gateway, your home's networks, the reverse proxy, the DNS filter,
CrowdSec, and the gateway's log and NetFlow feeds. Every step can be skipped and revisited from Settings.

Do this from inside your home network, and do it straight away: until a password is chosen, whoever
opens the page first sets it.

## Ports

| Port | Use |
|---|---|
| 3000/tcp | Web page, and where log shippers deliver |
| 5514/udp | Gateway log (set as the syslog/SIEM server in UniFi) |
| 2055/udp | NetFlow/IPFIX from the gateway (only if you use it) |

## Reaching it from outside your home

Put it behind your reverse proxy with HTTPS and, ideally, a single sign-on provider (authentik, Authelia,
Tinyauth, oauth2-proxy, Cloudflare Access). The Connections page explains how the portal trusts the
provider's sign-in. Do not forward port 3000 to the internet directly: it is plain HTTP.

## Where things are stored

Everything is in the data folder (`/var/lib/homecommand`, or the `homecommand-data` volume under Docker): `portal.db` (records), `settings.json`, `connections.json` and
`unifi-auth.json` (logins for the things it connects to, readable only by the portal's user), and the
country databases. Back up that folder; delete it to start again.

## Updating

Replace the program files and restart: `docker compose up -d --build`, or run `install.sh` again.

## Known limits

- The web page is plain HTTP on your home network.
- All log shippers share one feed password (shown in the install commands on the Connections page).
- Logins for connected systems are stored unencrypted in the data folder, protected by file permissions.
- The Elasticsearch connection does not verify the server's certificate.
- Reading AdGuard Home and Pi-hole over their web addresses, and the Traefik, Caddy and nginx log
  readers, were written from those products' documentation and have had little real-world use.

## Credits

Country and network-owner lookups use the free DB-IP Lite databases: IP Geolocation by DB-IP
(https://db-ip.com), CC BY 4.0. The portal downloads and refreshes them itself.
