<p align="center"><img src="web/mark.svg" width="64" alt="QuietDNS"></p>
<h1 align="center">QuietDNS</h1>
<p align="center">A quieter internet, managed from your own network.</p>

QuietDNS is a self-hosted DNS blocker with a small Go service, an embedded browser dashboard, and a guided first-run setup. Built for a 64-bit Raspberry Pi running Linux, with Docker Engine and Compose.

**Status: development preview.** The original DNS prototype was verified on a Debian 13 ARM64 Pi over UDP and TCP, including queries from another LAN device. This expanded version adds a new application backend and UI; its Go tests and container build still need to pass in CI or on the Pi before it should replace that prototype. It is not yet a production-equivalent replacement for Pi-hole.

## What’s included

- DNS forwarding over UDP and TCP, upstream failover, and TCP retry after truncated UDP responses.
- Domain and subdomain blocking, allowlist overrides, and checks for blocked CNAME targets.
- Responsive dashboard with a 24-hour activity chart, query search, status filters, recent clients, and top blocked domains.
- Immediate allow/block rule changes and five-minute protection pausing with automatic expiry.
- HaGeZi Light and Normal blocklists, daily updates, manual refresh, and last-working-copy retention after failed downloads.
- First-run wizard, an installation key, password hashing, expiring admin sessions, and request-origin checks.
- Persistent settings, bounded query history, logging opt-out, and history clearing.
- Docker installation, GitHub Actions checks, and ARM64/AMD64 release-artifact builds.

The UI uses local HTML, CSS and JavaScript. There is no frontend build step, external font request, analytics SDK or cloud account. Node and Playwright are only needed for development tests.

## Install

Requirements: Linux, Docker Engine with Compose, a LAN IPv4 address, and free ports **53 TCP/UDP** and **8081 TCP**. The installer checks Docker and port conflicts; it does not install system packages, stop other services, or change your router.

Download the source archive or clone this repository, enter its directory, then run:

```bash
bash install.sh
```

The script detects a candidate LAN address, lets you confirm it, creates `.env` with a random installation key, builds and starts the container, and prints the dashboard URL. Open that URL to:

1. Name your network and create an administrator password.
2. Choose your initial blocklist.
3. Connect one test device and check its activity.

If you already have a DNS server on port 53, install a parallel trial:

```bash
DNS_PORT=1053 HTTP_PORT=8081 bash install.sh
```

Standard device DNS settings cannot specify a custom port. Move to port 53 after testing. See [upgrading from the prototype](docs/UPGRADING.md).

Docker’s dashboard is not required. Use Docker Engine on the Pi and access QuietDNS from your browser.

## Verify DNS

Install `dnsutils` on Debian if `dig` is missing. Replace `PI_IP` with the address printed by the installer, and use `-p 1053` if testing on the trial port.

```bash
dig @PI_IP example.com A
dig @PI_IP example.com A +tcp
dig @PI_IP blocked.test A
dig @PI_IP child.blocked.test AAAA +tcp
```

The first two must return `NOERROR` and IP answers. The final two must return `NXDOMAIN`. The test domain `blocked.test` is built in; an allow rule or a protection pause can intentionally override it. An upstream’s genuine NXDOMAIN is labelled “Not found” in the log, not counted as a block.

Repeat a query from another LAN device to confirm the published port is reachable. The dashboard’s connection check exercises the resolver and upstreams internally; it does not prove another device can access the Pi.

Reserve the Pi’s IP address in DHCP before configuring a whole network. Another configured DNS server, IPv6 DNS advertisements, or browser encrypted DNS can bypass the blocker. The default Compose file publishes on the selected IPv4 address only. DNS filtering cannot remove advertisements served from the same domain as wanted content.

## Administration

```bash
docker compose ps
docker compose logs --tail=50
docker compose restart
```

Settings, cached lists and query history live in the `quietdns_data` Docker volume. The container runs without root, with a read-only filesystem and dropped Linux capabilities. `GOMEMLIMIT` is a soft Go runtime target, not a hard process limit, so it also works on Pis without memory cgroup support.

Defaults send allowed queries to Cloudflare (`1.1.1.1:53`), with Quad9 (`9.9.9.9:53`) as fallback. Change these in Settings. They use ordinary DNS; this version does not provide encrypted upstream DNS or independently validate DNSSEC.

Query history contains domains and client IPs. At most 2,000 recent queries and 24 hours of five-minute aggregate buckets are kept. Snapshots are written every 30 seconds and at orderly shutdown; a crash can lose the latest interval. Top domains and client counts use retained queries; headline totals use aggregate buckets. Logging opt-out stops both and clears existing data.

### Password reset

Run this from the installation directory on your Pi:

```bash
docker compose stop quietdns
docker compose run --rm --no-deps quietdns reset-password
docker compose up -d
```

Reopen the dashboard and use the installation key from `.env`. This is a local administrator recovery operation. It invalidates current sessions on restart; it does not delete rules or history. Keep `.env` private.

### Backup

Follow [backup, migration and rollback](docs/UPGRADING.md). Do not use `docker compose down -v` unless you intend to remove the data volume.

## Development

Go 1.26 or later:

```bash
go mod tidy
go test -race ./...
go vet ./...
go run .
```

Local defaults: DNS `:1053`, dashboard `:8080`, data `./data`. A first-run installation key is printed if none was supplied. Use a private IP address or `localhost` to access the dashboard; arbitrary Host headers are rejected as a DNS-rebinding precaution.

Environment variables: `DATA_DIR`, `DNS_ADDR`, `HTTP_ADDR`, `SETUP_TOKEN`, `BIND_IP`, and optionally `GOMEMLIMIT`. Docker port mapping variables `DNS_PORT` and `HTTP_PORT` belong in `.env`.

UI checks (Node 24):

```bash
npm install --ignore-scripts
npm test
npx playwright install chromium
npm run test:browser
```

Browser tests use an explicitly labelled in-memory API fixture. Backend behavior is covered separately by the Go tests. See [validation status](docs/VALIDATION.md) for the exact checks completed in the development workspace.

The first network-enabled Go build should commit the `go.sum` and indirect requirements produced by `go mod tidy`; the module dependency is pinned and downloaded through Go’s checksum verification. CI currently runs `go mod tidy` before verification. The Node test dependency is also version-pinned; commit its generated lockfile after the first installation.

## Roadmap toward a stable release

- Run the expanded Go suite, race detector and ARM64 build; test the upgrade on a real Pi.
- Add load and malformed-packet fuzz testing, dependency vulnerability review, and a sustained reliability test.
- Add TTL-aware DNS caching with dedicated DNSSEC/EDNS tests.
- Publish versioned container images with checksums and an upgrade channel.
- Improve IPv6 installation guidance, TLS deployment options, and configuration import/export.

## Project documents

[Architecture](docs/ARCHITECTURE.md) · [Upgrade guide](docs/UPGRADING.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

QuietDNS code is MIT-licensed. The DNS library has its own BSD license. Downloaded [HaGeZi lists](https://github.com/hagezi/dns-blocklists) remain subject to their own GPL-3.0 license and attribution; they are not included in this source archive. QuietDNS is an independent project, not affiliated with Pi-hole.
