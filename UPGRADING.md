# Upgrade from the verified prototype

Keep the existing `~/pi-dns` directory and container until the expanded version has passed its tests. The new application uses a separate Compose project (`quietdns`) and persistent data volume.

## 1. Trial installation

Extract the new archive as `~/quietdns` and run:

```bash
cd ~/quietdns
DNS_PORT=1053 HTTP_PORT=8081 bash install.sh
```

The original prototype currently uses port 53, so it can continue to serve DNS during this trial. If 1053 or 8081 is occupied, choose another trial port.

Open `http://PI_IP:8081`, use the printed installation key, choose a password, and select a list. Wait for a non-zero downloaded list count under Blocklists. Failed downloads display an error; do not assume the full blocklist is active before this count appears.

## 2. Test

```bash
dig @PI_IP -p 1053 example.com A
dig @PI_IP -p 1053 example.com A +tcp
dig @PI_IP -p 1053 blocked.test A
dig @PI_IP -p 1053 child.blocked.test AAAA +tcp
```

Check that the dashboard shows these queries. Add an allow rule for `blocked.test`, verify it no longer reports a policy block, remove that rule, and verify blocking resumes. The reserved `.test` name normally returns NXDOMAIN from an upstream too, so distinguish the “Allowed/Not found” policy status from the final DNS code during this allowlist check. For a public allowlist test, use a known-resolving domain you explicitly add to your own block rules.

## 3. Move to port 53

After the new build and tests pass:

```bash
docker stop fresh-pi-dns-dns-1
cd ~/quietdns
sed -i 's/^DNS_PORT=.*/DNS_PORT=53/' .env
docker compose up -d --wait
dig @PI_IP example.com A
dig @PI_IP blocked.test A
```

On Windows, run `nslookup example.com PI_IP` and `nslookup blocked.test PI_IP`. Existing client DNS settings continue using the same Pi IP once the new service owns port 53.

Rollback:

```bash
cd ~/quietdns
docker compose down
docker start fresh-pi-dns-dns-1
```

The trial app’s data volume remains intact after `down` without `-v`. The old prototype does not have an automatic configuration importer; recreate any custom rules through the new dashboard.

## Back up the application data

From the installation directory, stop the application briefly for a consistent archive:

```bash
docker compose stop quietdns
docker run --rm -v quietdns_data:/data:ro -v "$PWD:/backup" alpine:3.24 tar czf /backup/quietdns-backup.tar.gz -C /data .
docker compose up -d
```

Store that archive and `.env` securely. They contain administrator credential material and private query history. A custom Compose project name changes the data volume name; check `docker volume ls` if you changed it.

## Subsequent source updates

Back up first. Update the source checkout, run `docker compose build` (which runs the tests), then `docker compose up -d --wait`. The named data volume is retained. Keep the prior source revision and image available until the update is verified. This preview does not yet include an automatic data-schema migration or downgrade system.
