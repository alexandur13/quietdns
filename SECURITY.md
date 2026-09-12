# Security

QuietDNS is a development preview. Run it on a trusted LAN while its expanded backend and deployment are being validated. Do not expose DNS or dashboard ports to the public internet.

The default admin interface uses HTTP, so use a trusted LAN or an SSH tunnel. Passwords are hashed at rest, but HTTP does not protect them in transit. `.env` contains a first-run installation key and the data volume contains administrator credential material and query history.

For private testing, an SSH tunnel can expose the dashboard only to the local machine:

```bash
ssh -L 8081:PI_IP:8081 USER@PI_IP
```

Open `http://localhost:8081` while the tunnel is active. This does not change the underlying LAN listener. For an exclusively tunneled dashboard, change only the dashboard mapping's bind address in Compose to `127.0.0.1`, then tunnel to `127.0.0.1:8081` on the Pi.

Do not open a public issue containing setup keys, passwords or private DNS logs. Before a public release, configure GitHub private vulnerability reporting. Until then, arrange a private reporting channel with the repository maintainer; no public security-reporting email is configured in this starter repository.
