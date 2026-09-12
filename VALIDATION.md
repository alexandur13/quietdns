# Validation status

## Previously verified on the Pi

The earlier DNS-only prototype built and passed its automated tests on Debian 13 ARM64. Live `dig` queries confirmed allowed UDP/TCP forwarding and blocked A/AAAA/subdomain queries. A Windows LAN device confirmed port 53 reachability. Those results establish the prototype baseline; they do not automatically validate the expanded application in this directory.

## Completed for this expanded version

- JavaScript syntax checks.
- Docker Compose configuration validation.
- Four frontend logic tests: combined query filters, HTML escaping, empty statistics and chart bucket handling.
- Browser inspection with a clearly labelled in-memory API fixture: first-run wizard through completion, desktop layout, pause/resume, query search, creation of an allow rule from a query, blocklist toggle, settings save, diagnostics display, and mobile navigation.
- Mobile viewport inspection at 390 pixels; no document-level horizontal overflow was observed.
- Current HaGeZi Light and Normal download paths checked against the maintained repository.

## Pending

- Go compilation, unit/integration suite, race detector and vet for this expanded version.
- Container build, expanded first-run setup against the real API, ARM64 runtime and persistent volume permissions.
- Full automated Playwright script and Linux installer execution.
- Real blocklist download, restart persistence and trial-to-port-53 migration on the Pi.
- Longer load/reliability tests and dependency vulnerability audit.

The development workspace had no Go compiler or active Docker daemon. Network approval for downloading a compiler was rejected by the session policy. Launching an independent headless browser was also blocked, so available in-app browser controls were used for the stated UI checks. The included GitHub Actions workflow and Docker build provide the next backend verification gate. Do not label this a stable release until those gates pass.
