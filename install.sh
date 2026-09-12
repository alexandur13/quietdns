#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
printf '\n  QuietDNS — a quieter internet, at home.\n\n'
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  printf 'Docker Engine and the Compose plugin are required.\nInstall them using https://docs.docker.com/engine/install/debian/ and rerun this script.\n'
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  printf 'Cannot reach Docker. Start Docker and check your account has permission to use it.\n'
  exit 1
fi
if [[ -f .env ]]; then
  printf 'Existing .env found; keeping your settings and setup key.\n'
else
  quiet_default=$(hostname -I | awk '{print $1}')
  quiet_ip="${BIND_IP:-$quiet_default}"
  if [[ -t 0 ]]; then read -r -p "Pi LAN IPv4 address [$quiet_ip]: " quiet_answer; quiet_ip="${quiet_answer:-$quiet_ip}"; fi
  if [[ ! "$quiet_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf 'Enter a valid IPv4 address.\n'; exit 1; fi
  IFS=. read -r q1 q2 q3 q4 <<< "$quiet_ip"
  for octet in "$q1" "$q2" "$q3" "$q4"; do if ((10#$octet > 255)); then printf 'Invalid IPv4 address.\n'; exit 1; fi; done
  quiet_dns="${DNS_PORT:-53}"
  quiet_http="${HTTP_PORT:-8081}"
  for port in "$quiet_dns" "$quiet_http"; do
    if [[ ! "$port" =~ ^[0-9]{1,5}$ ]] || ((10#$port < 1 || 10#$port > 65535)); then printf 'Ports must be between 1 and 65535.\n'; exit 1; fi
  done
  quiet_dns=$((10#$quiet_dns)); quiet_http=$((10#$quiet_http))
  if [[ "$quiet_dns" == "$quiet_http" ]]; then printf 'DNS and dashboard ports must be different.\n'; exit 1; fi
  if command -v ss >/dev/null; then
    for port in "$quiet_dns" "$quiet_http"; do
      if [[ -n "$(ss -H -lntu "sport = :$port")" ]]; then
        printf 'Port %s is already occupied. No existing service has been stopped.\n' "$port"
        printf 'For a parallel trial, run: DNS_PORT=1053 HTTP_PORT=8081 bash install.sh\n'
        exit 1
      fi
    done
  fi
  quiet_key=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  umask 077
  printf 'BIND_IP=%s\nDNS_PORT=%s\nHTTP_PORT=%s\nSETUP_TOKEN=%s\n' "$quiet_ip" "$quiet_dns" "$quiet_http" "$quiet_key" > .env
fi
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 90
quiet_ip=$(sed -n 's/^BIND_IP=//p' .env)
quiet_http=$(sed -n 's/^HTTP_PORT=//p' .env)
quiet_dns=$(sed -n 's/^DNS_PORT=//p' .env)
quiet_key=$(sed -n 's/^SETUP_TOKEN=//p' .env)
printf '\nQuietDNS is running.\nDashboard: http://%s:%s\nInstallation key: %s\n\n' "$quiet_ip" "$quiet_http" "$quiet_key"
printf 'Open the dashboard to create your administrator password and choose a blocklist.\n'
if [[ "$quiet_dns" != '53' ]]; then printf 'Trial DNS port: %s. Standard client DNS settings require port 53; see docs/UPGRADING.md.\n' "$quiet_dns"; fi
