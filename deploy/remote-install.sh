#!/bin/sh
# Runs on the relay server as root (CI: ssh root@host 'sh -s' < deploy/remote-install.sh).
# Expects /tmp/gate4ai-relay.new uploaded beforehand. Replaces only the binary:
# the systemd unit and /etc/gate4ai-relay/env (certificate, --route) stay as
# configured on the server. Rolls back to the previous binary if the relay API
# does not answer after the restart.
set -eu

BIN=/usr/local/bin/gate4ai-relay
DOMAIN=relay.gate4.ai

[ "$(uname -m)" = x86_64 ] || { echo "server is $(uname -m), CI builds x86_64" >&2; exit 1; }
systemctl cat gate4ai-relay >/dev/null 2>&1 || { echo "gate4ai-relay.service is not installed" >&2; exit 1; }

[ -f "$BIN" ] && cp -p "$BIN" "$BIN.prev"
install -m 0755 /tmp/gate4ai-relay.new "$BIN.tmp"
rm -f /tmp/gate4ai-relay.new
mv -f "$BIN.tmp" "$BIN"
systemctl restart gate4ai-relay

health() {
  i=0
  while [ $i -lt 20 ]; do
    if curl -fsS --max-time 5 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/api/health" >/dev/null 2>&1; then return 0; fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

if health; then
  echo "gate4ai-relay: $("$BIN" --version), healthy"
else
  echo "gate4ai-relay: health check failed" >&2
  journalctl -u gate4ai-relay -n 30 --no-pager >&2 || true
  if [ -f "$BIN.prev" ]; then
    mv -f "$BIN.prev" "$BIN"
    systemctl restart gate4ai-relay
    echo "rolled back to the previous binary" >&2
  fi
  exit 1
fi

# The site lives behind the relay (--route); a failure here is reported, not rolled back.
if ! curl -fsS --max-time 10 --resolve "gate4.ai:443:127.0.0.1" https://gate4.ai/healthz >/dev/null 2>&1; then
  echo "WARNING: https://gate4.ai/healthz does not answer through the relay" >&2
fi
