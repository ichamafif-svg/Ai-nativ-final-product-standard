#!/usr/bin/env bash
# Install Standard on one Ubuntu 24.04 server (ARCHITECTURE.md §19.2, D22, D23). Run as root from the project folder:
#
#     bash tools/install_server.sh            phase 1: system, users, hosting, demo repository, ceremony (init)
#     bash tools/install_server.sh activate   phase 2, at least one hour later (FLOOR-0): activate and start
#
# The interface listens on localhost only: reach it through an SSH tunnel.
# DEMO installation: every human and witness key is on this server and the installation assesses itself. qualify.py
# says so. What is physical here: the guard, the agent and the SSH gate are three Unix users, and only the guard
# can move main.
set -euo pipefail

CODE=/opt/standard
HOSTING=/srv/standard/hosting
INSTALL=/srv/standard/install
PINS=/var/lib/standard-pins/pins.db
PY=$CODE/venv/bin/python
SRC="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

say() { printf '\n== %s\n' "$*"; }

phase1() {
  say "system packages"
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q git python3-venv python3-pip ufw util-linux apparmor >/dev/null

  say "code in $CODE, its own Python environment"
  if [ "$SRC" != "$CODE" ]; then rm -rf "$CODE"; mkdir -p "$CODE"; cp -a "$SRC"/. "$CODE"/; fi
  python3 -m venv "$CODE/venv"
  "$CODE/venv/bin/pip" install -q -r "$CODE/requirements.txt"
  chown -R root:root "$CODE"; chmod -R a+rX,go-w "$CODE"

  say "three Unix users: the guard (K/T), the agent (U), the SSH gate"
  id standard-guard >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin standard-guard
  id standard-agent >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin -G standard-guard standard-agent
  id standard-gate  >/dev/null 2>&1 || useradd -m -s /bin/sh -G standard-guard standard-gate
  id standard-web   >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin -G standard-guard standard-web
  usermod -p '*' standard-gate                     # key login only, no password

  say "the agent's sandbox may open a network-less namespace (Ubuntu restricts it by default)"
  cat > /etc/apparmor.d/standard-unshare <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile standard-unshare /usr/bin/unshare flags=(unconfined) {
  userns,
}
EOF
  apparmor_parser -r /etc/apparmor.d/standard-unshare || echo "WARNING: the sandbox will run without network isolation"

  say "firewall: SSH only"
  { ufw allow OpenSSH >/dev/null && ufw --force enable >/dev/null; } || echo "WARNING: firewall not enabled"

  say "hosting: one repository (app) seeded from demo/"
  rm -rf /srv/standard; mkdir -p /srv/standard/seed "$HOSTING" "$(dirname "$PINS")"; chmod 755 /srv/standard "$HOSTING"
  cp -a "$CODE/demo/." /srv/standard/seed/
  git -C /srv/standard/seed init -q -b main
  git -C /srv/standard/seed add -A
  git -C /srv/standard/seed -c user.name=Standard -c user.email=standard@localhost commit -qm "Demo repository"
  for u in standard-guard standard-agent standard-gate; do rm -f "/home/$u/.gitconfig"; done
  cd "$CODE"
  "$PY" tools/host.py create "$HOSTING/hosting.toml" app --from /srv/standard/seed \
        --guard-user standard-guard --gate-user standard-gate
  git config --global --add safe.directory "$HOSTING/repos/app.git"
  for r in "$HOSTING/repos/app.git" "$HOSTING/inbox/app.git"; do   # the interface reads both, from outside
    runuser -u standard-web -- env HOME=/home/standard-web git config --global --add safe.directory "$r"
  done
  if [ -s /root/.ssh/authorized_keys ]; then
    head -1 /root/.ssh/authorized_keys > /tmp/owner.pub
    "$PY" tools/host.py authorize "$HOSTING/hosting.toml" app owner --key /tmp/owner.pub --write --gate-user standard-gate
  fi

  say "trusted data snapshot (OSV advisories, PyPI metadata, action commits), pinned by its digest"
  "$PY" tools/refresh_data.py /srv/standard/seed/requirements.txt \
        --actions actions/checkout@v4 actions/setup-python@v5 > /srv/standard/data.json \
    || { echo "WARNING: no data snapshot: vulnerabilities and action pinning stay uncovered"; rm -f /srv/standard/data.json; }
  chmod 644 /srv/standard/data.json 2>/dev/null || true

  say "ceremony, phase 1"
  DATA=(); [ -s /srv/standard/data.json ] && DATA=(--data /srv/standard/data.json)
  "$PY" tools/ceremony.py init "$INSTALL" --repo "$HOSTING/repos/app.git" --inbox "$HOSTING/inbox/app.git" \
        --pins "$PINS" "${DATA[@]}"
  printf '\n[run]\nmetrics = ["http://127.0.0.1:9000/metrics"]\nslo = 99.9\nbase_url = "http://127.0.0.1:9000"\n' >> "$INSTALL/standard.toml"
  # D30: the guard switches the live release (deploy, rollback); the product's user only reads it.
  printf '\n[deploy]\nroot = "/srv/standard/deploy"\n' >> "$INSTALL/standard.toml"
  # D33: contributors' code runs as an account without keys and without network, never as the guard.
  id standard-runner >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin standard-runner
  printf 'standard-guard ALL=(standard-runner) NOPASSWD: /usr/bin/env\n' > /etc/sudoers.d/standard-runner
  chmod 440 /etc/sudoers.d/standard-runner
  printf '\n[tests]\ninstall = true\nrunner_user = "standard-runner"\n\n[hosting]\nconfig = "%s"\ngate_user = "standard-gate"\n' \
         "$HOSTING/hosting.toml" >> "$INSTALL/standard.toml"

  say "Claude API key (optional: Enter to skip; it is not shown and stays in a file only the agent can read)"
  read -r -s -p "key: " KEY; echo
  if [ -n "$KEY" ]; then
    printf '%s' "$KEY" > "$INSTALL/claude.key"
    printf '\n[llm.small]\nkind = "anthropic"\nmodel = "claude-haiku-5-5"\nkey_file = "claude.key"\n' >> "$INSTALL/standard.toml"
    printf '\n[llm.frontier]\nkind = "anthropic"\nmodel = "claude-sonnet-5-5"\nkey_file = "claude.key"\n' >> "$INSTALL/standard.toml"
  fi
  unset KEY

  say "SSH: keys only, once a key is installed"
  if [ -s /root/.ssh/authorized_keys ]; then
    printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' \
      > /etc/ssh/sshd_config.d/10-standard.conf
    systemctl reload ssh || echo "WARNING: reload ssh by hand: systemctl reload ssh"
  else
    echo "WARNING: no key in /root/.ssh/authorized_keys: password login stays on"
  fi

  echo
  echo "Phase 1 done. FLOOR-0 makes the grants wait one hour. Then run:"
  echo "    bash $CODE/tools/install_server.sh activate"
}

unit() {   # name user args
  cat > "/etc/systemd/system/$1.service" <<EOF
[Unit]
Description=Standard $1
After=network-online.target

[Service]
User=$2
Group=$2
UMask=0027
Environment=HOME=/home/$2
WorkingDirectory=$CODE
ExecStart=$PY $3
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
}

phase2() {
  cd "$CODE"
  say "ceremony, phase 2"
  "$PY" tools/ceremony.py activate "$INSTALL"
  "$PY" tools/ceremony.py separate "$INSTALL" --guard-user standard-guard --agent-user standard-agent
  if [ -f "$INSTALL/claude.key" ]; then
    chown standard-agent:standard-agent "$INSTALL/claude.key"; chmod 600 "$INSTALL/claude.key"
  fi

  say "two services: the operator (guard) and the agent"
  unit standard-operator standard-guard "-m trusted serve $INSTALL/standard.toml 30"
  unit standard-agent standard-agent "-m autonomy run $INSTALL/standard.toml 60"
  unit standard-web standard-web "-m surface.web $INSTALL/standard.toml --bind 127.0.0.1 --port 8080"
  # DEMO: the demo product's API and steady traffic, so that Run shows real metrics.
  id standard-demo >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin standard-demo
  install -d -o standard-guard -g standard-guard -m 0755 /srv/standard/deploy
  install -d -o standard-demo -g standard-demo -m 0750 /srv/standard/data      # the product's data, not the guard's
  unit standard-demo-service standard-demo "$CODE/tools/run_release.py /srv/standard/deploy/current 9000 --data /srv/standard/data"
  unit standard-demo-load standard-demo "$CODE/tools/demo_load.py http://127.0.0.1:9000 20"
  systemctl daemon-reload
  systemctl enable --now standard-operator
  sleep 5
  systemctl enable --now standard-agent
  systemctl enable --now standard-web
  systemctl enable --now standard-demo-service standard-demo-load

  say "qualification"
  "$PY" tools/qualify.py "$INSTALL/standard.toml" | "$PY" -c \
    'import json,sys; [print(p["result"], "|", p["probe"]) for p in json.load(sys.stdin)]' || true
  echo
  echo "Interface: from your computer, ssh -L 8080:localhost:8080 root@<this server>, then open http://localhost:8080"
  echo "Follow:  journalctl -fu standard-agent    journalctl -fu standard-operator"
  echo "Status:  cd $CODE && $PY -m surface --socket $INSTALL/admission.sock status"
}

case "${1:-}" in
  "") phase1 ;;
  activate) phase2 ;;
  *) echo "usage: $0 [activate]"; exit 2 ;;
esac
