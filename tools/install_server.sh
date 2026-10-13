#!/usr/bin/env bash
# Replace the disposable Standard laboratory on Ubuntu 24.04.
# Run phase 1 from a pushed, clean checkout as root; run "activate" after FLOOR-0's delay.
# Never use this installation to claim independent qualification or govern client data.
set -euo pipefail

CODE=/opt/standard
ROOT=/srv/standard
SRC="$(cd "$(dirname "$0")/.." && pwd)"
PY="$CODE/venv/bin/python"
MARKER=.standard-laboratory

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

lab_path() {
  local path="$1"
  [ ! -L "$path" ] || { echo "refusing symlink: $path" >&2; exit 1; }
  if [ -e "$path" ] && [ ! -f "$path/$MARKER" ]; then
    echo "refusing non-laboratory path: $path" >&2
    exit 1
  fi
}

stop_lab() {
  for unit in standard-agent standard-web standard-operator; do
    if systemctl is-active --quiet "$unit"; then
      systemctl stop "$unit"
      ! systemctl is-active --quiet "$unit" || { echo "could not stop $unit" >&2; exit 1; }
    fi
  done
}

check_units() {
  for unit in standard-agent standard-web standard-operator; do
    if systemctl is-active --quiet "$unit"; then
      echo "refusing active $unit without a laboratory marker" >&2
      exit 1
    fi
  done
}

git_source() {
  git -c "safe.directory=$SRC" -C "$SRC" "$@"
}

unit() {
  local name="$1" user="$2" command="$3"
  cat > "/etc/systemd/system/$name.service" <<EOF
[Unit]
Description=Standard laboratory $name
After=network-online.target

[Service]
User=$user
Group=$user
UMask=0027
Environment=HOME=/home/$user
WorkingDirectory=$CODE
ExecStart=$PY $command
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
}

start_interface() {
  unit standard-operator standard-guard "-m standard.runtime serve $ROOT/install/standard.toml 30"
  unit standard-web standard-web "-m standard.surface.web $ROOT/install/standard.toml --bind 127.0.0.1 --port 8080"
  systemctl daemon-reload
  systemctl enable --now standard-operator standard-web
  local ready=0
  for _ in {1..15}; do
    if curl -fsS http://127.0.0.1:8080/api/state >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  [ "$ready" = 1 ] || { echo "web interface did not become ready" >&2; exit 1; }
}

install_lab() {
  case "$SRC/" in "$CODE/"*) echo "run from a separate Git checkout" >&2; exit 1 ;; esac
  local commit branch published
  commit="$(git_source rev-parse --verify HEAD)"
  branch="$(git_source symbolic-ref --quiet --short HEAD)"
  published="$(git_source ls-remote --exit-code origin "refs/heads/$branch")"
  [ "${published%%[[:space:]]*}" = "$commit" ] || {
    echo "the checked-out commit is not the pushed branch tip" >&2; exit 1;
  }
  [ -z "$(git_source status --porcelain --untracked-files=no)" ] || {
    echo "push a clean commit before installing" >&2; exit 1;
  }
  lab_path "$CODE"
  lab_path "$ROOT"
  if [ -f "$CODE/$MARKER" ] && [ -f "$ROOT/$MARKER" ]; then stop_lab; else check_units; fi

  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q git python3-venv python3-pip util-linux bubblewrap curl >/dev/null
  python3 -c 'import sys; assert sys.version_info >= (3, 11)'

  rm -rf -- "$CODE" "$ROOT"
  install -d -m 0755 "$CODE" "$ROOT" "$ROOT/seed" "$ROOT/hosting"
  touch "$CODE/$MARKER" "$ROOT/$MARKER"
  git_source archive "$commit" | tar -x -C "$CODE"
  printf '%s\n' "$commit" > "$CODE/LAB_COMMIT"
  python3 -m venv "$CODE/venv"
  "$PY" -m pip install -q -r "$CODE/requirements.txt"
  chown -R root:root "$CODE"
  chmod -R a+rX,go-w "$CODE"

  id standard-guard >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin standard-guard
  id standard-agent >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin -G standard-guard standard-agent
  id standard-gate  >/dev/null 2>&1 || useradd -m -s /bin/sh -G standard-guard standard-gate
  id standard-web   >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin -G standard-guard standard-web
  id standard-runner >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin standard-runner

  git -C "$ROOT/seed" init -q -b main
  git -C "$ROOT/seed" -c user.name=Standard -c user.email=lab@localhost \
    commit --allow-empty -qm "Empty laboratory repository"
  "$PY" "$CODE/tools/host.py" create "$ROOT/hosting/hosting.toml" lab --from "$ROOT/seed" \
    --guard-user standard-guard --gate-user standard-gate
  git config --global --add safe.directory "$ROOT/hosting/repos/lab.git"
  runuser -u standard-web -- env HOME=/home/standard-web git config --global --add safe.directory \
    "$ROOT/hosting/repos/lab.git"

  cd "$CODE"
  "$PY" tools/ceremony.py init "$ROOT/install" --repo "$ROOT/hosting/repos/lab.git" \
    --inbox "$ROOT/hosting/inbox/lab.git" --pins "$ROOT/pins/pins.db"
  cat >> "$ROOT/install/standard.toml" <<EOF

[tests]
install = false
runner_user = "standard-runner"

[hosting]
config = "$ROOT/hosting/hosting.toml"
gate_user = "standard-gate"
EOF
  "$PY" tools/ceremony.py separate "$ROOT/install" --guard-user standard-guard --agent-user standard-agent
  start_interface
  echo "LABORATORY ONLY: one host holds simulated human and witness keys; qualification must fail."
  echo "Commit: $(cat "$CODE/LAB_COMMIT")"
  echo "Interface ready on 127.0.0.1:8080 through an SSH tunnel; grants are still pending."
  echo "Wait for FLOOR-0, then run: bash $CODE/tools/install_server.sh activate"
}

activate_lab() {
  lab_path "$CODE"
  lab_path "$ROOT"
  [ -f "$CODE/$MARKER" ] && [ -f "$ROOT/$MARKER" ] || exit 1
  cd "$CODE"
  systemctl stop standard-web standard-operator
  if ! "$PY" tools/ceremony.py activate "$ROOT/install"; then
    "$PY" tools/ceremony.py separate "$ROOT/install" --guard-user standard-guard --agent-user standard-agent
    systemctl start standard-operator standard-web
    exit 1
  fi
  "$PY" tools/ceremony.py separate "$ROOT/install" --guard-user standard-guard --agent-user standard-agent
  printf 'standard-guard ALL=(standard-runner) NOPASSWD: /usr/bin/env\n' > /etc/sudoers.d/standard-runner
  chmod 440 /etc/sudoers.d/standard-runner

  unit standard-agent standard-agent "-m standard.autonomy run $ROOT/install/standard.toml 60"
  systemctl daemon-reload
  start_interface
  systemctl enable --now standard-agent
  "$PY" tools/qualify.py "$ROOT/install/standard.toml" > "$ROOT/qualification.json" || true
  "$PY" -c 'import json,sys; assert isinstance(json.load(open(sys.argv[1])), list)' "$ROOT/qualification.json"
  echo "LABORATORY ONLY: qualification is recorded in $ROOT/qualification.json, not claimed."
  echo "Use an SSH tunnel to localhost:8080; the interface is not publicly exposed."
}

case "${1:-}" in
  "") install_lab ;;
  activate) activate_lab ;;
  *) echo "usage: $0 [activate]" >&2; exit 2 ;;
esac
