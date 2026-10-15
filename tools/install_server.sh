#!/usr/bin/env bash
# Replace the disposable Standard laboratory on Ubuntu 24.04.
# Run from a pushed, clean checkout as root: one human, one agent, in force at once.
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
  local name="$1" user="$2" command="$3" stop_control="" dependency=""
  if [ "$name" = standard-agent ]; then
    # The fixed launcher places this process outside the service's initial cgroup.
    # Signal its main process, then let root kill the complete bounded UID subtree.
    dependency="standard-operator.service"
    stop_control="KillMode=process
ExecStopPost=+/bin/sh -c 'echo 1 > /sys/fs/cgroup/standard-bac/$(id -u standard-agent)/cgroup.kill'"
  fi
  cat > "/etc/systemd/system/$name.service" <<EOF
[Unit]
Description=Standard laboratory $name
After=network-online.target standard-cgroups.service $dependency
Requires=standard-cgroups.service $dependency

[Service]
User=$user
Group=$user
UMask=0027
Environment=HOME=/home/$user
WorkingDirectory=$CODE
ExecStart=$command
$stop_control
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
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
  [ -f /sys/fs/cgroup/cgroup.controllers ] || {
    echo "the fabric requires a cgroup v2 host with cpu, memory and pids delegation" >&2; exit 1;
  }
  for controller in cpu memory pids; do
    case " $(cat /sys/fs/cgroup/cgroup.controllers) " in
      *" $controller "*) ;;
      *) echo "missing cgroup controller: $controller" >&2; exit 1 ;;
    esac
  done
  lab_path "$CODE"
  lab_path "$ROOT"
  if [ -f "$CODE/$MARKER" ] && [ -f "$ROOT/$MARKER" ]; then stop_lab; else check_units; fi

  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q git python3-venv python3-pip util-linux bubblewrap curl runc sudo >/dev/null
  python3 -c 'import sys; assert sys.version_info >= (3, 11)'

  id standard-guard >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin standard-guard
  id standard-agent >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin -G standard-guard standard-agent
  usermod -a -G standard-guard standard-agent
  # Check the host prerequisite before replacing even a disposable existing installation.
  # Never grant extra capabilities or disable host LSM policy to get past this refusal.
  runuser -u standard-agent -- unshare -Urn /usr/bin/true || {
    echo "user/network namespaces unavailable; use a qualified orchestrator or host" >&2; exit 1;
  }

  rm -rf -- "$CODE" "$ROOT"
  install -d -m 0755 "$CODE" "$ROOT" "$ROOT/seed" "$ROOT/hosting"
  touch "$CODE/$MARKER" "$ROOT/$MARKER"
  git_source archive "$commit" | tar -x -C "$CODE"
  printf '%s\n' "$commit" > "$CODE/LAB_COMMIT"
  python3 -m venv "$CODE/venv"
  "$PY" -m pip install -q --require-hashes -r "$CODE/requirements.hashes"   # the reviewed closure, nothing newer
  chown -R root:root "$CODE"
  chmod -R a+rX,go-w "$CODE"

  id standard-gate  >/dev/null 2>&1 || useradd -m -s /bin/sh -G standard-guard standard-gate
  id standard-web   >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin -G standard-guard standard-web
  id standard-runner >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin standard-runner
  install -d -m 0755 /usr/local/libexec
  install -o root -g root -m 0755 "$CODE/tools/cgroup_setup.sh" /usr/local/libexec/standard-cgroups-setup
  install -o root -g root -m 0755 "$CODE/tools/cgroup_run.sh" /usr/local/libexec/standard-cgroup-run
  cat > /etc/systemd/system/standard-cgroups.service <<'CGROUP_UNIT'
[Unit]
Description=Standard laboratory native cgroup delegation
Before=standard-agent.service standard-operator.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/standard-cgroups-setup
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
CGROUP_UNIT
  /usr/local/libexec/standard-cgroups-setup

  git -C "$ROOT/seed" init -q -b main
  git -C "$ROOT/seed" -c user.name=Standard -c user.email=lab@localhost \
    commit --allow-empty -qm "Empty laboratory repository"
  "$PY" "$CODE/tools/hosting.py" create "$ROOT/hosting/hosting.toml" lab --from "$ROOT/seed" \
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
  echo "LABORATORY ONLY: this host holds the human's key too; qualification must fail (T02)."
  echo "Commit: $(cat "$CODE/LAB_COMMIT")"
  "$PY" tools/ceremony.py separate "$ROOT/install" --guard-user standard-guard --agent-user standard-agent
  printf 'standard-guard ALL=(root) NOPASSWD: /usr/local/libexec/standard-cgroup-run standard-runner *\n' > /etc/sudoers.d/standard-runner
  chmod 440 /etc/sudoers.d/standard-runner

  for account in standard-agent standard-runner; do
    /usr/local/libexec/standard-cgroup-run "$account" "$PY" -c \
      'from fabric.runtime.bac import Bac; b = Bac(); assert b.ready, b.why'
  done

  unit standard-operator standard-guard "$PY -m fabric.control.runtime serve $ROOT/install/standard.toml 30"
  unit standard-agent standard-agent "+/usr/local/libexec/standard-cgroup-run standard-agent $PY -m engine.agents.enclosed launch $ROOT/install/standard.toml 60"
  unit standard-web standard-web "$PY -m interface.surface.web $ROOT/install/standard.toml --bind 127.0.0.1 --port 8080"
  systemctl daemon-reload
  systemctl enable --now standard-cgroups
  systemctl enable --now standard-operator
  systemctl enable --now standard-agent standard-web
  local ready=0
  for _ in {1..15}; do
    if curl -fsS http://127.0.0.1:8080/api/state >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  [ "$ready" = 1 ] || { echo "web interface did not become ready" >&2; exit 1; }
  "$PY" tools/qualify.py "$ROOT/install/standard.toml" > "$ROOT/qualification.json" || true
  "$PY" -c 'import json,sys; assert isinstance(json.load(open(sys.argv[1])), list)' "$ROOT/qualification.json"
  echo "LABORATORY ONLY: qualification is recorded in $ROOT/qualification.json, not claimed."
  echo "Use an SSH tunnel to localhost:8080; the interface is not publicly exposed."
}

case "${1:-}" in
  "") install_lab ;;
  *) echo "usage: $0" >&2; exit 2 ;;
esac
