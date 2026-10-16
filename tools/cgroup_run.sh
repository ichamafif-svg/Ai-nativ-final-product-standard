#!/bin/bash
# Installed root-owned at /usr/local/libexec/standard-cgroup-run. Never executes a candidate as root.
set -euo pipefail
[ "$(/usr/bin/id -u)" = 0 ] || { echo 'root launcher required' >&2; exit 1; }
account="${1:-}"
case "$account" in standard-agent|standard-runner) ;; *) echo 'runner account refused' >&2; exit 1 ;; esac
shift
leaf=launcher
if [ "${1:-}" = --enclosed ] && [ "$account" = standard-agent ]; then
  leaf=enclosure
  shift
fi
[ "$#" -gt 0 ] || { echo 'command required' >&2; exit 1; }
task_uid="$(/usr/bin/id -u "$account")"
subtree="/sys/fs/cgroup/standard-bac/$task_uid"
[ -d "$subtree/launcher" ] || { echo 'delegation unavailable; start standard-cgroups.service' >&2; exit 1; }
# Root places its own process inside the delegation before UID drop. This satisfies cgroup v2's
# common-ancestor migration rule when the unprivileged OCI runtime creates a sibling run cgroup.
printf '%s\n' "$$" > "$subtree/$leaf/cgroup.procs"
exec /usr/sbin/runuser -u "$account" -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/bin "$@"
