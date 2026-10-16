#!/bin/bash
# Root-owned, boot-time preparation for the disposable Linux laboratory.
set -euo pipefail
[ "$(/usr/bin/id -u)" = 0 ] || { echo 'root required' >&2; exit 1; }
[ -f /sys/fs/cgroup/cgroup.controllers ] || { echo 'cgroup v2 required' >&2; exit 1; }
mkdir -p /sys/fs/cgroup/standard-bac
printf '%s\n' '+cpu +memory +pids' > /sys/fs/cgroup/standard-bac/cgroup.subtree_control
for account in standard-agent standard-runner; do
  task_uid="$(/usr/bin/id -u "$account")"
  subtree="/sys/fs/cgroup/standard-bac/$task_uid"
  mkdir -p "$subtree" "$subtree/launcher" "$subtree/enclosure"
  printf '%s\n' '+cpu +memory +pids' > "$subtree/cgroup.subtree_control"
  printf '%s\n' 8589934592 > "$subtree/memory.max"
  printf '%s\n' 512 > "$subtree/pids.max"
  printf '%s\n' '200000 100000' > "$subtree/cpu.max"
  # Root owns aggregate ceilings. The account can create children and migrate within this subtree.
  # The guard can read counters but cannot write limits or membership files.
  chown "$account:standard-guard" "$subtree" "$subtree/cgroup.procs" "$subtree/cgroup.threads" \
    "$subtree/cgroup.subtree_control"
  chmod 2750 "$subtree"
done
