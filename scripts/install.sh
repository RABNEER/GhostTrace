#!/usr/bin/env bash
set -euo pipefail

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing dependency: $1" >&2
    exit 1
  }
}

need nasm
need gcc
need go
need clang

go_version="$(go env GOVERSION | sed 's/^go//')"
go_major="${go_version%%.*}"
go_rest="${go_version#*.}"
go_minor="${go_rest%%.*}"
if (( go_major < 1 || (go_major == 1 && go_minor < 22) )); then
  echo "Go 1.22 or newer is required, found $(go env GOVERSION)" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

make -C asm
make -C cshim
CGO_ENABLED=1 go build -ldflags="-s -w" -o /usr/local/bin/ghosttrace ./cmd/ghosttrace

install -d -m 0755 /var/log/ghosttrace /etc/ghosttrace
install -m 0644 configs/ghosttrace.yaml /etc/ghosttrace/ghosttrace.yaml

cat >/etc/systemd/system/ghosttrace.service <<'UNIT'
[Unit]
Description=GhostTrace process integrity monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ghosttrace --config /etc/ghosttrace/ghosttrace.yaml --mode=ebpf --no-tui
Restart=on-failure
RestartSec=5s
User=root
AmbientCapabilities=CAP_SYS_PTRACE CAP_SYS_ADMIN CAP_NET_ADMIN
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF CAP_PERFMON
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/log/ghosttrace

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable ghosttrace
echo "GhostTrace installed. Start it with: systemctl start ghosttrace"
