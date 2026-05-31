# Install

## Build From Source

```bash
sudo apt-get update
sudo apt-get install -y build-essential nasm clang linux-headers-$(uname -r)
make build
sudo bin/ghosttrace --mode=ebpf
```

## System Service

```bash
sudo scripts/install.sh
sudo systemctl start ghosttrace
sudo journalctl -u ghosttrace -f
```

The service reads `/etc/ghosttrace/ghosttrace.yaml` and writes logs under `/var/log/ghosttrace`.
