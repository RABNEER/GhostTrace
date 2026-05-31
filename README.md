# GhostTrace

GhostTrace is a Linux process-integrity monitor that combines eBPF telemetry, native memory scanning helpers, anomaly scoring, and a terminal dashboard for rootkit and injection detection.

## Architecture

```text
            +--------------------+
            |  syscall/mmap data |
            +---------+----------+
                      |
        +-------------+-------------+
        |                           |
+-------v--------+          +-------v--------+
| eBPF tracepts  |          | ASM/C shim     |
| safe mode      |          | native helpers |
+-------+--------+          +-------+--------+
        |                           |
        +-------------+-------------+
                      |
              +-------v--------+
              |  event decoder |
              +-------+--------+
                      |
       +--------------+---------------+
       |                              |
+------v-------+              +-------v------+
| process DAG  |              | memory scan  |
| anomalies    |              | signatures   |
+------+-------+              +-------+------+
       |                              |
       +--------------+---------------+
                      |
              +-------v--------+
              | alerts + TUI   |
              +----------------+
```

## Prerequisites

- Linux 5.15 or newer
- Root privileges
- Go 1.22+
- NASM 2.16+
- GCC
- Clang and kernel headers for eBPF mode
- Optional: `golangci-lint` for linting

## Quick Start

```bash
make build
sudo bin/ghosttrace --mode=ebpf
sudo bin/ghosttrace --mode=ebpf --no-tui
```

## Modes

| Mode | Purpose | Risk profile | Notes |
| --- | --- | --- | --- |
| `asm` | Native ring buffer and assembly helper path | High | Kernel patching from user space is rejected safely on hardened Linux. |
| `ebpf` | Tracepoint-based process and memory telemetry | Low | Recommended production mode. |
| `hybrid` | Attempts native hooks, then continues with eBPF | Medium | Useful for controlled research systems. |

## Detection Capabilities

| Detection | Signal |
| --- | --- |
| Process orphaning | Parent PID missing from the live process graph |
| Hollow process behavior | `exec` followed by executable anonymous memory |
| Syscall spikes | Rate exceeds a rolling Welford baseline |
| DKOM suspicion | PID observed in telemetry but missing from `/proc` |
| Timing gaps | Sleep-like syscall gaps followed by burst activity |
| Shellcode signatures | AVX2-assisted scans over executable anonymous mappings |

## Alert Format

```json
{
  "id": "9f9e55ec-3158-4dbf-a158-4381e79b6322",
  "severity": "CRITICAL",
  "type": "SHELLCODE",
  "pid": 4242,
  "comm": "target",
  "detail": "matched cobalt_strike at 0x7f0000001000",
  "score": 91.3,
  "timestamp": "2026-05-27T12:34:56Z",
  "mitigations": ["kill -9 4242", "isolate network interface"]
}
```

## SIEM Integration

Enable the webhook block in `configs/ghosttrace.yaml`. GhostTrace posts each alert as JSON and includes `X-GhostTrace-Signature`, an HMAC-SHA256 over the request body using the configured secret. Verify the HMAC before ingesting the payload into a SIEM.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat_model.md)
- [Install guide](docs/install.md)

## License

Apache 2.0
