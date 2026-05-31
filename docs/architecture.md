# Architecture

GhostTrace is organized around a single event pipeline:

1. Native telemetry sources produce fixed 64-byte frames.
2. The Go ring-buffer consumer decodes frames into typed events.
3. The process graph updates parent-child lineage and rolling syscall statistics.
4. The memory scanner inspects executable anonymous mappings for shellcode signatures.
5. Alerting deduplicates, emits webhooks, and feeds the TUI or JSON stdout mode.

The recommended production source is eBPF tracepoints. The assembly and C shim are kept as native helper code for controlled systems and for fast memory scanning; user-space attempts to patch kernel syscall handlers fail closed with explicit errors on hardened Linux.

## Event Frame

Each raw frame is exactly 64 bytes and little-endian encoded. The first two fields are common:

- `uint16 type`
- `uint16 size`

Remaining fields are event-specific and decoded by `internal/events`.
