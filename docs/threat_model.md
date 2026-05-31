# Threat Model

GhostTrace detects behaviors commonly associated with process injection, user-space shellcode, and process hiding:

- executable anonymous mappings after an `exec`
- suspicious shellcode byte patterns
- syscall bursts after timing gaps
- telemetry-observed PIDs missing from `/proc`
- orphaned or reparented process lineage

## In Scope

- Linux hosts where GhostTrace runs as root
- Local process telemetry through eBPF tracepoints
- Scanning readable executable anonymous mappings
- Alert delivery to local TUI, stdout, and HTTP webhooks

## Out of Scope

- Prevention or sandboxing
- Kernel memory patching on locked-down production kernels
- Bypasses by attackers with equal or greater kernel privileges
- Guaranteed detection of polymorphic payloads without behavioral signals

## Trust Boundaries

Webhook receivers must verify the HMAC signature and treat alert payloads as untrusted input. Process names, paths, and command data come from the host and can be attacker-controlled.
