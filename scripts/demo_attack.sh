#!/usr/bin/env bash
set -euo pipefail

echo "Starting a benign GhostTrace detection exercise."
echo "This script does not automate Meterpreter or cross-process migration."

python3 - <<'PY'
import ctypes
import mmap
import os
import time

signature = b"\x90" * 16 + b"\x0f\x05" + b"/bin/sh\x00"
buf = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
buf.write(signature)
addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
print(f"PID={os.getpid()} executable anonymous mapping=0x{addr:x}")
print("GhostTrace should detect this benign signature in the next scan interval.")
try:
    time.sleep(30)
finally:
    buf.close()
PY
