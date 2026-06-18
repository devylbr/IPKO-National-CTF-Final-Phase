---
title: "The Gatekeeper"
ctf: "Kosovo Cyber CTF (kosovacyber.team)"
date: 2026-06-17
category: reverse
difficulty: hard
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# The Gatekeeper

## Summary

A stripped ELF64 binary with three KOS{} strings: one in dead code (never reached), one behind a trivially-bypassed check (decoy path), and the real flag decoded from 37 encrypted bytes using a 6-round key schedule cipher when the correct 32-char hex token is provided.

## Solution

### Step 1: Identify the three flag candidates

- `KOS{23547200B42540DEF60B2DF89B26B090}` — dead code behind `cmp argc,0; jns`, always skipped
- `KOS{LEGACY_GATE_ARRAY_ACCEPTED}` — decoy path, trivially reachable via a `17*k XOR` input transform (submitting it loses points)
- Real flag — decoded at runtime from 37 encrypted bytes at `0x402040` when the 6-round cipher check passes

### Step 2: Reverse the 6-round cipher (`fcn.004012c3`)

Each round `j` iterates `k=0..15`:
```
key[k] = rol8((rconst[j*16+k] + key[k]) & 0xff, (k+j)%7+1) ^ xorconst[j]
```
Then permute via `perm = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]`.

The input token `7ad3c0de91fe44aa13b857602cc519ef` (the 16-byte key hex-encoded) passes all 6 rounds.

### Step 3: Decode the flag (`fcn.004014e8`)

```python
encrypted = bytes.fromhex("...")  # 37 bytes at 0x402040
key = bytes.fromhex("7ad3c0de91fe44aa13b857602cc519ef")

flag = ""
for i in range(37):
    flag += chr(((13*i - 89) & 0xff) ^ encrypted[i] ^ key[i & 0xf])
print(flag)  # KOS{824051215ED94D74B5496A7A51ACE06F}
```

## Flag

```
KOS{824051215ED94D74B5496A7A51ACE06F}
```
