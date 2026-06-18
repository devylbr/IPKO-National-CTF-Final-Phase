# The Gatekeeper

**Category:** Rev  
**Challenge Description:**

Mind games. The gate has many faces, but only one is real. Don't let the decoys take your points.

Flag: `KOS{824051215ED94D74B5496A7A51ACE06F}`

## Analysis

Stripped ELF64 x86-64 binary with three `KOS{}` strings — only one is the real flag:

- `KOS{23547200B42540DEF60B2DF89B26B090}` — dead code behind `cmp argc,0; jns`, never reached
- `KOS{LEGACY_GATE_ARRAY_ACCEPTED}` — decoy path, triggered by a trivial `17*k XOR` input check (submitting loses points)
- **Real flag** — decoded at runtime from 37 encrypted bytes at `0x402040` via a 6-round key schedule cipher, only when the correct 32-char hex token is supplied

**Cipher (`fcn.004012c3`):** 6 rounds, each iterating `k=0..15`:
```
key[k] = rol8((rconst[j*16+k] + key[k]) & 0xff, (k+j)%7+1) ^ xorconst[j]
```
Then permuted via `[0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]`.

The valid token is `7ad3c0de91fe44aa13b857602cc519ef` (the 16-byte key hex-encoded).

**Decode formula (`fcn.004014e8`):**
```
decoded[i] = ((13*i - 89) & 0xff) ^ encrypted[i] ^ key[i & 0xf]
```

## Solution

1. Identify all three `KOS{}` candidates through static analysis.
2. Recognize the dead code path and the trivial decoy path.
3. Reverse the 6-round cipher to recover the key, then decode the 37 encrypted bytes.

```python
encrypted = bytes.fromhex("...")  # 37 bytes at 0x402040 in the binary
key = bytes.fromhex("7ad3c0de91fe44aa13b857602cc519ef")

flag = ""
for i in range(37):
    flag += chr(((13 * i - 89) & 0xff) ^ encrypted[i] ^ key[i & 0xf])
print(flag)
```
