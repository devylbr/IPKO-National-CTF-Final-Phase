---
title: "WhisperNet"
ctf: "Kosovo Cyber CTF"
date: 2026-06-17
category: misc
difficulty: medium
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# WhisperNet

## Summary

A web misc challenge with three obvious decoy endpoints and a hidden 4-layer decode chain in the `ETag` response header of the `/broadcast` endpoint. The real flag requires chaining: base64 → rot13 → morse (dots/dashes) → hex → ASCII.

## Solution

### Step 1: Identify and skip the decoys

Three endpoints return flags that subtract points:
- `KOS{html_comment_is_a_decoy}` — hidden in HTML source
- `KOS{otp_key_is_a_decoy}` — from `/otp`
- `KOS{frequency_analysis_is_a_decoy}` — from `/freq-analysis`

### Step 2: Decode the ETag chain

```python
import requests, base64, codecs

BASE = 'http://ctf.kosovacyber.team:7001'

# Step 1: fetch ETag from /broadcast
resp = requests.get(f'{BASE}/broadcast')
etag = resp.headers['ETag'].strip('"')

# Step 2: base64 decode
b64_decoded = base64.b64decode(etag).decode()

# Step 3: rot13
rot13_decoded = codecs.decode(b64_decoded, 'rot_13')

# Step 4: morse decode (. = dot, - = dash, spaces separate chars)
MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
}
morse_decoded = ''.join(MORSE.get(c, c) for c in rot13_decoded.split())

# Step 5: hex decode
flag = bytes.fromhex(morse_decoded).decode()
print(flag)  # KOS{521A3123054D581E64FE361F76B9E3C4}
```

## Flag

```
KOS{521A3123054D581E64FE361F76B9E3C4}
```
