---
title: "IronSeal"
ctf: "Kosovo Cyber CTF"
date: 2026-06-17
category: crypto
difficulty: medium
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# IronSeal

## Summary

A web crypto challenge where "The Guild of Notaries" encrypts charters with a shared iron signet. Three decoy flags are planted at obvious endpoints. The real flag is recovered by sending the server's own ciphertext back to the `/verify` endpoint, which decrypts and returns the plaintext.

## Solution

### Step 1: Find and discard decoys

Three endpoints return decoy flags designed to cost submission points:
- `KOS{html_comment_is_a_decoy}` — HTML source comment
- `KOS{security_page_is_a_decoy}` — `/security` bulletin
- `KOS{key_rotation_is_a_decoy}` — `/keys/rotate` response

### Step 2: Exploit the verify oracle

```python
import requests

BASE = 'http://ctf.kosovacyber.team:7003'

# Step 1: get the sealed charter (ciphertext + HMAC)
seal = requests.get(f'{BASE}/seal').json()
ciphertext = seal['ciphertext']
hmac = seal['hmac']

# Step 2: POST ciphertext back to /verify — server decrypts with its own key
result = requests.post(f'{BASE}/verify', json={
    'ciphertext': ciphertext,
    'hmac': hmac
}).json()

print(result)  # plaintext contains KOS{E42DC17308226393C7C99ADFAA2C7F8E}
```

The "unbreakable process" was symmetric: the same key seals and verifies, so submitting the server's own ciphertext returns the plaintext directly, which contains the flag.

## Flag

```
KOS{E42DC17308226393C7C99ADFAA2C7F8E}
```
