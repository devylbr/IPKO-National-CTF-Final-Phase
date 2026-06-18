# IronSeal

**Category:** Crypto  
**Challenge Description:**

The Guild of Notaries stamps every charter with the same iron signet and swears the process is unbreakable. One sealed charter is all we recovered — read what it says.

Flag: `KOS{E42DC17308226393C7C99ADFAA2C7F8E}`

## Analysis

The service exposes three endpoints that bait you into losing points:

- `KOS{html_comment_is_a_decoy}` — buried in the HTML source comment
- `KOS{security_page_is_a_decoy}` — from the `/security` bulletin endpoint
- `KOS{key_rotation_is_a_decoy}` — from `/keys/rotate`

The real flag is in a sealed charter retrieved from `/seal` (ciphertext + HMAC). The "unbreakable" claim is the hint: the same iron signet (symmetric key) both seals and verifies. Sending the server's own ciphertext back to `/verify` makes it decrypt with its own key and return the plaintext — which contains the flag.

## Solution

1. Identify and ignore the three decoy endpoints.
2. `GET /seal` to retrieve the encrypted charter.
3. `POST /verify` with the same ciphertext and HMAC — the server decrypts it for you.

```python
import requests

BASE = 'http://ctf.kosovacyber.team:7003'

seal = requests.get(f'{BASE}/seal').json()

result = requests.post(f'{BASE}/verify', json={
    'ciphertext': seal['ciphertext'],
    'hmac': seal['hmac']
}).json()

print(result)
```
