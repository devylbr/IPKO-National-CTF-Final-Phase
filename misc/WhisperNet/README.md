# WhisperNet

**Category:** Misc  
**Challenge Description:**

Signals travel in whispers. The network is alive, but the truth is buried under noise. Find the real message.

Flag: `KOS{521A3123054D581E64FE361F76B9E3C4}`

## Analysis

The service has three bait endpoints designed to waste submission points:

- `KOS{html_comment_is_a_decoy}` — buried in the HTML source comment
- `KOS{otp_key_is_a_decoy}` — from the `/otp` endpoint
- `KOS{frequency_analysis_is_a_decoy}` — from `/freq-analysis`

The real flag is hidden in the `ETag` response header of the `/broadcast` endpoint, encoded through a 4-layer chain: `base64 → rot13 → morse → hex → ASCII`.

## Solution

1. Ignore the obvious decoy endpoints.
2. Hit `/broadcast` and read the `ETag` header.
3. Apply the decode chain.

```python
import requests, base64, codecs

BASE = 'http://ctf.kosovacyber.team:7001'

resp = requests.get(f'{BASE}/broadcast')
etag = resp.headers['ETag'].strip('"')

b64_decoded = base64.b64decode(etag).decode()
rot13_decoded = codecs.decode(b64_decoded, 'rot_13')

MORSE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
    '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
    '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
    '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
    '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2',
    '...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
    '---..':'8','----.':'9',
}
morse_decoded = ''.join(MORSE.get(c, c) for c in rot13_decoded.split())
flag = bytes.fromhex(morse_decoded).decode()
print(flag)
```
