---
title: "Broadcast"
ctf: "Kosovo Cyber CTF"
date: 2026-06-17
category: misc
difficulty: easy
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# Broadcast

## Summary

A PCAP capture from a forgotten relay that briefly broadcast diagnostic data before going silent. The flag was embedded in Frame 3 as plaintext, disguised with a `internal-debug-do-not-ship` label intended to look like a decoy.

## Solution

### Step 1: Analyze the capture

```bash
tshark -r broadcast.pcap -x
```

The capture has 3 frames:
- **Frames 1 & 2** — Identical 72-byte binary blobs (noise/static). No XOR key or encoding reveals a flag.
- **Frame 3** — Contains a `leaked_flag` field labeled `internal-debug-do-not-ship`.

### Step 2: Extract the flag

The label `internal-debug-do-not-ship` is the narrative device, not a disqualifier. The relay was in debug mode and accidentally broadcast diagnostic info — the flag is exactly what's in Frame 3.

```python
from scapy.all import rdpcap

pkts = rdpcap("broadcast.pcap")
data = bytes(pkts[2])
# Flag appears as plaintext in the payload
idx = data.find(b"KOS{")
print(data[idx:data.index(b"}", idx)+1].decode())
```

## Flag

```
KOS{A78CC1C88AB568ADEAB83D58ACE436F8}
```
