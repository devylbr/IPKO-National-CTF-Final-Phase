# Broadcast

**Category:** Misc  
**Challenge Description:**

A forgotten relay woke up for one clean burst, then disappeared into static. The capture is yours. There might be fake flags — find the real one.

Flag: `KOS{A78CC1C88AB568ADEAB83D58ACE436F8}`

## Analysis

The PCAP has 3 frames:

- **Frames 1 & 2** — Identical 72-byte binary blobs (noise/static). XOR attempts and encoding checks yield nothing useful.
- **Frame 3** — Contains a `leaked_flag` field tagged `internal-debug-do-not-ship`.

The `internal-debug-do-not-ship` label is the narrative device, not a disqualifier. The relay was in debug mode and accidentally broadcast diagnostic data containing the real flag.

## Solution

1. Open the capture and inspect all frames.
2. Frames 1 and 2 are noise — skip them.
3. Frame 3 contains the `KOS{}` flag as plaintext in the payload marked as an internal debug leak.

```python
from scapy.all import rdpcap

pkts = rdpcap("broadcast.pcap")
data = bytes(pkts[2])
idx = data.find(b"KOS{")
print(data[idx : data.index(b"}", idx) + 1].decode())
```
