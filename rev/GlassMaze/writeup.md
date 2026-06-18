---
title: "GlassMaze"
ctf: "Kosovo Cyber CTF"
date: 2026-06-17
category: reverse
difficulty: medium
points: ~
flag_format: "KOS{...}"
author: "ylbadev"
---

# GlassMaze

## Summary

A reverse engineering challenge with a Mach-O arm64 binary. Running it prints `YOU WIN! FLAG: KOS{MAZE_WINNER_SCREEN_IS_ALWAYS_FALSE}` — that's the decoy (`_win_screen_lie`). The real flag is stored as a UTF-16 LE string in the `_glass_blob` section and is never printed at runtime.

## Solution

### Step 1: Run and observe the decoy

```bash
./glass
# YOU WIN! FLAG: KOS{MAZE_WINNER_SCREEN_IS_ALWAYS_FALSE}
```

The binary is a Mach-O arm64 — can't execute on Linux, so static analysis is required.

### Step 2: Extract the real flag from `_glass_blob`

The real flag is stored as UTF-16 LE in the `_glass_blob` section. Extract and decode:

```python
import subprocess, re

# Dump the binary as hex
data = open('glass', 'rb').read()

# Search for UTF-16 LE KOS{ pattern: 4b 00 4f 00 53 00 7b 00
marker = bytes.fromhex('4b004f0053007b00')
idx = data.find(marker)
end = data.index(b'\x7d\x00', idx)  # find } in UTF-16
raw = data[idx:end+2]

# Decode UTF-16 LE
flag = raw.decode('utf-16-le')
print(flag)  # KOS{A1371A4226DEF43114553185A00EC746}
```

The function `_win_screen_lie` unconditionally prints the fake winner flag; `_glass_blob` contains the real secret that the maze "guards carefully."

## Flag

```
KOS{A1371A4226DEF43114553185A00EC746}
```
