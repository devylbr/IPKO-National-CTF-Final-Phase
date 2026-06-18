# GlassMaze

**Category:** Rev  
**Challenge Description:**

A trinket from a shuttered workshop. Boot it and it proudly declares victory — but the glass maze guards its real secret far more carefully.

Flag: `KOS{A1371A4226DEF43114553185A00EC746}`

## Analysis

Mach-O arm64 binary. Running it immediately prints:

```
YOU WIN! FLAG: KOS{MAZE_WINNER_SCREEN_IS_ALWAYS_FALSE}
```

That string comes from `_win_screen_lie` — a function that unconditionally prints a fake winner screen. The real flag is stored as a **UTF-16 LE** string in the `_glass_blob` section and is never printed at runtime.

Submitting the winner screen flag would lose points.

## Solution

1. Recognize the printed flag is from `_win_screen_lie` and is a decoy.
2. Search the binary for a UTF-16 LE `KOS{` pattern (`4b 00 4f 00 53 00 7b 00`).
3. Decode the bytes from `_glass_blob`.

```python
data = open('glass', 'rb').read()

marker = bytes.fromhex('4b004f0053007b00')
idx = data.find(marker)
end = data.index(b'\x7d\x00', idx)
flag = data[idx:end+2].decode('utf-16-le')
print(flag)
```
