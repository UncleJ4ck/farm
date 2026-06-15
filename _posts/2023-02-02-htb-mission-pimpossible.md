---
layout: post
title: "Mission PINpossible (HTB hardware)"
subtitle: "decoding I2C off a logic-analyzer capture to recover the keypad PIN"
date: 2023-02-02
tags: [htb, ctf, hardware, i2c, logic-analyzer]
category: writeups
tldr: "A logic-analyzer capture had two channels carrying I2C (clock and data). I exported the data to CSV, parsed the hex byte values to ASCII with a Python script, then stripped the framing strings to leave the keypad PIN that was the flag."
---

## the challenge

I got a logic capture `op_pinpossible.logicdata` from a security keypad, plus a photo of the device. Two channels were active, and they read as I2C: one clock line, one data line. The keypad pushes its display text over the bus, so the bytes on the wire are the characters it shows. I exported the capture to `data.csv` to work with the decoded values directly.

## analysis

The CSV has a `Data` column of hex byte values from the I2C transfers. The keypad output is built from nibble-paired bytes, so each visible character comes from two consecutive entries: the high nibble of one combined with the high nibble of the next. The capture also carries control bytes that are not characters, so those had to be filtered before pairing. The text that decoded out included the keypad's own UI strings (the password prompt, the access message, and the asterisks masking input). The PIN was buried in that framing text.

## the solve

`csv_to_data.py` reads the `Data` column, filters to the relevant bytes by their low nibble bits, pairs them up, and reconstructs each character from two nibbles:

```python
import sys
import csv
from collections import defaultdict

columns = defaultdict(list)
with open(sys.argv[1]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        for k, v in row.items():
            columns[k].append(v)

data = map(lambda h: int(h, 16), columns["Data"])
data = list(filter(lambda h: ((h & 0x0f) & 0x01) and ((h & 0x0f) & 0x04) and ((h & 0x0f) & 0x08), data))

data = zip(data[::2], data[1::2])
data = map(lambda pair: chr(pair[0] & 0xf0 | (pair[1] >> 4)), data)
print("".join(data))
```

Then I chained the output through `sed` and `tr` to delete the keypad UI strings and whitespace, leaving only the PIN:

```bash
python3 csv_to_data.py data.csv | sed 's/*//g' | sed 's/Enter Password//g' | sed 's/ACCESS GRANDED SYSTEM DISARMED//g' | tr -d ' '
```

## the flag

After scrubbing the prompt text, the asterisks, and the access message, what remained was the PIN, which was the flag in `HTB{...}` form. The keypad leaked its entire input over an unprotected I2C bus, so the flag itself is a note that bad hardware design leads to leaks.
