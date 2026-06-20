---
layout: post
title: "Mission PINpossible (HTB hardware)"
subtitle: "decoding I2C off a logic-analyzer capture to recover the keypad PIN"
date: 2023-02-02
tags: [htb, ctf, hardware, i2c, logic-analyzer]
category: writeups
kind: challenge
tldr: "A logic-analyzer capture had two channels carrying I2C (clock and data). I exported the data to CSV, parsed the hex byte values to ASCII with a Python script, then stripped the framing strings to leave the keypad PIN that was the flag."
---

## the challenge

I got two files: a logic capture, `op_pinpossible.logicdata`, and a photo of the device it came off, `security_keypad.jpeg`. The `.logicdata` extension is the older Saleae Logic 1 capture format. The photo did the work of telling me what I was looking at before I touched the capture.

The photo showed a security keypad cracked open. The front was a `16x2` character LCD (a QAPASS-branded `1602` module) printing `Enter Password`. The back showed the LCD soldered to a small I2C backpack daughterboard and the whole thing wired to an Arduino over four lines. That backpack is the standard `PCF8574T`, an 8-bit I2C I/O expander. Nobody drives a parallel HD44780 LCD with eight-plus GPIO when they can hang it off two I2C wires through a `PCF8574T` instead, so seeing the backpack told me exactly which two signals were on the capture and how the bytes would be framed. I2C is a synchronous two-wire bus: one data line (SDA) and one clock line (SCL), with every transaction addressed to a device on the bus.

Opening `op_pinpossible.logicdata` in Saleae Logic showed two active channels. Channel 0 was SDA (the I2C data line) and channel 1 was SCL (the I2C clock). I added the I2C analyzer across those two channels and it decoded cleanly. Every transaction was a write to address `0x4E`. That is the 8-bit form of the classic `PCF8574T` address `0x27` (`0x27 << 1 = 0x4E`, with the low bit being the read/write flag). So every byte on the bus was the microcontroller writing to the LCD's expander. The keypad pushes its display text out over that bus, which means the bytes on the wire reconstruct exactly what the screen showed, including whatever the user typed. I set the analyzer's display radix to hex and exported the decoded transactions to `data.csv` to process the byte values directly instead of squinting at the waveform.

## analysis

The export gave a CSV with columns `Time [s]`, `Packet ID`, `Address`, `Data`, `Read/Write`, `ACK/NAK`. Every row is one byte written to `0x4E`, every one a `Write` that the LCD `ACK`ed. The `Data` column is the payload, in hex. The file held `8424` data rows. The first handful look like this:

```text
Time [s],Packet ID,Address,Data,Read/Write,ACK/NAK
0.448499000000000,0,0x4E,0x08,Write,ACK
0.448728500000000,1,0x4E,0x0C,Write,ACK
0.448958500000000,2,0x4E,0x08,Write,ACK
0.449248000000000,3,0x4E,0x18,Write,ACK
0.449478000000000,4,0x4E,0x1C,Write,ACK
0.449707500000000,5,0x4E,0x18,Write,ACK
0.452084500000000,6,0x4E,0x88,Write,ACK
0.452314500000000,7,0x4E,0x8C,Write,ACK
0.452544000000000,8,0x4E,0x88,Write,ACK
```

That pattern (`0x08`, `0x0C`, `0x08`, then `0x18`, `0x1C`, `0x18`) is the whole decoding problem in miniature, and it reads straight off the backpack wiring.

The decoding turns on how a `PCF8574T` backpack drives an HD44780 LCD. The expander has only 8 output pins, and the LCD needs more than that for a full parallel interface, so the backpack runs the LCD in 4-bit mode. The 8 expander bits are wired like this:

- bits 7-4 (the high nibble): the four LCD data lines `D7..D4`
- bit 3: backlight enable
- bit 2: `EN`, the enable strobe that latches data into the LCD
- bit 1: `RW`, read/write select
- bit 0: `RS`, register select (0 = command, 1 = character data)

Reading the low nibble of those first bytes against that map: `0x08` is backlight on, everything else low (an idle/setup write). `0x0C` is backlight plus `EN` high (`0b1100`), the strobe asserted. `0x18` is backlight plus `RS` high with the data nibble `0x1` up top, and `0x1C` adds `EN` to it. So a real character write looks like `0x?D` where `RS`, `EN`, and backlight bits are all set.

Because the LCD is in 4-bit mode, each displayed character is sent as two writes: the high nibble of the character first, then the low nibble, each one shifted into the top four bits of an expander byte. And because the LCD latches on the falling edge of `EN`, the controller writes each nibble two or three times in a row: once with `EN` low to set up the data, once with `EN` high, then `EN` low again to strobe it in. Those repeats are why the raw byte stream looks redundant.

So to rebuild a character I needed to (1) throw away the command writes and the `EN`-low setup/strobe writes, keeping only the writes that carry real character data with the strobe asserted, and (2) take two surviving writes at a time and glue their high nibbles back together into one byte.

The filter keys off the low nibble (the control bits). The script keeps a byte only if, in its low nibble, the bits for `RS` (0x01), `EN` (0x04), and backlight (0x08) are all set. That selects the character-data writes that have the enable strobe high, which is the one copy of each nibble I want, and drops the command writes and the strobe-low duplicates. After that filter, `8424` bytes collapsed to `2580`, which pair into `1290` characters.

The text those characters spell is the keypad's full UI as it animated on screen: the `Enter Password` prompt, an asterisk appended for every key press to mask the input, and finally the `ACCESS GRANDED SYSTEM DISARMED` message (the typo is the firmware's, not mine). The PIN itself was not masked on the bus. Each real keypress wrote the actual character to the LCD's controller one moment before the firmware overwrote that cell with an asterisk, so the true digits were interleaved through the framing text. The masking only ever happened on glass, never on the wire.

## the solve

`csv_to_data.py` reads the `Data` column, applies the low-nibble filter, pairs the survivors, and reassembles each character from two nibbles (high nibble of the first byte ORed with the high nibble of the second, shifted down):

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

Note this is Python 2 style: `data[::2]` slicing a `zip` and indexing a `filter` only works if those are lists, so I ran it under an interpreter where `map`/`filter`/`zip` return lists, or wrapped them in `list(...)`. The math is the part that matters: `pair[0] & 0xf0` keeps the high nibble of the first write (the character's high nibble) and `pair[1] >> 4` shifts the second write's high nibble down into the low position, and ORing them rebuilds the full 8-bit character.

Running it dumped the reconstructed display history, `1290` characters. Reading it shows the screen redrawing on every keypress: it reprints `Enter Password`, then the growing run of asterisks, and the next real PIN character riding along just before the mask catches up:

```text
 Enter PasswordH Enter Password*T Enter Password**B Enter Password***{ Enter Password****8 Enter Password*****4 Enter Password******d Enter Password*******_ Enter Password********d Enter Password*********3 Enter Password**********5 Enter Password***********1 Enter Password************9 Enter Password*************n Enter Password**************_ Enter Password***************c ... Enter Password************************************   ACCESS GRANDED SYSTEM DISARMED
```

The flag characters are the lone non-asterisk bytes that appear right after each `Enter Password` redraw: `H`, `T`, `B`, `{`, `8`, `4`, `d`, `_`, `d`, `3`, `5`, `1`, `9`, `n`, ... in order. To pull just those out, I chained the script through `sed` to delete the three UI strings (the asterisks, the `Enter Password` prompt, and the access message) and `tr` to strip the spaces, leaving only the leaked characters concatenated:

```bash
python3 csv_to_data.py data.csv | sed 's/*//g' | sed 's/Enter Password//g' | sed 's/ACCESS GRANDED SYSTEM DISARMED//g' | tr -d ' '
```

That printed the flag on a single line, the PIN that the keypad had typed onto its own LCD over an I2C bus with no protection at all:

```text
HTB{84d_d3519n_c4n_134d_70_134k5!d@}
```

## the flag

After scrubbing the prompt, the asterisks, and the access banner, what was left was the PIN itself, the flag in `HTB{...}` form. Its own text says it plainly: bad design leads to leaks. The keypad masked the PIN visually with asterisks but shipped the real digits in the clear over a two-wire bus that any probe could read. The masking was theater. The bytes never lied.
