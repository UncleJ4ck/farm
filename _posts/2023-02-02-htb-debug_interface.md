---
layout: post
title: "Debugging Interface (HTB hardware)"
subtitle: "reading the baud rate off a UART capture from its shortest pulse width"
date: 2023-02-02
tags: [htb, ctf, hardware, uart, serial]
category: writeups
kind: challenge
tldr: "The capture is an asynchronous serial (UART) signal. The shortest pulse measures 32.02 us, so the bit rate is 1/32.02e-6 = 31230 bit/s. Setting the decoder to roughly 31230 baud decoded the ASCII frames into the flag."
---

## the challenge

I got a single file, `debugging_interface_signal.sal`. The `.sal` extension is the Saleae Logic capture format, the file their Logic 2 software writes when you save a recording off a hardware probe. The premise: someone tapped a debug header on a live embedded device while it was running, captured whatever the chip was printing over a serial line, and handed me the recording. My job was to turn that one analog-looking square wave back into the text it carried.

The `.sal` file is not opaque. It is a ZIP container. Renaming it to `.zip` and extracting (the archive password was `hackthebox`) gave two files: `digital-0.bin`, the raw sample buffer for digital channel 0, and `meta.json`, the capture metadata (sample rate, channel map). `digital-0.bin` is one hardware line's logic level over time, sampled at a fixed rate. In practice it is the TX pin of a UART. Loading the original `.sal` straight into Logic 2 is the easier path since it parses both files for me and gives the analyzer UI, so that is what I did.

The signal is asynchronous serial communication, ASCII encoded. Asynchronous means there is no separate clock line shared between the sender and the receiver. The two ends never agree on a clock edge. Instead each transmitted byte is wrapped in framing bits: the line idles high, drops low for one bit period to mark a start, sends the data bits, then returns high for a stop bit. Both sides have to be configured to the same bit period up front, and they sample the middle of each bit on their own internal timer. That is the whole reason UART works over two wires with no clock. The common asynchronous serial protocols built on this idea are RS-232, RS-485, and RS-422, and a UART (Universal Asynchronous Receiver/Transmitter) is the device that frames the bytes this way.

The catch with that design is the receiver only decodes correctly if its assumed bit period matches the line. Read the bits too fast and you sample one bit twice; too slow and you skip past bits. Either way the start and stop bits fall in the wrong place, the decoder throws a framing error, and you get garbage bytes out. A framing error is exactly that: a bit sent too fast or too slow relative to what the receiver expects, so the frame fails to line up. So before anything decoded to readable ASCII, I had to recover the exact baud rate the device transmitted at. The capture came with no label for it.

## analysis

With no clock line to lock onto, the bit period has to come out of the waveform itself. The key fact about a UART line: the narrowest pulse it can ever produce is exactly one bit wide. A run of identical bits (say four 1s in a row) holds the line at one level for four bit periods, so it shows up as one wide pulse. But the moment a bit flips, the line transitions, and the shortest stretch the line ever stays constant is a single bit. So if I find the narrowest high-or-low interval anywhere in the whole capture, that width is one bit period.

I zoomed into the start of the transmission in Logic 2 and hovered over the very first narrow pulse I could find. The measurement tooltip read `32.02 us`. That is the bit period, the time the line holds one bit.

Baud rate (here equal to the bit rate, since UART sends one bit per symbol) is the reciprocal of the bit period. Baud is the symbol rate; bit rate is the number of bits transmitted per second; for this line the two are the same number. Saleae wants the rate entered in bits per second, not microseconds, so I converted the period from microseconds and inverted it:

```
bit rate (bit/s) = 1 / (32.02 x 10^-6 s)
                 = 1,000,000 / 32.02
                 = 31,230.480949406621
                 ~ 31,230 bit/s
```

So the line runs at roughly `31230` baud. That is not a standard rate (the common ones are `9600`, `19200`, `38400`, `115200`), which is exactly why the default decoder produced nothing. The number sits nowhere near anything on the standard list, so guessing would not have landed it. Measuring the pulse was the only way in.

## the solve

In Logic 2 I opened the Analyzers panel and added an `Async Serial` analyzer bound to `Channel 0`. The default bit rate is `9600`, and at `9600` against a `31230` line the decoder was sampling far too slowly. Every frame tripped a framing error and the output was a wall of red error markers and meaningless bytes.

I edited the analyzer and set the bit rate to `31230`. I also set the display format to `ASCII` so the decoded bytes rendered as characters instead of hex. The rest of the framing I left at the standard UART defaults, which matched the capture:

- bits per frame: `8`
- parity: `none`
- stop bits: `1`
- significant bit: least-significant first
- signal: non-inverted (idle high)

With the bit period now correct, the analyzer's sampling points landed in the center of each real bit. The start and stop bits lined up, the framing errors cleared, and every byte resolved to one clean ASCII character. The decoded bytes appeared inline on the waveform as little annotation bubbles.

To read the message as a continuous string rather than per-byte bubbles, I opened the `Terminal` view, which concatenates the decoded ASCII output of the analyzer into a flat text stream. The device had been printing its debug banner over the line, and the flag was sitting in that text in plain `HTB{...}` form. No scripting, no carving, no post-processing. The entire solve was one measurement and two analyzer settings: the bit rate and the ASCII display format.

The one number that mattered was the shortest pulse width, `32.02 us`. Everything downstream of it is the reciprocal and a stock UART decode. Get the bit period right and the line reads itself.

## the flag

The terminal output spelled the flag out directly:

```text
HTB{d38u991n9_1n732f4c35_c4n_83_f0und_1n_41m057_3v32y_3m83dd3d_d3v1c3!!52}
```

Its own text makes the point: a debug interface like this shows up on nearly every embedded device, an open serial header that prints internal state to anyone with a probe. Pulling the baud rate off the single narrowest pulse is the whole trick for decoding an unlabeled async serial dump.
