---
layout: post
title: "Debug Interface (HTB hardware)"
subtitle: "reading the baud rate off a UART capture from its shortest pulse width"
date: 2023-02-02
tags: [htb, ctf, hardware, uart, serial]
category: writeups
tldr: "The capture is an asynchronous serial (UART) signal. The shortest pulse measures 32.02 us, so the bit rate is 1/32.02e-6 = 31230 bit/s. Setting the decoder to roughly 31230 baud decoded the ASCII frames into the flag."
---

## the challenge

I had a captured signal that was asynchronous serial communication, ASCII encoded. Asynchronous serial means there is no shared clock between sender and receiver. Start and stop bits mark the beginning and end of each byte instead. UART is the typical device for this. If the decoder reads bits too fast or too slow relative to the line, you get a frame error and garbage out, so the baud rate has to be right before anything decodes.

## analysis

With no clock line to lock onto, the bit period has to come from the waveform itself. The shortest interval in the capture is one bit wide, since a single bit is the smallest unit the line can hold at a constant level. I measured that shortest pulse at `32.02 us`. The bit rate is just the reciprocal of the bit period:

```
Bit rate (bit/s) = 1 / (32.02 x 10^-6) = 31230.480949406621 = 31230 bit/s
```

So the line runs at about `31230` baud.

## the solve

I set the decoder's baud rate to `31230` and let it re-frame the capture. With the right bit period, the start and stop bits lined up and each byte resolved to a clean ASCII character. The decoded ASCII stream spelled out the flag directly. No scripting beyond pointing the analyzer at the correct rate.

The one measurement that mattered was the shortest pulse width. Everything downstream is the reciprocal and a standard UART decode.

## the flag

The ASCII decode produced the flag in `HTB{...}` form, the kind of string noting that debug interfaces show up in almost every embedded device. Pulling the baud rate off the shortest pulse is the whole trick for an unlabeled async serial dump.
