# Digitakt II firmware research

Tooling for understanding and (eventually) patching Elektron Digitakt II OS
images. **No Elektron firmware is included in this repository and none ever
should be** — it is copyright Elektron. You supply your own lawfully-obtained
`.syx`; `.gitignore` is set up to keep it out of git.

Target: `Digitakt_II_OS1.15C.syx`,
SHA-256 `62d588456e47194bd56dfee9568fb9dd4521c4ff1e8b5427eb461355532e8c6c`.
Addresses throughout are for that build only.

## What the hardware is

Not ARM. Two processors:

| | Part | Notes |
|---|---|---|
| Control | Freescale **ColdFire MCF54415** | 68k-family ISA, **big-endian**. Runs UI, sequencer, files, MIDI. C++ codebase. |
| Audio | Analog Devices **ADSP-21569** SHARC+ | FreeRTOS. Shipped as ADI loader records. |

MAIN OS does not make sound — it holds parameter state and RPCs it to the
SHARC. That split governs what is and isn't patchable.

## Layout

```
dt2/container.py   .syx -> 8-in-7 decode -> ELE3 container + section table
dt2/coldfire.py    ColdFire-aware disassembly (Capstone misses MVS/MVZ and FF1)
emu/harness.py     Unicorn m68k machine; works around four Unicorn/ColdFire gaps
emu/oracle.py      Runs the DEVICE'S OWN validators against a candidate image
emu/boot.py        Full-boot experiment (see docs/FINDINGS.md for how far it gets)
docs/FINDINGS.md   Everything established, with evidence and open questions
```

## Setup

```sh
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
```

Extract sections into `sections/` using
[mischa85/elektron-firmware-tool](https://github.com/mischa85/elektron-firmware-tool)
(MIT), which supports device `0x14` = Digitakt II:

```sh
elektron-firmware-tool -i Digitakt_II_OS1.15C.syx -o sections/
```

## Use

```sh
./venv/bin/python -m dt2.container Digitakt_II_OS1.15C.syx     # section table
./venv/bin/python emu/oracle.py                                # oracle self-test
./venv/bin/python dt2/coldfire.py sections/section_2_DSP.bin 0x800003fc 0x80001c48 0x80001c80
```

## The acceptance oracle

The bootstrap decides whether to accept an OS image using a few self-contained
routines. Emulating them turns "will the device take this?" from a hardware
experiment into a unit test. Two are implemented and verified byte-exact:

- **CRC-32** `0x80001bd0` — poly `0xEDB88320`, residue `0xDEBB20E3`
- **aPLib depacker** `0x80000432` — decompresses a rebuilt image *using the
  device's own code*. Confirms a repacked stream is acceptable without hardware.

Still to add: the content checksum at `0x40003ca6` and the HMAC-SHA256 trailer
check at `0x80005e2a`. Together those are the bootstrap's entire accept/reject
decision.

## Safety

Established by static analysis and emulation, not by flashing anything:

- The **recovery path** is the bootstrap's STARTUP menu (hold FUNC at power-on),
  independent of MAIN OS, accepting SysEx over **MIDI DIN only** — not USB.
- The only irreversible operation is **BOOTSTRAP UPGRADE**, gated at
  `0x80001c72` by `bcc` — it runs only when the incoming bootstrap version is
  *strictly greater* than the running one (`0x0200` in 1.15C). Patching sections
  3/7 never presents a higher version, so that step is unreachable.
- **Never modify sections 2 (bootstrap) or 4 (updater).** A patcher should
  hard-fail on any patch targeting them.

Read `docs/FINDINGS.md` before flashing anything.

## Licence and attribution

Original work here is MIT. Not affiliated with or endorsed by Elektron.
Container format knowledge derives from `mischa85/elektron-firmware-tool` (MIT);
architecture and memory-map facts marked *Documented* in FINDINGS.md derive from
`lalzart/digitakt-ii-firmware-research-public`.
