# Patches

Two diffs against [Unicorn Engine](https://github.com/unicorn-engine/unicorn)
2.1.4, tag commit `8028ec436f2d9376525352dd38ed9ed6b9f6be10`, applied in this
order:

- `unicorn-2.1.4-m68k-hook-ccr-sync.patch` touches
  `qemu/target/m68k/translate.c` and `qemu/target/m68k/unicorn.c`.
- `unicorn-2.1.4-m68k-emac-mac-load.patch` touches
  `qemu/target/m68k/translate.c`.

Both files are QEMU sources vendored inside Unicorn. **The patches are
derivative works of that code and carry its licence, not this repository's
choice of one** — take their terms from Unicorn and QEMU upstream. This is why
the repository as a whole is GPL-2.0-or-later rather than something
permissive; see the licence section of the top-level [README](../README.md).

## What the CCR patch fixes

Unicorn's m68k translator keeps condition codes lazily and commits them when a
translation block ends normally. A code hook, or a `count=` stop, can return to
the host *mid-block*, before that commit — so a guest `CMP` followed by a
hook-visible `SR` read, or by a counted stop on the next instruction, exposes
stale flags. Guest branches then take the wrong arm.

The patch commits the pending condition codes before handing control back.

## What the EMAC patch fixes

`DISAS_INSN(mac)` handles MAC and MSAC with load (ColdFire Programmer's
Reference Manual, p.6-3 to 6-5 and p.6-22 to 6-23) wrongly in four ways.
QEMU master had the same code on 2026-09-15.

- It takes extension-word bits 1..0 as a dual-accumulate request and, on a
  core without EMAC_B such as the CFV4E, raises an illegal-instruction
  exception. In the load forms those bits are part of Ry, so every Ry whose
  register number has bit 0 or 1 set faulted. The patch honours the request
  only on EMAC_B cores.
- It reads a data-register Rx from operation-word bits 14..12, which are
  always 2 for these opcodes, so Rx was always D2. Rx is extension-word bits
  15..12.
- It reads the MSAC bit from operation-word bit 8, which is always 0 for
  these opcodes, so MSAC added. The bit is extension-word bit 8. This also
  affects MSAC without load.
- It ANDs MASK into every load address. Extension-word bit 5 says whether
  MASK is used.

The Digitakt II SHARC frame build reaches one of these instructions at
`0x400db9e0`.

## Checks

`emu/unicorn_compat.py` exercises the CCR shapes and the `0x400db9e0`
instruction, and refuses to run on an interpreter whose Unicorn lacks either
patch, rather than letting a subtly wrong emulation pass for a working one.
`tests/test_unicorn_emac.py` checks the MAC and MSAC load forms against the
manual.

## Applying them

Do not apply these by hand. `tools/install-patched-unicorn.sh` pins the
upstream commit, verifies each patch's SHA-256, builds only the m68k target,
replaces the dynamic library the Python bindings actually load, and then runs
the compat check. `uv sync` can restore the stock wheel, which puts the
emulator back to refusing to start until the installer is rerun.
