# Patches

`unicorn-2.1.4-m68k-hook-ccr-sync.patch` is a diff against
[Unicorn Engine](https://github.com/unicorn-engine/unicorn) 2.1.4, tag commit
`8028ec436f2d9376525352dd38ed9ed6b9f6be10`. It touches two files:

- `qemu/target/m68k/translate.c`
- `qemu/target/m68k/unicorn.c`

Both are QEMU sources vendored inside Unicorn. **The patch is a derivative work
of that code and carries its licence, not this repository's choice of one** —
take its terms from Unicorn and QEMU upstream. This is why the repository as a
whole is GPL-2.0-or-later rather than something permissive; see the licence
section of the top-level [README](../README.md).

## What it fixes

Unicorn's m68k translator keeps condition codes lazily and commits them when a
translation block ends normally. A code hook, or a `count=` stop, can return to
the host *mid-block*, before that commit — so a guest `CMP` followed by a
hook-visible `SR` read, or by a counted stop on the next instruction, exposes
stale flags. Guest branches then take the wrong arm.

The patch commits the pending condition codes before handing control back.
`emu/unicorn_compat.py` is the check: it exercises both shapes and refuses to
run on an interpreter whose Unicorn has not been patched, rather than letting a
subtly wrong emulation pass for a working one.

## Applying it

Do not apply this by hand. `tools/install-patched-unicorn.sh` pins the upstream
commit, verifies the patch's SHA-256, builds only the m68k target, replaces the
dynamic library the Python bindings actually load, and then runs the compat
check. `uv sync` can restore the stock wheel, which puts the emulator back to
refusing to start until the installer is rerun.
