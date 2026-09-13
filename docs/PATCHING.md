# Patching MAIN OS: what works, and how

Verified end to end in the emulator. Getting a patched image onto hardware
additionally needs the container repacked, which is not built yet.

## The rules

MAIN OS is position-dependent ColdFire code full of absolute addresses, so
**bytes may be replaced, never inserted or deleted**. `tools/patchimg.py`
enforces that, and also refuses any patch whose expected original bytes are
not present -- a patch landing on the wrong address usually still boots and
is wrong in a way no test catches.

Addresses are guest load addresses (base `0x40000400`), which is what Ghidra
and `emu/symbols.py` report.

## Free space

The tail of each image is zero-filled padding running exactly to the end of
the image -- linker padding to a block boundary:

    Digitakt II 1.15C   0x402f9c14   58,188 bytes
    Digitone II 1.10E   0x402e1bf4   64,908 bytes

Measured free at runtime, not just in the file: after a full boot to Main OS
plus 40M instructions, all 64,908 bytes of the Digitone cave are still zero
and none was written. MAIN OS is loaded into RAM, so the cave is writable at
runtime and can hold both code and scratch variables.

Caveat: "untouched during boot" is not "never touched". A feature not
exercised at boot could still use it. Re-check before relying on a region.

That caveat has now bitten, and hard. **The Digitakt cave is not 58,188 free
bytes.** The tail of MAIN OS is `.bss` — zero-initialised globals the linker
placed there — so "all zero in the image" and "still zero after a boot" are
exactly what *allocated but not yet written* storage looks like. Both are
consistent with the space being owned.

The tell was one byte: a boot to post-intro leaves `0x402fa193` non-zero.
Watching the region found live buffer-pool allocator state at `0x402fa190` —
an enable flag, two 32-bit slot bitmaps and a counter, written from
`0x40004e68`/`0x40005016` and paired with a counter at `0x40303000`. Not a
stray static; a subsystem.

Scanning the whole image for absolute references into the range
(`tools/refscan.py`, 975,501 instructions, 96.75% byte coverage, 0% undecoded
inside the cave itself) finds **119 real references to ~120 distinct cells**,
clustered rather than scattered. Ghidra's own reference database independently
agrees on 91 addresses and finds zero code anywhere in the range. The usable
map:

| range | bytes | status |
|---|---|---|
| `0x402f9c14`-`0x402fa000` | 1,004 | free — 0 references by either method |
| `0x402fa000`-`0x402fa1a4` | ~420 | **live** — buffer-pool allocator state |
| `0x402fa1a4`-`0x40303000` | ~36 KB | free apart from one computed read at `0x402fcbf8`; flanked by live clusters both sides |
| `0x40303000`-`0x40303e58` | ~3.6 KB | **live** — RTOS counters and a further subsystem |
| `0x40303e5c`-`0x40307f60` | 16,644 | free — 0 references, nothing lives after it |

Use `0x40303e5c`-`0x40307f60` as the primary region. `0x402f9c14` is also
clean and is where `tools/machinepatch.py` puts its table, but it has only
1,004 bytes before live allocator state.

**On method.** Three checks with different blind spots, in increasing order of
strength:

- a runtime dump (`tools/memdump.py --range`) only proves nothing was written
  during the boot you observed. It cannot establish that space is free, only
  that it is not *currently* in use on one path. Treat a clean dump as a
  falsification test that failed, not as evidence.
- a static immediate scan (`tools/refscan.py --range`) is exhaustive over
  decodable code, but is blind by construction to computed and
  register-relative addressing.
- Ghidra's data-flow references (`tools/ghidraq.py ... range LO HI`) catch some
  of what the immediate scan cannot — `0x402fcbf8` is referenced only via an
  index-computed `movea.l $8(a1),a0`, invisible to an immediate scan and found
  only this way.

None of the three is a proof, and a clean result from all three is a lower
bound on safety. Run all three before relying on any region, and re-run them
per image — this map is for Digitakt II 1.15C only.

## Injecting code: the trampoline recipe

Redirect an existing call site into the cave, do the new work there, then
tail-call the original target so behaviour is preserved exactly.

Verified on Digitone, redirecting the `jsr task_create` at `0x400d1044`
(which creates the priority-1 task at `0x400d1110`):

    cave @0x402e1bf4:
        23FC C0DE0001 402E1C80    move.l #$C0DE0001,($402E1C80).L
        4EF9 400012C8             jmp ($400012C8).L      ; tail-call the original

    call site @0x400d1044:
        4EB9 400012C8   ->   4EB9 402E1BF4

22 bytes changed in total. Applied with:

    uv run python tools/patchimg.py --image IN.bin --out OUT.bin \
      --bytes 0x402e1bf4=<32 zeros>:23fcc0de0001402e1c804ef9400012c8 \
      --bytes 0x400d1044=4eb9400012c8:4eb9402e1bf4

Check any encoding you emit actually occurs in the image before relying on
it -- that is the cheapest proof ColdFire supports it. `23FC` (move.l
immediate to absolute long) occurs 9 times, `4EF9` (jmp abs.L) 3,626 times
and `4EB9` (jsr abs.L) 25,503 times in the Digitone image.

## What it measured

    marker at 0x402e1c80     stock 0x00000000      patched 0xc0de0001
    cave executed            stock 0 times         patched 1 time
    task_create() entered    stock 4 times         patched 4 times
    next task creation at    stock n=26,473,051    patched n=26,473,053

The tail-call preserves semantics: `task_create` still runs the same number
of times, and the boot is exactly **+2 instructions** -- the two that were
added. A full ladder from the patched image then reaches `MAIN_OS_RUNNING`
under `bootcheck --verify`, deterministic.

## Two gotchas

`emu/dspboot.py` finds task-create call sites by scanning for
`4eb9 <task_create>`, so a redirected site stops being recognised and drops
out of the TASK_CREATE log and the ladder's "tasks" count. That is a
reporting artifact, not a behaviour change -- confirmed by hooking
`task_create`'s entry directly, which counts 4 in both.

`bootcheck`'s state digest is a useful patch oracle, and it distinguishes
two cases. A data-only patch (two filter labels) left it byte-identical to
unpatched, `d1e8c68377741b68`. This code patch changed it, as it must. So an
unchanged digest is a real signal that a patch touched nothing it should
not have, and a changed one on a data-only patch means something is wrong.
