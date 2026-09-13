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

That caveat has now bitten, on Digitakt. The 58,188-byte Digitakt cave at
`0x402f9c14` is entirely zero in the static image, but a boot to post-intro
leaves one non-zero byte, at `0x402fa193`. Watching the region shows why:
there is a live 8-byte object at `0x402fa190` — a `u32` written once to `1`
from `0x40005014`, and a second word read seven times from `0x40005030`. That
is the shape of a C++ function-local static and its guard variable, which
means the linker placed real data here and the trailing zeros are
zero-initialised data, not slack.

So the cave is not uniformly free, and its stated size is an upper bound, not
an allocation. Empirically the rest of it stays zero through a boot to
post-intro, and the first 1,404 bytes from the base have been used
successfully (see `tools/machinepatch.py`), but anything placed here should be
checked against a runtime dump of the specific region first —
`tools/memdump.py --range` does that in one run.

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
