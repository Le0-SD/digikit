# Handover — 2026-09-14, the eighth machine

This thread continues `HANDOVER-2026-09-13-sharc-and-repack.md`. Goal A (the
repack chain) is closed to the limit of what can be checked without hardware.
This thread is Goal B. Everything established is in `docs/FINDINGS.md` — "The
ColdFire machine dispatch" and its subsection "The display names are a
separate table". Read those, not this file, for facts.

## The goal, and how far "done" is

**A new machine on the Digitakt II that appears in the machine list, can be
selected, and makes a sound that the seven stock machines do not.**

That is a ladder, and it is worth being explicit about which rung the work is
on, because the four patches below only reach rung 2:

1. **Listed** — an eighth row appears in MACHINE SEL with its own name.
2. **Selectable** — selecting it does not crash, and the track plays. At this
   rung the machine is a *clone*: the cave descriptor copies entry 6's nine
   parameter IDs verbatim, so it behaves exactly like MANUAL SLICE and only
   the name differs. This is deliberate — a known-good payload while the
   plumbing is proven.
3. **Distinct behaviour** — its own parameter set. The nine literal IDs in the
   descriptor (`0xca`-`0xfe` across the stock entries) are not decoded yet; we
   do not know what they select or what a valid new combination would be. MIDI
   (entry 5) carries all nine zeroed, which proves they are not mandatory but
   says nothing about what they mean.
4. **A new algorithm** — DSP code the SHARC does not already run. This needs
   the SHARC assembler and semantic model that do not exist, and is the
   deepest item in the whole project. A machine that reuses an existing DSP
   mode with different parameters avoids it entirely.

So: the four patches below get to rung 2. Rung 3 is the next real research
question and is not started. Rung 4 is out of scope for a first machine.

## Where it stands

An eighth machine is dispatched and named in the emulator, proven by direct
in-guest call for all nine dispatch inputs. It is not yet visible on screen.
All four patches that should reach rung 2 are now implemented and pass
headlessly, but **the patched image still fails to boot under the GUI** —
see "The open failure" below.

| # | patch | what it does | state |
|---|---|---|---|
| 1 | source list | relocate table D to the cave with an eighth entry; repoint the `pea` immediates at `0x40052000`/`0x4005200a` | implemented |
| 2 | dispatch | trampoline `FUN_400caf48` for `type == 7`; descriptor and COW string reps in the cave | implemented, boots clean on its own |
| 3 | grouping | `FUN_4005d7b8`: `7206b2806604` -> `7207b2806504` at `0x4005d7ca`, making the exact-6 test a `<= 7` range test so type 7 gets group `1` instead of `0` | implemented, effect unverified |
| 4 | display name | copy the 7-row `0x401fbc50` name table to the cave with an eighth row; repoint `FUN_400dcc50`'s bound (`0x400dcc51`) and `lea` immediate (`0x400dcc62`) | implemented, table verified correct |

Two more are known but not blocking: the filter-list bounds (`pea` at
`0x40052296`/`0x400522a0`), only needed if the new machine should be a filter
target; and `FUN_4005e022`'s `param_1[0x73] + 1 < 8` auto-scroll gate, which
is cosmetic.

## The open failure

With all four halves applied, `emu/gui.py` freezes at the end of the boot
animation: 2 tasks instead of 6, `DTIM3 0`, `mainloop 0`, and the main task in
the terminal loop at `0x4012d2fa`. The fault log reports **0 distinct pages
touched**, so it is not a wild pointer — the `weak_ptr` trap is an object that
was never constructed. This is the same signature as the `list`-only failure.

What the bisect has established so far:

| halves applied | result |
|---|---|
| none | boots, 6 tasks, renders |
| `dispatch` | boots, 6 tasks, renders past 340M |
| `list` | **fails** |
| `list` with `--eighth 6` (eight rows, no new machine type) | boots |
| all four | **fails** |

So eight entries is fine; introducing machine *type 7* is what breaks it, and
patch 3 was the hypothesis for why. That hypothesis is **not yet tested in
isolation** — the decisive run has not been made:

    uv run python -m emu.gui --weakptr --patch-machine=list+group snapshots/boot400M.snap

If that boots, patch 3 works and the remaining break is in patch 4 (or in the
combination). If it still fails, patch 3 is not sufficient and `FUN_4005d7b8`
is not the only thing that rejects type 7.

Also untested in isolation: `group`, `name`, and `list+group+name`. The GUI's
`--patch-machine` accepts `+`-separated combinations for exactly this.

What has been ruled out, so it is not re-investigated:

- **The cave.** The `dispatch` half writes the trampoline, descriptor and
  string reps into the same region and boots clean.
- **The name table copy.** Read back from guest memory after patching, all
  eight rows are correct: `Oneshot/ONE`, `Werp/WRP`, `Stretch/STRE`,
  `Repitch/RPI`, `Grid/GRD`, `MIDI/MIDI`, `Slice/SLC` (plus its third
  pointer), `Placeholder/PLC`.
- **The pre-existing `weak_ptr` hang.** Both arms of every A/B ran with
  `--weakptr`; only the patched arm fails.
- **A wild pointer.** Zero memory faults in the failing run.

## How to reproduce

The machine-select screen renders, and modifier chords work, with:

    uv run python -m emu.gui --weakptr --patch-machine=dispatch snapshots/boot400M.snap

Click FUNC (it latches, staying sunken), then SRC. The list stays open.
`clear` in the latch box releases held modifiers.

- `--patch-machine` takes `list`, `dispatch`, or bare for both, with an
  optional `:N` suffix setting the eighth list entry's value (e.g.
  `--patch-machine=list:6`).
- `--panel-dwell N` sets the emulated dwell between panel state changes in
  chunks, default 16 (~50 ms). `0` restores the old coalescing and reproduces
  the flicker the dwell fixed.
- `--weakptr` is required on this snapshot or the main task traps before the
  UI comes up.

Headless equivalents: `tools/machinepatch.py --milestone b [--parts
list|dispatch|both] [--eighth N]`, which also unit-tests the dispatch by
calling it in-guest.

## Retractions from this thread

1. **The cave is not 58,188 free bytes.** The tail of MAIN OS is `.bss`. Only
   `0x40303e5c`-`0x40307f60` (16,644 bytes) and `0x402f9c14`-`0x402fa000`
   (1,004 bytes) are clear. See `docs/PATCHING.md`, corrected.
2. **A clean runtime dump does not prove memory is free** — it only proves
   nothing wrote there on the path observed. Use `tools/refscan.py` and
   `tools/ghidraq.py ... range` as well; all three have different blind spots
   and none is a proof.
3. **The descriptor's name pointers are not the UI's display names.** Those
   come from a separate static table. Corrected in FINDINGS.md.
4. **"The UI task is never scheduled" was wrong** — it was true only of
   headless resume runs. Under `emu/gui.py` the UI runs normally.

## Suggested order

1. **Sweep for remaining bounds before implementing.** Three of the four
   patches above were discovered only when something broke. `FUN_400caf48`
   and `FUN_400dcc50` are both accessors of the same shape — a `moveq #6`
   bound followed by a base address — and between them have eleven callers.
   Grep the image for that instruction shape to find any sibling accessors in
   one pass, rather than discovering them one crash at a time.
2. **Find why type 7 still breaks boot.** Patches 3 and 4 are written; the
   question is what else rejects the new machine type. Start with the
   `list+group` run named in "The open failure" — it is one command and it
   splits the remaining search in half. The `[gui] FAULT` lines and the
   terminal-loop fault summary are now printed unconditionally, so a failing
   run reports more than it used to.
3. Decode the descriptor's nine parameter IDs — rung 3, and the first thing
   that makes the machine actually different rather than a renamed clone.
4. Convert the whole thing to a real image patch through `tools/patchimg.py`
   and `dt2/build.py`, and put it through `tools/roundtrip.py`.
5. Only then hardware — and the standing advice from the previous handover
   still holds: prove recovery mode while the device is healthy, then flash
   an unmodified rebuild before anything patched.

## Tools added this thread

    tools/memdump.py      resume, spin to post-intro, dump a guest range
    tools/memfind.py      search mapped guest memory for a pattern
    tools/refscan.py      exhaustive static scan for absolute references into a range
    tools/machinepatch.py install the eighth machine live; --parts bisects it
    tools/uidrive.py      script panel input and watch for UI-side signals
    tools/ghidraq.py      gained a `range LO HI` subcommand

`emu/gui.py` gained `--patch-machine`, `--panel-dwell`, latching modifiers,
and unconditional memory-fault reporting (`[gui] FAULT page=... pc=...`),
which was previously recorded and never surfaced.
