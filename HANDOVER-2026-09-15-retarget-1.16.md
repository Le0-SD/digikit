# Handover 2026-09-15: move the analysis to Digitakt II 1.16

Replaces `HANDOVER-2026-09-14-machine-sel.md`, `HANDOVER-2026-09-14-ui-queue.md`
and `HANDOVER-2026-09-15-sharc-frame.md` (deleted). Results are in
`docs/FINDINGS.md`; this file holds state and next steps only.

## State

- Branch `machine-engine-link`, pushed to `origin` and tracking it, no PR.
  Commits since `main@4a2bced`: `792a141`, `7c1dbe2`, `90bb5ea`, `39e5ab8`,
  `1280291` (ghidradump, CLAUDE.md), `edffac8` (frame gate writers),
  `aaeb009` (Unicorn MAC/MSAC with load patch), `fa9d3de` (sharcframe
  `--poke`, forced frame), `572c753` (dt2/elz.py extraction), `dc20744`
  (tools/sharcspec, docs/sharc), `7edc93a` (doc fixes).
- Tests: 148 passed, 5 skipped.
- Target: analysis and emulation move to Digitakt II 1.16, with Digitone II
  1.11 alongside. The device stays on 1.15C with bootstrap 2.00. Installing
  1.16 upgrades the bootstrap to 2.01 and cannot be undone, so no hardware
  test of a 1.16-based build happens without Em's decision.
- `.venv` Unicorn is built with both patches (library SHA-256 `c3899680…`).
  `uv run python -m emu.unicorn_compat` must print `"compatible": true`;
  `uv sync` restores stock Unicorn, then rerun `tools/install-patched-unicorn.sh`.
- `sections/` is 1.15C (`.source-sha256` = `62d58845…`). Em uses it; extract
  other firmware under `out/sections/` (git-ignored).
- Nothing for 1.16 exists yet: no extraction on disk, Ghidra project, dump or
  snapshot.
- Outside the repo: Ghidra projects `~/ghidra-projects/dt2` (stock language,
  1.15C), `dt2-emac` (ColdfireEMAC, seeds and RTTI applied, 14,257 functions,
  1.15C), `backup-2026-09-14` (1.15C before seeds and RTTI), `dt2cmp`
  (purpose not recorded). The ColdfireEMAC extension is symlinked into
  `~/Library/ghidra/ghidra_12.1.3_PUBLIC/Extensions`. The 1.15C dump is in
  `out/ghidra/dt2-1.15C-emac/`. The public ADI PDFs used by
  `tools/sharcspec/` are in `docs/refs/` (git-ignored).
- Em's separate sharc-spec work lives outside the repo. Its tables, docs and
  decoder are now in the repo (`tools/sharcspec/`, `docs/sharc/`,
  `dt2/elz.py`); work from those copies.
- Untracked and not for committing: `maybe.md`, `scratch/`,
  `docs/refs/netburner-coldfire/` (third-party SDK headers),
  `docs/refs/dspi2-edma-blocker-and-register-sources.md`.

## How to run

```
uv run --with pytest python -m pytest tests -q

# extraction, about a second; --oracle runs the device routine (1.15C/1.10E only)
uv run python -m emu.extract Digitakt_II_OS1.16.syx -o out/sections/dt2-1.16
uv run python -m emu.extract Digitone_II_OS1.11.syx -o out/sections/dn2-1.11

# Ghidra import with the EMAC language (about 100 s), then peripheral labels
GHIDRA_PROJ=$HOME/ghidra-projects/NAME GHIDRA_NAME=NAME \
  GHIDRA_IMG=out/sections/dt2-1.16/section_3_MAIN_OS.bin \
  GHIDRA_LANG=68000:BE:32:ColdfireEMAC tools/ghidra.sh import
GHIDRA_PROJ=... GHIDRA_NAME=... GHIDRA_IMG=... tools/ghidra.sh run McfLabels.java

# seeds and RTTI names (--code LO HI per image), applied to the project
uv run python tools/codeseeds.py IMG --code LO HI --json out/symbols/dt2-1.16-seeds.json
uv run python tools/rttiscan.py IMG --code LO HI --json out/symbols/dt2-1.16-rtti.json
uv run python tools/ghidraapply.py seeds out/symbols/dt2-1.16-seeds.json \
  --project P --project-name N --program /section_3_MAIN_OS.bin --analyze --report REPORT
uv run python tools/ghidraapply.py rtti out/symbols/dt2-1.16-rtti.json \
  --project P --project-name N --program /section_3_MAIN_OS.bin --report REPORT

# dump once (about a minute), then query with rg/sqlite3/jq
uv run python tools/ghidradump.py --out out/ghidra/dt2-1.16-emac \
  --project P --project-name N --rtti out/symbols/dt2-1.16-rtti.json
uv run python tools/ghidraq.py /section_3_MAIN_OS.bin decompile 0xADDR --project P --project-name N

# raw-byte reference scan: use it to confirm "no caller" or "no writer"
uv run python tools/refscan.py IMG --base 0x40000400 --range LO HI --map

# frame capture (constants are 1.15C addresses today)
uv run python tools/sharcframe.py snapshots/boot400M.snap --passes 3 --poke 0x4094e4f4=0

# SHARC boot stream, and the SHARC+ tables from the public manuals
uv run python tools/sharcldr.py out/sections/dt2-1.16/section_7_BLOB.bin
cd tools/sharcspec && uv run --with pymupdf python extract_figures.py
```

## Next steps, in order

### 1. The 1.16 main CPU image in Ghidra

- Extract 1.16 and 1.11 as above.
- Import the 1.16 MAIN OS into a project that also holds a 1.15C program,
  because Version Tracking (step 2) needs both programs in one project; for
  example a new `~/ghidra-projects/elektron-emac` with a copy of the
  `dt2-emac` program. Keep `dt2-emac` itself unchanged.
- Find the code ranges from the function-entry histogram (1.15C used
  `0x40000400-0x40200400` and `0x402c0400-0x402f9c14`), then seeds, RTTI and
  a dump to `out/ghidra/dt2-1.16-emac/`. Record function and Error bookmark
  counts in FINDINGS.

### 2. Carry names from 1.15C to 1.16

- `analyzeHeadless <project> <name> -process <dest> -postScript
  AutoVersionTrackingScript.java <session-folder> <session-name>
  <source-program-folder>` (see the header of
  `Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java`;
  the source must already be analysed). Pairs: Digitakt II 1.15C -> 1.16,
  Digitone II 1.10E -> 1.11, Digitakt II 1.15C -> Digitone II 1.11.
- Spot-check 20 matches per pair against the bytes. Install BinExport and
  BinDiff only if cross-product matching is weak.
- Digitone II 1.11 anchors: dispatcher `FUN_400c248e` (5 types, table
  `0x42432b24`), machine type at `+0xde` via `FUN_4004b7f2`, frame handler
  `FUN_40025e36`, DSPI2 driver `FUN_400cf7be`, test-handler installer
  `0x400d11d4`.

### 3. Re-find the ColdFire-to-SHARC frame link on 1.16

1.15C addresses to find again (all in FINDINGS, "The ColdFire tells the
SHARC through a periodic DSPI2 frame" and the frame gate section):

- vector-191 handler `0x4002d652`, DSPI2 driver `FUN_400cf9c4`, pacing
  counter `0x4028ac90`, SHARC boot routine `FUN_400cef6c`;
- gate `0x4094e4f4`, countdown `0x4094e4f0`, mode `0x4094e4f8`, stop flag
  `0x4094e4ec` and its writer `0x4002d632`;
- `FUN_4002d602` and its nine call and jump sites, including the opener at
  `0x400330f6` in the task `FUN_40032f5a` and the trampolines `0x400323d6`,
  `0x400407c8`, `0x400407de`, `0x400fa6c2`;
- frame tables: TX `0x80005348` (0x802 bytes), RX `0x8000488c` (0xabc),
  `0x800047fc + 4*i`, `0x80003340 + i*0x9a`, `0x80005b50 + i*0x8e`, MIDI
  flags `0x80004684 + 4*i` and `0x800046c4 + 4*i`; `FUN_400db9aa` returns
  `0x80005b50`.

Then:

- Make `tools/sharcframe.py`'s constants (handler, vector, pacing counter,
  driver) selectable per image before running it on 1.16.
- New `tools/dspmap.py`: every instruction that references the frame tables,
  its function and callers two levels up, as JSON in `out/maps/`, plus a
  FINDINGS summary. Highlight the `*::updateMirror` methods.

### 4. The emulator on 1.16

- Build a cold-boot snapshot ladder for 1.16 (the 1.15C ladder is
  `snapshots/boot*M.snap` with `.ladder.json`). Expect boot or peripheral
  differences. Run the emulator only when a static answer is not enough, and
  bound every run with `--limit`.
- Open question carried from 1.15C: does a normal boot open the gate? In
  1.15C the gate went from 0 to 1 between `boot200M` and `boot280M`. A write
  watch on the gate across that span answers it.
- Forced-gate capture on 1.16 with `--poke`; then why pass 0 sends zeros and
  what the slot words mean.

### 5. SHARC side on 1.16

- Rebuild `tools/sharc_visa_tables.py` from `tools/sharcspec/decode_table.json`
  and keep `tools/sharc_disasm.py`'s stop-at-unknown design. Prove it with a
  decoder comparison over the DSP main program: the sharc-spec decoder left
  1.1% of words unknown on 1.15C, ours stopped 4.4% in and could not name
  9.6% when forced on, and 1,928 words decoded as `17b` because our `15b`
  entry fixes 3 bits instead of 7. The comparison script from this session is
  not in the repo; write it as a tool.
- Regenerate `tools/ghidra/SHARC/` from the corrected table (adapt
  `tools/sharcspec/ghidra/gen_sleigh.py`) and import the 1.16 SHARC main
  program with `tools/sharc_import.py`.
- Check the hypotheses in `docs/sharc/structure-1.16.md`: the RPC dispatcher
  task (trampoline SW `0x1c3bf0`), the command block at `0x82a00000`, the
  audio task. Model the firmware's call convention (return address pushed
  through I7/M7, jump as call, return through an indirect jump and `rframe`).
- Join the two sides: which frame fields the dispatcher reads.
- Later: p-code for compute operations so the decompiler works, then a
  decode/re-encode round trip as the first half of an assembler.

### 6. Still open from 2026-09-14 (1.15C addresses; re-find on 1.16 when resumed)

SLICE-copy gaps (the horizontal line after a trig, `FUN_40017080` type-6
case, unreached shims, a type-read sweep tool); decode the nine descriptor
fields; boot from a patched image (`plan_b` applied to a copy of
`section_3_MAIN_OS.bin`); machine spec file; speed (A/B the idle-spin hook,
idle skipping, button dwell); project save with type 7 and eMMC block storage
in `emu/esdhc.py`; `guirun --regs-at ADDR[=NAME]`.

The 1.15C machine-type runs, if still wanted: three headless runs from
`snapshots/boot400M.snap`, all with `--patch-machine`: ONE SHOT (no
selection, trig only), SLICE, PLACEHOLDER. Add `--save-at
<trig+15M>:out/snap/NAME.snap`, `--watch 0x4094e4ec:16=gate`, `--at
0x40035e90=commit` and PNGs after the trig; then `tools/snapdiff.py` and
`tools/sharcframe.py` on the saved snapshots. Resume a snapshot saved with
`--patch-machine` without passing it again. Runs took 12-23 minutes each.

PLACEHOLDER replay (input times assume `--ips-at 80M:18720000`):
```
uv run python tools/guirun.py snapshots/boot400M.snap --patch-machine --ips-at 80M:18720000 --panel-dwell 12 --at 0x401d5680=cxa_throw --at 0x40035e90=commit --at 0x400caf48=desc --ring 4096 --input 90M:press:17 --input 102M:press:2 --input 102M:release:2 --input 114M:release:17 --input 126M:press:14 --input 126M:release:14 --input 138M:press:14 --input 138M:release:14 --input 150M:press:14 --input 150M:release:14 --input 162M:press:14 --input 162M:release:14 --input 174M:press:14 --input 174M:release:14 --input 186M:press:14 --input 186M:release:14 --input 198M:press:14 --input 198M:release:14 --input 210M:press:10 --input 210M:release:10 --input 238M:press:10 --input 238M:release:10 --input 253M:press:2 --input 253M:release:2 --input 268M:press:25 --input 268M:release:25 --input 283M:press:10 --input 283M:release:10 --png-at 279M:out/after-trig.png --png-at 293M:out/after-yes.png --limit 305000000
```
SLICE: 4 DOWN taps, YES at 190M and 205M, SRC 220M, trig 235M, YES 250M.
Button codes: SRC=2, YES=10, UP=11, NO=12, DOWN=14, FUNC=17, PLAY=20,
TRIG1=25.

## Gotchas

- Em runs things in the same tree. Check `sections/.source-sha256` before
  trusting a run, and never extract into `sections/`.
- One JVM per Ghidra project. A pyghidra tool under `tools/` must strip its
  own directory from `sys.path` before `import pyghidra`.
- Ghidra's call and reference tables miss code outside functions (four of
  the nine `FUN_4002d602` sites, the `0x4094e4ec` writer). Confirm with
  `tools/refscan.py`.
- The stock ColdFire language stops at `movclr`; use a ColdfireEMAC import.
- `dt2/elz.py` on 1.16 and 1.11 is checked by internal consistency (every
  stream ends at its declared length, and it agrees with the earlier
  sharc-spec extraction), not by an independent oracle.
- `tools/sharcspec/` scripts run from their own directory and read the PDFs
  from `docs/refs/`.
- Never name the vendor DSP toolchain in the repo; sharc-spec's original
  docs do, the imported copies do not.
- The coder agent's file tools drop whitespace-only lines: copy patch files
  with `cp`, and check a patch's SHA-256 after writing it.
- Subagents return only their final message and can stop at a turn limit on
  long edit lists; split large edits.
- Shell is zsh (an unquoted `$VAR` is one word), there is no `timeout`
  binary, and the rtk hook shortens `git log` and `ls` (use `rtk proxy`).

## Workflow

scout reads, coder applies fully specified edits, general-purpose agents run
processes, Ghidra and the emulator. Record results in `docs/FINDINGS.md`.
Commit when Em asks; Em asked for a commit and push at each clean breaking
point.
