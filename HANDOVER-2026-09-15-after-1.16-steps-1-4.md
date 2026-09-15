# Handover 2026-09-15: 1.16 retarget, after steps 1-4

Replaces `HANDOVER-2026-09-15-retarget-1.16.md` (deleted). Results are in
`docs/FINDINGS.md`; this file holds state and next steps only.

## State

- Branch `machine-engine-link`, pushed to `origin` and tracking it, no PR.
  Commits since the previous handover (`6d38794`): `1c2e64e` (ghidra.sh
  folders, ghidracopy, ghidradump `--image`, entryhist), `ce0e014`
  (ghidravt, vtcheck), `5e4ac43` (FINDINGS: 1.16 in Ghidra, Version
  Tracking), `f9f76ef` (framelink, sharcframe and snapdiff per image,
  dspmap), `d0cd9fa` (FINDINGS: the frame link on 1.16), `67f90b9`
  (bootwatch), `a2033ea` (FINDINGS: the emulator boots 1.16).
- Tests: 185 passed, 5 skipped.
- The device stays on 1.15C with bootstrap 2.00. Installing 1.16 upgrades the
  bootstrap to 2.01 and cannot be undone, so no hardware test of a
  1.16-based build happens without Em's decision.
- Steps 1-4 of the retarget are done: 1.16 in Ghidra with seeds, RTTI and a
  dump; names and addresses carried from 1.15C by Version Tracking; the frame
  link re-found on 1.16; a 1.16 cold-boot ladder, the gate writer, and a
  frame captured on 1.16.
- `sections/` and `snapshots/` are 1.15C, and Em uses them. 1.16 and
  Digitone outputs, all git-ignored:
  - `out/sections/dt2-1.16/`, `out/sections/dn2-1.11/`,
    `out/sections/dn2-1.10E/`: extracted sections.
  - `out/snapshots/dt2-1.16/boot{60,120,200,280,400}M.snap` and
    `.ladder.json`: the 1.16 cold-boot ladder.
  - `out/ghidra/{dt2-1.15C,dt2-1.16,dn2-1.10E,dn2-1.11}-emac/`: dumps made
    before Version Tracking.
  - `out/symbols/{dt2-1.16,dn2-1.10E,dn2-1.11}-{seeds,rtti}*.json`.
  - `out/vt/`: Version Tracking exports (accepted matches) and
    `check-*.json` from vtcheck.
  - `out/maps/`: dspmap and gatewatch outputs. `out/sharcframe/`: frames.
- Ghidra projects, outside the repo:
  - `~/ghidra-projects/elektron-emac` (name `elektron-emac`): folders
    `/dt2-1.15C`, `/dt2-1.16`, `/dn2-1.10E`, `/dn2-1.11` and
    `/dn2-1.11-from-dt2`, each with `section_3_MAIN_OS.bin`; Version
    Tracking sessions in `/vt/`. `/dt2-1.16`, `/dn2-1.11` and
    `/dn2-1.11-from-dt2` carry markup applied by Version Tracking.
  - `~/ghidra-projects/backup-2026-09-15-elektron`: `/dt2-1.16` before
    Version Tracking.
  - `~/ghidra-projects/dt2-emac`: the 1.15C project, content unchanged.
    `dt2cmp`: an old stock-language import of Digitone II 1.10E.
    `backup-2026-09-14`: 1.15C before seeds and RTTI.
- `tools/framelink.py` holds the frame-link addresses of 1.15C and 1.16 by
  MAIN OS SHA-256. sharcframe, dspmap and `bootwatch --frame-gate` stop on
  an image without a profile.
- Untracked and not for committing: `maybe.md`, `scratch/`,
  `docs/refs/netburner-coldfire/`,
  `docs/refs/dspi2-edma-blocker-and-register-sources.md`.

## How to run

```
uv run --with pytest python -m pytest tests -q

# extraction (about a second)
uv run python -m emu.extract Digitakt_II_OS1.16.syx -o out/sections/dt2-1.16

# Ghidra: import into a project folder, copy a program, dump, code ranges
GHIDRA_PROJ=$HOME/ghidra-projects/elektron-emac GHIDRA_NAME=elektron-emac \
  GHIDRA_FOLDER=dt2-1.16 GHIDRA_IMG=out/sections/dt2-1.16/section_3_MAIN_OS.bin \
  GHIDRA_LANG=68000:BE:32:ColdfireEMAC tools/ghidra.sh import
uv run python tools/ghidracopy.py --from DIR NAME /PATH --to DIR2 NAME2 /FOLDER/section_3_MAIN_OS.bin
uv run python tools/ghidradump.py --out out/ghidra/dt2-1.16-emac \
  --project $HOME/ghidra-projects/elektron-emac --project-name elektron-emac \
  --program /dt2-1.16/section_3_MAIN_OS.bin \
  --image out/sections/dt2-1.16/section_3_MAIN_OS.bin --rtti out/symbols/dt2-1.16-rtti.json
uv run python tools/entryhist.py out/ghidra/dt2-1.16-emac/functions.jsonl

# Version Tracking (15-20 minutes a pair) and the check against the bytes
uv run python tools/ghidravt.py run --project $HOME/ghidra-projects/elektron-emac \
  --project-name elektron-emac --source /dt2-1.15C/section_3_MAIN_OS.bin \
  --dest /dt2-1.16/section_3_MAIN_OS.bin --session /vt/NAME --json out/vt/NAME.json
uv run python tools/vtcheck.py out/vt/dt2-1.15C_to_dt2-1.16.json \
  --source-image sections/section_3_MAIN_OS.bin --source-dump out/ghidra/dt2-1.15C-emac \
  --dest-image out/sections/dt2-1.16/section_3_MAIN_OS.bin \
  --dest-dump out/ghidra/dt2-1.16-emac --lookup 0x4002d652

# instructions that use the frame tables
uv run python tools/dspmap.py --image out/sections/dt2-1.16/section_3_MAIN_OS.bin \
  --dump out/ghidra/dt2-1.16-emac --json out/maps/dt2-1.16-dspmap.json

# emulator on 1.16: its own sections and snapshots
DT2_SECTIONS=out/sections/dt2-1.16 DT2_SNAPSHOTS=out/snapshots/dt2-1.16 \
  uv run python -m emu.checkpoint make 60000000,120000000,200000000,280000000,400000000 \
  out/snapshots/dt2-1.16/boot Digitakt_II_OS1.16.syx
DT2_SECTIONS=out/sections/dt2-1.16 DT2_SYX=Digitakt_II_OS1.16.syx \
  uv run python tools/bootwatch.py --limit 401000000 --frame-gate --dump out/ghidra/dt2-1.16-emac
DT2_SECTIONS=out/sections/dt2-1.16 DT2_SYX=Digitakt_II_OS1.16.syx \
  uv run python tools/sharcframe.py out/snapshots/dt2-1.16/boot400M.snap --passes 3 --open-gate

# SHARC boot stream, and the SHARC+ tables from the public manuals
uv run python tools/sharcldr.py out/sections/dt2-1.16/section_7_BLOB.bin
cd tools/sharcspec && uv run --with pymupdf python extract_figures.py
```

## Next steps, in order

### 1. SHARC side on 1.16

- Done: `tools/sharc_visa_tables.py` loads `tools/sharcspec/decode_table.json`
  (form names without `Type`, e.g. `15b`, `8a_abs`, `5b_move`), and
  `tools/sharc_disasm.py` keeps its stop-at-unknown design.
  `tools/sharcldr.py --main` writes the DSP main program, and
  `tools/sharccompare.py` compares the decoders; results in FINDINGS,
  "SHARC+ instruction tables from the public ADI manuals". Both decoders stop
  at `0xbb0`, 2.9% into the main program, so a linear walk alone is not
  enough: disassembly has to follow control flow.
- Regenerate `tools/ghidra/SHARC/` from the table (adapt
  `tools/sharcspec/ghidra/gen_sleigh.py`) and import the 1.16 SHARC main
  program with `tools/sharc_import.py`. `tools/ghidra/gen-sharc-slaspec.py`
  still expects the old form names (`8a`, `9a`, `9b`) and fails on the
  rebuilt table; replace or remove it.
- Check the hypotheses in `docs/sharc/structure-1.16.md`: the RPC dispatcher
  task (trampoline SW `0x1c3bf0`), the command block at `0x82a00000`, the
  audio task. Model the firmware's call convention (return address pushed
  through I7/M7, jump as call, return through an indirect jump and `rframe`).
- Join the two sides: which frame fields the dispatcher reads.
- Later: p-code for compute operations so the decompiler works, then a
  decode/re-encode round trip as the first half of an assembler.

### 2. What the frame means

- Why pass 0 sends no track data, and what the slot words mean. The 1.16
  frame equals 1.15C's except the header byte the new installer sets, and the
  tables did not move, so this can be worked on the 1.15C setup, where the
  GUI runs.
- Which peripheral raises vector 191: the installer writes priority 5 to
  `ICR1_63` (`0xfc04c07f`), INTC1 source 63. Name it from the MCF5441x
  reference manual (`docs/refs/MCF5441XRM.pdf`, text and tables); it explains
  why the emulator never raises the vector.

### 3. Emulator literals on 1.16 (when a 1.16 GUI run is needed)

- Still 1.15C literals: `PRINT` and `SWITCH_TO` in `emu/longrun.py`,
  `TX_STATE` `0x4094cd74` and `WAIT_LOOP` in `emu/edma.py`, the weak-pointer
  patch, and the addresses in `emu/panel.py`, `emu/screen.py`, `emu/hle.py`,
  `emu/serial.py`, `emu/uiprobe.py` and the terminal hook in `emu/gui.py`.
  `out/vt/check-dt2-1.15C_to_dt2-1.16.json` gives the 1.16 function for
  most of them.
- `emu/symbols.py`: the `transport` signature matches `0x40134200` on 1.16,
  but the counterpart of 1.15C `0x40128c7c` is `0x40136268`, so
  `call_sites` lists 25 sites. `ctx_switch_load`'s verify bytes contain
  `current_tcb` `0x47d9adb4`, which moved. The `view_*` and
  `ui_key_dispatch` hooks are fixed 1.15C addresses.

### 4. Still open from 2026-09-14 (1.15C addresses; re-find on 1.16 when resumed)

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
  trusting a run, and never extract into `sections/` or build snapshots in
  `snapshots/`; give 1.16 its own directories through `DT2_SECTIONS` and
  `DT2_SNAPSHOTS`.
- One JVM per Ghidra project. A pyghidra tool under `tools/` must strip its
  own directory from `sys.path` before `import pyghidra`.
- A headless `analyzeHeadless -postScript` runs inside a transaction and the
  analyzer saves the processed program afterwards, even when the script
  fails. Use the pyghidra tools (`ghidracopy`, `ghidravt`) for anything that
  must not write.
- Headless `AutoVersionTrackingScript` gets a 2 GB heap and runs out of
  memory on these images; `tools/ghidravt.py` sets 32 GB. Its "apply markup
  errors" are not logged in headless mode.
- Version Tracking matches can be wrong (look-alike virtual methods), and a
  `vfunc_N` slot number can shift between versions. Check a match with
  `tools/vtcheck.py` and the bytes before relying on it.
- Ghidra's data references can be wrong: it attributes the DSPI2 driver's
  `move.w a0,(a1,d0.l*4)` to `0x80003340`, while `a1` holds `0x80001bc0`.
  Its call and reference tables also miss code outside functions; confirm
  with `tools/refscan.py`.
- The stock ColdFire language stops at `movclr`; use a ColdfireEMAC import.
- `dt2/elz.py` on 1.16 and 1.11 is checked by internal consistency (every
  stream ends at its declared length, and it agrees with the earlier
  sharc-spec extraction), not by an independent oracle.
- `tools/sharcspec/` scripts run from their own directory and read the PDFs
  from `docs/refs/`.
- Never name the vendor DSP toolchain in the repo; sharc-spec's original
  docs do, the imported copies do not.
- `jcmd` cannot attach to the JVM inside a pyghidra process.
- The coder agent's file tools drop whitespace-only lines: copy patch files
  with `cp`, and check a patch's SHA-256 after writing it.
- Subagents return only their final message and can stop at a turn limit on
  long edit lists; split large edits.
- Shell is zsh (an unquoted `$VAR` is one word), there is no `timeout`
  binary, and the rtk hook shortens `git log` and `ls` and rejects
  `find -newer` (use `rtk proxy`).

## Workflow

scout reads, coder applies fully specified edits, general-purpose agents run
processes, Ghidra and the emulator. Record results in `docs/FINDINGS.md`,
and have a second agent check a finding against the bytes before marking it
**[V]**. Commit when Em asks; Em asked for a commit and push at each clean
breaking point.
