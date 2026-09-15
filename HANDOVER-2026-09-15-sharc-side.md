# Handover 2026-09-15: the SHARC side of the 1.16 retarget

Replaces `HANDOVER-2026-09-15-after-1.16-steps-1-4.md` (deleted). Results
are in `docs/FINDINGS.md`; this file holds state and next steps only.

## State

- Branch `machine-engine-link`, pushed to `origin` and tracking it, no PR.
  Commits since `6d38794`: `1c2e64e` (ghidra.sh folders, ghidracopy,
  ghidradump `--image`, entryhist), `ce0e014` (ghidravt, vtcheck), `5e4ac43`
  (FINDINGS: 1.16 in Ghidra, Version Tracking), `f9f76ef` (framelink,
  sharcframe and snapdiff per image, dspmap), `d0cd9fa` (FINDINGS: frame link
  on 1.16), `67f90b9` (bootwatch), `a2033ea` (FINDINGS: emulator boots 1.16),
  `77c9fa4` (SHARC decoder on the sharc-spec table, sharccompare, sharcldr
  `--main`), `a45cc1e` (previous handover, FINDINGS: rebuilt decoder),
  `36f50ea` (SHARC_VISA language install and import), `60c7735` (FINDINGS:
  DSP program in Ghidra), `7a6a177` (FINDINGS: call convention, RPC
  dispatcher, command block checked), and the commit after it (sharcimm,
  FINDINGS: the SHARC side of the SPI frame link, this handover).
- Tests: 190 passed, 5 skipped.
- The device stays on 1.15C with bootstrap 2.00. Installing 1.16 upgrades the
  bootstrap to 2.01 and cannot be undone, so no hardware test of a
  1.16-based build happens without Em's decision.
- Done: steps 1-4 of the retarget (1.16 in Ghidra with names carried from
  1.15C, the frame link re-found, a 1.16 cold-boot ladder, the gate writer, a
  frame captured on 1.16), and on the SHARC side the decoder rebuild, the
  generated Ghidra language, both DSP images imported, and the
  `docs/sharc/structure-1.16.md` hypotheses checked (call convention, RPC
  dispatcher task, command block confirmed on 1.15C and 1.16).
- `sections/` and `snapshots/` are 1.15C, and Em uses them. Other outputs,
  all git-ignored:
  - `out/sections/dt2-1.16/`, `out/sections/dn2-1.11/`,
    `out/sections/dn2-1.10E/`: extracted sections.
  - `out/snapshots/dt2-1.16/boot{60,120,200,280,400}M.snap` and
    `.ladder.json`: the 1.16 cold-boot ladder.
  - `out/ghidra/{dt2-1.15C,dt2-1.16,dn2-1.10E,dn2-1.11}-emac/`: ColdFire
    dumps made before Version Tracking.
  - `out/vt/`: Version Tracking exports and `check-*.json`.
  - `out/maps/`: dspmap and gatewatch outputs. `out/sharcframe/`: frames.
  - `out/sharc/dt2-{1.15C,1.16}-main.bin`: the DSP main programs (104,848
    bytes at loader byte address `0x28382670`); `compare-*.json`.
- Ghidra, outside the repo:
  - `~/ghidra-projects/elektron-emac`: ColdFire programs `/dt2-1.15C`,
    `/dt2-1.16`, `/dn2-1.10E`, `/dn2-1.11`, `/dn2-1.11-from-dt2`
    (`section_3_MAIN_OS.bin` in each), Version Tracking sessions in `/vt/`.
  - `~/ghidra-projects/elektron-sharc`: DSP programs `/dt2-1.16_SHARC` and
    `/dt2-1.15C_SHARC` (language `SHARC_VISA:LE:32:default`, 347 and 352
    functions). The hypothesis check may have added disassembly there.
  - `~/ghidra-projects/dt2-emac` (1.15C ColdFire, unchanged content),
    `backup-2026-09-15-elektron` (`/dt2-1.16` before Version Tracking),
    `backup-2026-09-14`, `dt2cmp` (old Digitone II 1.10E import), `dt2`
    (old, holds `dt2_SHARC` imported with the old language).
  - Installed processor modules: `Processors/SHARC_VISA` (current, from
    `tools/ghidra/install-sharc.sh`), `Processors/SHARC` (old, keep for
    `dt2_SHARC`); ColdfireEMAC is linked into the user Extensions.
- `tools/framelink.py` holds the ColdFire frame-link addresses of 1.15C and
  1.16 by MAIN OS SHA-256.
- `tools/sharcimm.py` outputs in `out/sharc/`:
  `imm-periph-dt2-{1.16,1.15C}.json` (code immediates) and
  `words-periph-dt2-{1.16,1.15C}.json` (loader-block words).
- Untracked and not for committing: `maybe.md`, `scratch/`,
  `docs/refs/netburner-coldfire/`,
  `docs/refs/dspi2-edma-blocker-and-register-sources.md`.

## How to run

```
uv run --with pytest python -m pytest tests -q

# SHARC: language, import, main program, decoders
tools/ghidra/install-sharc.sh
uv run python tools/sharc_import.py out/sections/dt2-1.16/section_7_BLOB.bin \
  --name dt2-1.16_SHARC --seed-calls --analyze          # add --overwrite to redo
uv run python tools/sharcldr.py out/sections/dt2-1.16/section_7_BLOB.bin --main out/sharc/dt2-1.16-main.bin
uv run python tools/sharc_disasm.py out/sharc/dt2-1.16-main.bin
uv run python tools/sharccompare.py out/sharc/dt2-1.16-main.bin --json out/sharc/compare-dt2-1.16-new.json
uv run python tools/sharcimm.py out/sharc/dt2-1.16-main.bin --json out/sharc/imm-periph-dt2-1.16.json
uv run python tools/sharcimm.py --words out/sections/dt2-1.16/section_7_BLOB.bin --json out/sharc/words-periph-dt2-1.16.json

# ColdFire: dump, Version Tracking check, frame-table map
uv run python tools/ghidradump.py --out out/ghidra/dt2-1.16-emac \
  --project $HOME/ghidra-projects/elektron-emac --project-name elektron-emac \
  --program /dt2-1.16/section_3_MAIN_OS.bin \
  --image out/sections/dt2-1.16/section_3_MAIN_OS.bin --rtti out/symbols/dt2-1.16-rtti.json
uv run python tools/vtcheck.py out/vt/dt2-1.15C_to_dt2-1.16.json \
  --source-image sections/section_3_MAIN_OS.bin --source-dump out/ghidra/dt2-1.15C-emac \
  --dest-image out/sections/dt2-1.16/section_3_MAIN_OS.bin \
  --dest-dump out/ghidra/dt2-1.16-emac --lookup 0x4002d652
uv run python tools/dspmap.py --image out/sections/dt2-1.16/section_3_MAIN_OS.bin \
  --dump out/ghidra/dt2-1.16-emac --json out/maps/dt2-1.16-dspmap.json

# emulator on 1.16: its own sections and snapshots
DT2_SECTIONS=out/sections/dt2-1.16 DT2_SYX=Digitakt_II_OS1.16.syx \
  uv run python tools/sharcframe.py out/snapshots/dt2-1.16/boot400M.snap --passes 3 --open-gate
DT2_SECTIONS=out/sections/dt2-1.16 DT2_SYX=Digitakt_II_OS1.16.syx \
  uv run python tools/bootwatch.py --limit 401000000 --frame-gate --dump out/ghidra/dt2-1.16-emac
```

## Next steps, in order

### 1. Where the SHARC receives the ColdFire's frame

The ColdFire side is known on 1.16 (FINDINGS, "The frame link on Digitakt II
1.16"): the vector-191 handler `0x4002dd0c` builds a frame and calls the
DSPI2 driver `FUN_400cd2bc(0x802, 0x80005348, 0xabc, 0x8000488c)`: it sends
2050 bytes from `0x80005348` and receives 2748 bytes into `0x8000488c`.

Done on 2026-09-15 (FINDINGS, "The SHARC side of the SPI frame link"):
`tools/sharcimm.py` found no SPI, DMA or SEC address in the DSP code; the SPI
bases are in a data table (loader block 35, SPI0/1/2 entries at data
pointers `0x2694a0`/`0x2694c8`/`0x2694f0`, stride `0x28`). SW `0x1c80a0`
passes 2748 to `0x1c7bd4`, which sets R4=2 and R12=`0x261a10` and jumps to
`0x1c9fd5`; that computes I1 = `0x2694a0` + 2 * `0x28`, the SPI2 entry. The
function at `0x1c136a` returns 2748. `0x401` is written to offset `0xc` of a
structure at `0x268220`.

- Follow the SPI2 entry pointer: in `0x1c9fd5` it is I1 after SW `0x1c9ffb`,
  and the calls that follow are `0x1c0cd0` and `0x1c9f9c` (which calls
  `0xb87e25`, outside the loaded blocks). Find where I1 or the struct at
  `0x261a10` is stored and the code that reads the SPI base (entry +0) and
  the DMA bases (+4, +8) from it, then the register writes at base + offset:
  SPI_CTL `+0x04` (MSTR bit 1 says slave or master), RXCTL `+0x08`, TXCTL
  `+0x0c`, RWC `+0x1c`, TWC `+0x24`; DMA CFG `+0x08`, ADDRSTART `+0x04`,
  XCNT `+0x0c`. The offsets are in the table in `tools/sharcimm.py`.
- The small function at SW `0x1ca17a` loads `0x2694f0` and calls
  `0x1c89b9` (bit set/clear helpers); no direct caller was found. Check with
  a raw scan before calling it unused.
- What `0x1c7bd4` does with 2748, and who calls the init run around
  `0x1c80a2`: no `25a_direct` targets `0x1c7ff8`-`0x1c80af`.
- The struct at `0x268220` (+4 = `0x268240`, +8 = `0x100000`, +0xc =
  `0x401`, +0x10 = 4) is passed to `0x1c834a` and `0x1c83ff`: find whether it
  is an SPI buffer descriptor or unrelated.
- These traces read compute instructions by hand. Step 2's flow-override
  pass, and compute p-code, would let Ghidra show them; consider doing it
  before a long trace.
- Follow the receive buffer to its reader: does it end at the RPC dispatcher
  (SW `0x1c35xx`-`0x1c48xx`) or at the command block `0x82a00000`?
- A captured 1.16 frame to match against: `out/sharcframe/dt2-1.16/`
  (`--open-gate`, pass 1, sha256 `d674f76c…`). Its non-zero bytes: offset
  `0x0001` (`0x03`), `0x00d8`-`0x00d9` (`38 40`), single `0x02` bytes at
  `0x011c`, `0x0120` and every `0x60` bytes after to `0x06bc`, `0x06c0`
  (16 pairs, one per track?), `0x0736` (`40`), `0x0738`-`0x0739` (`11 30`),
  `0x07dd` (`08`), `0x07e1` (`12`), `0x07e9` (`02`), `0x07f0`-`0x07f3`
  (`7f ff ff ff`), `0x0801` (`01`). Byte 1 is `0x01` at pass 0 because the
  1.16 installer writes word 1 to `0x80005348`; 1.15C sends the same frame
  with byte 1 = `0x02`.

### 2. How the RPC dispatcher selects a command

Known (FINDINGS, SHARC+ section): the task is created at SW
`0x1c3f5a`-`0x1c3f6a` with entry `0x1c3bf0`; the body starts at `0x1c3bf6`
and calls, through the software-call idiom, `0x1c7d09`, `0x1c7f45`,
`0x1c4353`, `0x1c7e02` and `0x1c43c9` (1.16; 1.15C callees after
`0x1c7700` are `0x6c` lower). All 30 references to the command block
`0x82a00000`-`0x82a001c8` are in SW `0x1c361a`-`0x1c48c3`.

- Ghidra has no function there, because the language models the software
  call (`3c` push, `16a` store, `25a_direct` goto) as a plain goto and the
  return (`9b_abs` through I4/M6, then `25c_rframe`) as an unresolved
  return. Write a pyghidra pass (a tool under `tools/`) that finds each call
  triple and return pair with our decoder and sets flow overrides on the
  program: CALL on the `25a_direct` of a triple, RETURN on the `9b_abs` of a
  pair; then create functions at the goto targets and re-run analysis.
  Measure functions and call references before and after.
- Candidate dispatch jump: `9a_abs` at SW `0x1c46c4`, indirect through I6/M3
  (the return idiom uses I4/M6). Read the instructions before it: what loads
  I6/M3, and is there a table of short-word pointers near it (the old 1.15C
  work labelled 11 RPC handlers with `--label-table ADDR:COUNT`; find the
  table on 1.16)? The `9a_rel` at `0x1c551a` has a fixed target and is not a
  table jump.
- Reading which command field selects the case needs compute semantics:
  `tools/sharcspec/compute_table.json` describes the compute operations; the
  language has p-code only for control flow. Porting compute p-code into
  `tools/sharcspec/ghidra/gen_sleigh.py` is the larger job behind this.

### 3. The Audio Task entry

Created with the same call as the RPC dispatcher: 1.16 at SW `0x1c7775`
(ureg4 = `0x1c7749`, ureg8 = name at `0x2825f7c0`), 1.15C at SW `0x1c7708`
(ureg4 = `0x1c76dc`, ureg8 = `0x2825f7b0`). `0x1c7749` is not an instruction
boundary in our 1.16 decode (a run of `21a`/`22a`/`23p_undoc16` words around
it); on 1.15C `0x1c76dc` decodes as `25a_direct` to `0xb86b1a`, outside the
loaded blocks. Check whether ureg4 is the entry itself or points at a
structure, by comparing with the RPC dispatcher's ureg4 (`0x1c3bf0`, a real
entry).

### 4. What the frame means (ColdFire side)

- Why pass 0 sends no track data, and what the slot words mean. The 1.16
  frame equals 1.15C's except byte 1, and the tables did not move, so this
  can be worked on the 1.15C setup, where the GUI runs.
- Which peripheral raises vector 191: the installer writes priority 5 to
  `ICR1_63` (`0xfc04c07f`), INTC1 source 63. Name it from the MCF5441x
  reference manual (`docs/refs/MCF5441XRM.pdf`, text and tables); it explains
  why the emulator never raises the vector.

### 5. Emulator literals on 1.16 (when a 1.16 GUI run is needed)

- 1.15C literals: `PRINT` and `SWITCH_TO` in `emu/longrun.py`, `TX_STATE`
  `0x4094cd74` and `WAIT_LOOP` in `emu/edma.py`, the weak-pointer patch, and
  the addresses in `emu/panel.py`, `emu/screen.py`, `emu/hle.py`,
  `emu/serial.py`, `emu/uiprobe.py` and the terminal hook in `emu/gui.py`.
  `out/vt/check-dt2-1.15C_to_dt2-1.16.json` gives the 1.16 function for most.
- `emu/symbols.py`: `transport` matches `0x40134200` on 1.16 but the
  counterpart of 1.15C `0x40128c7c` is `0x40136268` (so `call_sites` lists
  25); `ctx_switch_load`'s verify bytes contain `current_tcb` `0x47d9adb4`,
  which moved; the `view_*` and `ui_key_dispatch` hooks are fixed 1.15C
  addresses.

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

- SHARC addresses: loader byte address = 2 * short-word + `0x28000000` for
  code in the L1 bank. Code pointers in the DSP code (task entries, goto
  targets) are short-word addresses; data pointers (names, tables) are loader
  byte addresses less `0x28000000`, not doubled. In Ghidra the code space has
  wordsize 2: `getAddress(byte_offset)` with byte offset = 2 * short-word,
  and Ghidra prints the short-word address. A wordsize-2 space needs
  `define alignment=2`, or Ghidra silently disassembles nothing.
- In the call idiom the `16a` stores the goto's short-word address minus 1,
  not the address after the call.
- The task-creation call target (`0xb8615d` on 1.16) lies outside every
  loaded section-7 block. Do not read Ghidra's "thunk"/"EXT" labels there as
  evidence of what it is.
- A linear walk over the DSP main program stops at `0xbb0` (2.9% in) with
  either decoder; disassembly has to follow control flow or skip words.
- Em runs things in the same tree. Check `sections/.source-sha256` before
  trusting a run, and never extract into `sections/` or build snapshots in
  `snapshots/`; give 1.16 its own directories through `DT2_SECTIONS` and
  `DT2_SNAPSHOTS`.
- One JVM per Ghidra project. A pyghidra tool under `tools/` must strip its
  own directory from `sys.path` before `import pyghidra`.
- A headless `analyzeHeadless -postScript` runs inside a transaction and the
  analyzer saves the processed program afterwards, even when the script
  fails. Use pyghidra tools (`ghidracopy`, `ghidravt`) for anything that
  must not write.
- Headless `AutoVersionTrackingScript` gets a 2 GB heap and runs out of
  memory on these images; `tools/ghidravt.py` sets 32 GB. Its "apply markup
  errors" are not logged in headless mode.
- Version Tracking matches can be wrong (look-alike virtual methods), and a
  `vfunc_N` slot number can shift between versions. Check with
  `tools/vtcheck.py` and the bytes before relying on a match.
- Ghidra's data references can be wrong: it attributes the DSPI2 driver's
  `move.w a0,(a1,d0.l*4)` to `0x80003340`, while `a1` holds `0x80001bc0`.
  Its call and reference tables also miss code outside functions; confirm
  with `tools/refscan.py`.
- The stock ColdFire language stops at `movclr`; use a ColdfireEMAC import.
- `dt2/elz.py` on 1.16 and 1.11 is checked by internal consistency, not by
  an independent oracle.
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
