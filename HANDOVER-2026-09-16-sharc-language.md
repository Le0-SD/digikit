# Handover 2026-09-16: SHARC+ semantics in the generated Ghidra language

Replaces `HANDOVER-2026-09-15-sharc-side.md`. Results are in
`docs/FINDINGS.md`; this file holds state and next steps only.

## State

- Branch `sharc-pcode`, from `main` after PR #13 (`machine-engine-link`,
  merged). Commits: `ad2ec98` CJUMP as a call; `14f85fc` conditional jumps,
  calls and returns keep a fall-through, plus `tools/sharcpcode.py`;
  `c8b7990` a sqlite dump per measurement run and `tools/sharcpcode.sql`;
  `bd153a3` Type21a is the all-zero word, not a prefix; `eed409d` Type22a is
  idle and neither image contains one, plus `tools/sharcspec/audit_bits.py`;
  `534f73b` the previous handover; `78a4ee5` three older manuals, two more
  provisional forms, and the stale-language hole below. **`78a4ee5` and this
  handover are not pushed.** Only the untracked files listed below are
  uncommitted.
- Tests: 209 passed, 5 skipped.
- The language installed in Ghidra is current: 80 constructors, slaspec
  `ca2362aa`, installed by `tools/ghidra/install-sharc.sh` on 2026-09-16. The
  programs in `~/ghidra-projects/elektron-sharc` were imported under two older
  languages now: re-import before reading them, or work from the throwaway
  projects `tools/sharcpcode.py` builds under its own output directory.
- Measurement runs, git-ignored, each with `lint.json`, `<image>.json`,
  `<image>.sqlite` and its own Ghidra project, under `out/sharcpcode/`:
  `db-old`, `db-new`, `t21`, `t22`, `t23`, `t24`, `t25`, `t26`, `t27`, `t28`,
  `t29`, `t30`. **Measure a change against `t30`.** `t24` to `t27` compiled a
  stale slaspec: their decoder numbers are sound but their Ghidra numbers are
  of the language as it was before `78a4ee5` -- see the Gotchas. `t28` is lint
  only (the guard stopped it); `t29` and `t30` are the first runs whose
  language matches the decode table.
- Analysis targets are Digitakt II 1.16 and Digitone II 1.11; Em asked on
  2026-09-15 to stop cross-checking 1.15C.
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
    `out/sharc/dn2-1.11-main.bin`: Digitone II 1.11 (105,016 bytes, SW
    `0x1c12e2`).
- Ghidra, outside the repo:
  - `~/ghidra-projects/elektron-emac`: ColdFire programs `/dt2-1.15C`,
    `/dt2-1.16`, `/dn2-1.10E`, `/dn2-1.11`, `/dn2-1.11-from-dt2`
    (`section_3_MAIN_OS.bin` in each), Version Tracking sessions in `/vt/`.
  - `~/ghidra-projects/elektron-sharc` (language
    `SHARC_VISA:LE:32:default`): `/dt2-1.16_SHARC` and `/dn2-1.11_SHARC`
    re-imported with the CJUMP language and after `tools/sharcflow.py
    --cover` (1,999 and 1,776 functions);
    `/dt2-1.15C_SHARC` (352 functions, not covered); test copies in
    `/flowtest/`, `/flowtest2/`, `/flowtest3/` and `/flowtest5/`, which can
    be deleted.
  - `~/ghidra-projects/backup-2026-09-15-sharc`: `/dt2-1.16_SHARC`,
    `/dt2-1.15C_SHARC` and `/dn2-1.11_SHARC` from before the flow pass.
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

## Start here: do machines reach the SHARC at all?

This is the fork in the road and it comes before every p-code stage below.

Em's goal is their own machines on Digitakt II and Digitone II. Rungs 1 and 2
of the eighth-machine ladder are done -- PLACEHOLDER is listed and selectable,
and the ColdFire side is no longer the blocker (FINDINGS, "The ColdFire machine
dispatch"). What is not known is whether a machine is distinct DSP code at all.

The evidence says maybe not. Nobody has found the machine type travelling to
the SHARC: "no call to `FUN_4004fc02` or `FUN_400caf48`, and no read of
`+0xa2`, was found in the handler or its frame loop" (FINDINGS, "The ColdFire
tells the SHARC through a periodic DSPI2 frame"), and the same negative result
holds on Digitone II 1.11. Two readings:

- the type reaches the DSP by a path nobody has traced, inside the per-track
  tables the frame copies; or
- there is no per-machine DSP algorithm on a sampler at all. SAMPLE, WERP,
  STRETCH, REPITCH and SLICE are playback modes of one engine, and a machine is
  a parameter mapping.

If the second holds for Digitakt II, a new machine needs no assembler and no
DSP semantics, and stages 1-7 below stop being on its critical path. Digitone
II is unlikely to go the same way: FM TONE, WAVETONE and SWARMER are different
synthesis algorithms, so a new one there probably is new DSP code. The stages
below stay as written; they are the road for Digitone II and for rung 4.

**The experiment.** Capture the frame with one track set to machine A, then to
machine B, and diff. Bytes that differ at a stable offset are the selector or
the parameter encoding. Frames identical apart from parameter values say
machines are mappings.

Digitakt II 1.15C can run it today: `tools/framelink.py` has the profile,
`snapshots/boot400M.snap` exists, the GUI runs, and `tools/sharcframe.py`
captures a pass. The only gap is a way to set the machine --
`tools/machinepatch.py` adds an eighth type, it does not select among the
seven. Three options, cheapest first:

- `sharcframe.py --poke ADDR=LONG` on the per-track machine field (`+0xa2` of
  the track struct). Fastest, but a poke may never reach the derived per-track
  tables the frame actually copies -- the MIDI case shows the commit
  `FUN_40035e90` writing derived state -- so a null result here is ambiguous.
- Call the machine setter `FUN_40050cd6` from a Unicorn hook.
  `tools/sharcframe.py` already hooks the driver call; copy that shape. This is
  the reliable one.
- Drive the GUI with `--input` presses, as the 1.15C machine runs under "Still
  open from 2026-09-14" do. Slowest: 12-23 minutes a run.

**Digitone II needs setup first.** `emu/` supports it properly -- Digitone
addresses run through `emu/symbols.py`, `pit.py`, `esdhc.py`, `dspboot.py` and
`device.py` -- but two things are missing:

- `tools/framelink.py` has no Digitone profile, so `sharcframe.py` and
  `tools/dspmap.py` refuse the image outright. The addresses are partly known
  (FINDINGS, "Digitone II 1.11: the same link and the same machine table
  shape"): handler `FUN_40025e36`, driver call
  `FUN_400cf7be(0xa80, 0x80005e60, 0xabc, 0x800053a4)`, TX 2,688 and RX 2,748,
  16 per-track slots of `0x92` bytes copied from `0x800068e4 + i*0xca`. The
  gate and pacing variables have not been located at all. Verify them
  instruction by instruction, the way 1.16's were, before writing a profile.
- Boot snapshots exist for Digitone II **1.10E** only
  (`snapshots/Digitone_II_OS1.10E/boot*.snap`), not 1.11. Either build a 1.11
  ladder with `emu.longrun.build` as 1.16's was built, or run the experiment on
  1.10E -- a departure from the 1.16/1.11 rule that costs nothing here, since
  the question is structural.

**The static cross-check**, which needs no emulator and works on both devices:
find what writes the per-track tables the frame reads (`0x800047fc + 4i`,
`0x80003340 + i*0x9a`, `0x80005b50 + i*0x8e` on Digitakt). Only the MIDI flag's
writer is known. `tools/refscan.py` cannot find these by construction -- they
are reached as `base + i*stride` and its docstring says it misses computed
addresses -- so use `tools/dspmap.py`, which pairs the Ghidra dump's data
xrefs with a refscan sweep and already knows these regions. FINDINGS puts the
writers "among functions that use file-browser strings (`ENTER DIR NAME`,
`WRITE PROTECTED`), in about `0x4002c0fa`-`0x4002f000`. About 45 of them are
called from elsewhere and they were not traced one by one."

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
uv run python tools/sharcldr.py out/sections/dn2-1.11/section_7_BLOB.bin --main out/sharc/dn2-1.11-main.bin
uv run --with pymupdf python tools/refstext.py            # manuals to out/refs/
uv run python tools/sharcflow.py out/sharc/dt2-1.16-main.bin --program /dt2-1.16_SHARC --cover --analyze   # --save writes
uv run python tools/sharcflow.py out/sharc/dn2-1.11-main.bin --base-sw 0x1c12e2 --program /dn2-1.11_SHARC --cover --analyze

# SHARC: measure a language change, and query a run
uv run python tools/sharcpcode.py measure --out out/sharcpcode/NEW --ghidra   # ~35 s per image
uv run python tools/sharcpcode.py compare out/sharcpcode/t30 out/sharcpcode/NEW
uv run python tools/sharcfields.py                        # declared fields vs the classic grid
sqlite3 -header -column out/sharcpcode/NEW/dt2-1.16.sqlite \
  "ATTACH 'out/sharcpcode/t30/dt2-1.16.sqlite' AS old;" ".read tools/sharcpcode.sql"
uv run python tools/sharcspec/audit_bits.py --top 12     # PRM bits the table does not fix
(cd tools/sharcspec && uv run python build_table.py)     # after editing the merge rules

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

Put the semantics in the generated language and let Ghidra's analysis draw
function boundaries; do not add boundary heuristics to `tools/sharcflow.py`
(a delay-slot and switch "tidy" step was written and dropped). Work in
`tools/sharcspec/ghidra/gen_sleigh.py`. `tools/ghidra/install-sharc.sh`
regenerates, compiles and installs the language; then
`tools/sharc_import.py ... --overwrite --seed-calls --analyze` and
`tools/sharcflow.py ... --cover --analyze --save` rebuild a program (about
15 s per image; commands under "How to run").

Measure every change with `tools/sharcpcode.py measure --out DIR --ghidra`
and `compare out/sharcpcode/t30 DIR`, which fails on new sleigh diagnostics,
fewer decoded instructions, a conditional branch with no fall-through, a
decompiler failure, a probe that stops passing, or a timing that grows by more
than a quarter. `measure` regenerates the slaspec into a temp directory first
and refuses when the one on disk has drifted from `decode_table.json`, so run
`tools/ghidra/install-sharc.sh` after any table or generator change.

`t30`'s numbers for 1.16: 21,792 aligned instructions, all decoding; 1,169
main-program functions, 95 of them one instruction and 493 two to five; 289
functions truncated at bad instruction data; 160 Error bookmarks; `8a_rel`
branches landing on an instruction start 520 of 590 in range. For 1.11: 21,361
aligned, 1,048 functions, 336 truncated, 178 Error bookmarks. Read the rest
with `tools/sharcpcode.sql` against the run's sqlite dump. Mark unconfirmed
forms unimplemented instead of guessing.

How much p-code exists today: 80 constructors, 28 with a semantic body and 52
empty. Ten of the 52 decoded forms emit any p-code, all of them control flow,
so 19,622 of 1.16's 21,792 aligned instructions lift to nothing. Stage 4 below
covers about 62% of the program by instruction count and stage 6 another 12%.

1. Delay slots in the generator: CJUMP, the return and every delayed
   `8a`/`9a`/`9b` jump, and `11a`/`11c` with j=1 if they compile. The spike
   that proved this compiles is gone (FINDINGS, "Delay slots as one Ghidra
   instruction"); rebuild it from these rules:
   - Two structurally identical slot subtables `s1` and `s2`, each a copy of
     every root constructor with an empty body; one subtable cannot appear
     twice in a pattern. Define them before the constructors that use them.
   - In subtable constructors, quote the mnemonic text (`s1:"jump" ...`):
     bare words there must be operands.
   - A field cannot be both a display operand and constrained (`j=1`) in the
     same constructor: drop it from the display of the split halves.
   - Shapes that compiled: CJUMP (0x1804, 0x1844) as `<pattern> ; s1 ; s2`
     with `build s1; build s2; call target;`; `9a_abs` and `9b_abs` jumps
     split on j, j=1 as `build s1; build s2; return [0:4];` (j=0 unchanged);
     `8a_abs` jump with j=1 as `... goto target;`. RFRAME bodies emptied: it
     restores I7 and I6 and is not a return.
   - A conditional delayed branch must evaluate its condition before the
     slots run. The conditional constructors are already split on cond
     (`gen_sleigh.py`, `conditional_semantics`), so the slots go inside the
     branch that takes it.
   - Remove any test install afterwards: `rm -rf
     /opt/homebrew/Cellar/ghidra/12.1.3/libexec/Ghidra/Processors/SHARC_SPIKE
     ~/ghidra-projects/spike-sharc*`.
   - The probe `returns 2748` is this stage's target. `FUN_001c136a` returns
     through the `9b_abs` at SW `0x1c1496` (`0x083f343f`, the I4/M6 idiom),
     and 2748 = `0xabc` is loaded by the `17b` at `0x1c1498`, in its delay
     slot. No decoder change can make that probe pass; this one can.
2. Attach the ureg register names (SHARC+ Core Programming Reference, UREG
   class table: 0x00-0x0f R, 0x10 I, 0x20 M, 0x30 L, 0x40 B, 0x50 S, 0x60 and
   up system registers) and define the status and system registers (ASTAT,
   STKY, PCSTK, LPSTK, loop registers). The sleigh compiler already runs in
   `tests/test_sharc_pcode.py`.
3. Done in `78a4ee5`, with a correction. `Type8a_abs` and `Type8a_rel` now fix
   bit 25 to zero, and `Type8p_undoc48` takes the 32 words across the two
   images that have it set -- 30 of which point at something that is not an
   address, including the nonsense `jump 0x3e0030` at 1.16 SW `0x1c13bc` and
   1.11 SW `0x1c1366`, the same six bytes in both. 0 regressions, and
   `FUN_001c136a` loses its `halt_baddata()`. But this handover was wrong that
   the function stops there: it does not, and the probe is blocked on stage 1,
   not on the decoder. Restoring the other six dropped PRM bits was measured
   and rejected -- 225 aligned instructions lost in 1.16, 279 in 1.11 -- and
   `RESTORE_PRM_GAP` in `build_table.py` records why, per bit. Still open: what
   the `Type8p` words are (32 across two images, several byte-identical in
   both, so shared code rather than misalignment).
4. P-code for the move and memory forms (`17a`, `17b`, `14a`, `15a`, `15b`,
   `16a`, `3a`-`3c`, `5a`, `5b`, `19a`) and a calling convention (R4, R8,
   R12 in, R0 out, I7 stack, I6 frame).
5. Indirect jumps: `9a`/`9b` jumps go to I + M (pre-modify); only the I4/M6
   jump (raw `0x083f343f`) is a return. The test is the RPC dispatcher's jump
   at `0x1c3c3c` and its cases that jump back to `0x1c3c1d`, and the probe
   "RPC dispatcher is one function", which passes now and must keep passing.
6. ALU and multiplier compute (`4a`, `2c`, `1a`, `1b`) with flags; then the
   condition codes, the shifter and float operations. With real flags, the
   `condition` p-code op the conditional branches call becomes a genuine
   test of ASTAT instead of a placeholder.
7. The provisional forms, when there is evidence: `21p_undoc16` (883 in 1.16,
   969 in 1.11), `23p_undoc16` (407, 399), `22p_undoc48` (91, 129),
   `26p_undoc48` (1, 1). Their prefixes and lengths fit the images; their
   names and semantics are unknown, and the public manuals skip Types 23 and
   24. Twelve of the twenty worst mid-instruction branch targets are still
   unexplained: the instruction the target lands inside decodes cleanly, so a
   neighbouring form is wrong as well.

After stage 4, take up step 1 below (the SPI2 trace) again with the
decompiler.

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

- `tools/sharcflow.py --cover` covers the program (FINDINGS, "The DSP
  programs of Digitakt II 1.16 and Digitone II 1.11 in Ghidra"), but
  function boundaries stay too fine until the language models delay slots
  and indirect jumps (see the plan above). The dispatcher's first piece
  ends in the `9b` jump at `0x1c3c3c`, and its cases jump back to
  `0x1c3c1d`.
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
- Every SHARC+ CJUMP (`25a`) is a delayed call: the push of R2 and the store
  of the return address - 1 after it are its delay slots, and the return
  lands after them. Returns and other delayed jumps also run the two
  instructions after them. Read listings with that in mind.
- SLEIGH's `delayslot(n)` counts bytes, so it cannot model two SHARC+
  delay-slot instructions of varying length (Next steps, stage 1).
  `getMaximumInstructionLength()` is empty for the generated language, and
  18-byte instructions work.
- Manual text is in `out/refs/<pdf stem>/` (`toc.md`, `pages/pNNNN.txt`,
  `all.txt`) from `tools/refstext.py`: grep there, do not extract the PDFs
  again.
- Em wants strict delegation: scout reads, coder edits, general-purpose
  agents run every process, including short commands and git.
- Analyse Digitakt II 1.16 and Digitone II 1.11 only; use 1.15C only when a
  hardware test needs it.
- A Ghidra JVM holds one version of a language for its lifetime, so a project
  read after a different language was installed gives wrong numbers. Measure
  each language in its own `tools/sharcpcode.py` run.
- `tools/sharcspec/build_table.py` has no `if __name__` guard: importing it
  rewrites `decode_table.json`. Copy what you need from it, as
  `audit_bits.py` does.
- The generated `tools/sharcspec/ghidra/SHARC_VISA/` tree is git-ignored and
  nothing regenerates it on its own, so a decode-table edit leaves it stale
  with no sign. That cost four measurements on 2026-09-16. The installed-
  language check could not catch it: a stale slaspec compiles to the stale
  `.sla` that is installed, the two agree, and the run proceeds. `measure` now
  regenerates into a temp directory and refuses on drift, and records
  `decode_table_sha256` in `lint.json`. When a change measures perfectly flat,
  check that hash before believing it.
- `tools/sharcfields.py` is the mirror of `audit_bits.py`: it tallies what
  values the table's declared fields actually take in the firmware and flags
  any field sitting on bits the classic grid fixes. It reads `classic_keys`,
  which `build_table.py` now records per form.
- A form merged from two classic tables has a real field wherever those tables
  disagree, and reading only one of them makes that bit look like a conflict.
  Guessing the classic table from the form name gets every split form wrong:
  `Type8a_rel` guesses `Type 8a` where the merge used `Type 8a #2`. Both
  mistakes were made and both produced confident false findings.

## Workflow

scout reads, coder applies fully specified edits, general-purpose agents run
processes, Ghidra and the emulator. Record results in `docs/FINDINGS.md`,
and have a second agent check a finding against the bytes before marking it
**[V]**. Commit when Em asks; Em asked for a commit and push at each clean
breaking point.
