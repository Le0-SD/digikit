# Start here

Cold-start guide for continuing this work. Read `docs/FINDINGS.md` for the
evidence behind any claim below; this file is the *what to do next*.

**No Elektron firmware is in this repo and none should ever be committed.**
`.gitignore` covers `*.syx`, `*.zip`, `sections/`, `snapshots/`, `out/`.
You supply your own `Digitakt_II_OS1.15C.syx`
(SHA-256 `62d588456e47194bd56dfee9568fb9dd4521c4ff1e8b5427eb461355532e8c6c`).

---

## 0. Setup and smoke test (5 minutes)

```sh
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt

# extract sections with mischa85/elektron-firmware-tool (MIT, supports dev 0x14)
elektron-firmware-tool -i Digitakt_II_OS1.15C.syx -o sections/

./venv/bin/python -m dt2.container Digitakt_II_OS1.15C.syx   # section table
./venv/bin/python emu/oracle.py                              # CRC oracle, seconds
./venv/bin/python emu/screen.py selftest                     # graphics, seconds
```

All three should pass. If `oracle.py` throws `UC_ERR_MAP`, see Trap 3 below.

---

## 1. What is already built and verified

| Capability | Where | Status |
|---|---|---|
| `.syx` -> ELE3 container + section table | `dt2/container.py` | works |
| ColdFire-aware disassembly | `dt2/coldfire.py` | works (handles MVS/MVZ, FF1) |
| Unicorn machine + ISA workarounds | `emu/harness.py` | works |
| CRC-32 oracle (`0x80001bd0`) | `emu/oracle.py` | byte-exact vs zlib |
| aPLib depacker (`0x80000432`) | `emu/oracle.py` | validates a full 3.1 MB repack |
| Render firmware graphics | `emu/screen.py` | pixel-exact vs ground truth |
| Boot emulation, 10/16 tasks | `emu/dspboot.py` | 58,387 addrs |
| Snapshots / checkpoints | `emu/snapshot.py`, `emu/checkpoint.py` | verified faithful |
| Serial console model | `emu/console.py` | UART modelled; console task not reached |

**The single most important result**: the device's *own* depacker, run under
emulation, decompresses our repacked image to byte-identical output. Byte-exact
repacking is therefore unnecessary — nothing in the acceptance path hashes the
original compressed bytes.

---

## 2. Work item A — the emulator

### Honest ceiling, read this first

Full boot to a UI is **not reachable on a useful timescale**, and this is
arithmetic rather than a guess:

- with instrumentation on, throughput is **~0.83M instr/sec**
  (the 2.72M figure in FINDINGS is a *bare* run that records nothing)
- **1 new task per ~250M instructions**, and the gaps are widening
  (tasks landed at 32M, 47M, 257M, 416M)
- 6 tasks remain; the draw path and console task are past all of them

That is hours per experiment with no guarantee. Do not launch multi-billion
instruction runs expecting a UI.

### What *is* worth doing

1. **Use snapshots as the normal working mode.** Never re-run from entry.
   ```sh
   ./venv/bin/python -m emu.checkpoint make 60000000,120000000,200000000,280000000
   ./venv/bin/python -m emu.longrun snapshots/boot280M.snap 200000000
   ```
   `boot280M.snap` carries 9 tasks / 47,335 addresses and resumes in ~10 s.

2. **Differential testing — the thing that actually serves patching.** Run stock
   and patched images through the same harness and diff coverage/traces. A
   string patch should give *identical* traces; a logic patch should diverge only
   where intended. This needs no boot and is the real validation story.
   Note: a patched image invalidates existing snapshots (they capture post-load
   memory), so the patched run pays the ~5 min checkpoint cost once.

3. **Speed, if you want it.** Profile which hooks cost most — the UART
   `UC_HOOK_MEM_READ/WRITE` and the `SWITCH_TO` hook are the prime suspects for
   the 3x loss. Dropping to only the hooks a given experiment needs should
   recover most of the bare-run throughput.

### Concrete open leads

- **Draw path**: `particles 0x44f52000 -> rasterise -> 8bpp 0x43139290 -> >>2 into
  0x43137290 (loop at 0x400d3628) -> px_copy_to_bitmap 0x400d315e -> Bitmap`.
  Both 8bpp stages are still zero; the rasteriser has never executed. Finding a
  *callable* entry for it would give a rendered frame without waiting for boot.
- **Console**: task entry `0x400cd594` (prio 2), dispatcher `strcmp` chain at
  `0x400cd93e`, print function **`0x400054b4`** (hook it to capture all output —
  no transport modelling needed). Starting the task by hand from a snapshot runs
  but yields into an idle spin.
- **Text rendering**: never located. None of the 27 `setPixel` callers walks a
  string, and no static font table exists (searched 5x7/6x8 `'!'` glyph patterns).
  Icons are runtime-constructed, so the font probably is too — look for a glyph
  *decompressor*, working outward from `VerticalMenuView(const char*, int,
  std::string, const Bitmap*, int)`.

---

## 3. Work item B — the patcher (the original goal)

Three items, all with second-scale feedback. This is the shortest path to
something you can actually flash.

### B1. Finish the acceptance oracle

Two routines left, same pattern as the two that already work in `emu/oracle.py`:

| routine | address | what it checks |
|---|---|---|
| content checksum | `0x40003ca6` | word-sum, each 32-bit word XORed with its index, vs value at container `+0x04` |
| HMAC-SHA256 | `0x80005e2a` | hashes image minus last 32 bytes, compares to trailer. SHA-256 H0 at `0x800058bc`, K-table at `0x80006ef8` |

Together with CRC + depacker these are the bootstrap's **entire** accept/reject
decision for a MIDI-delivered image. An image that passes all four on the laptop
is one the device will take.

### B2. Build the patcher

Requirements, in priority order:

1. **Refuse to touch sections 2 and 4.** Section 2 is the bootstrap — your
   recovery path. Hard-fail any patch targeting either, and verify after every
   build that both came back byte-identical.
2. **Hash-pin the input.** A tool built for 1.15C must refuse a different image.
3. **Pattern-anchored patches, not fixed offsets.** Each patch definition carries
   a match pattern, the expected original bytes, and the replacement. Fixed
   offsets silently land in the wrong place on a new firmware version — the worst
   available failure mode.
4. **Never modify in place.** Read-only input, new output file.
5. **Round-trip + oracle as build gates**, not optional tests: extract → patch →
   rebuild → re-extract → all five sections identical except the intended delta →
   all four oracle routines pass. Refuse to emit a file otherwise.
6. **Byte-level diff report**: offsets, virtual addresses, before/after, and a
   disassembly of the touched region.

### B3. First real patch

A same-length string edit from the 248 KB of string tables (7.8% of MAIN OS,
1,392 contiguous tables). Good target: the machine/filter name table at
`0x4022b20e` — `WERP`, `STRETCH`, `REPITCH`, `SLICED SMP`/`SLIC`,
`MANUAL SLICE`/`MLIC`, `STATE VARIABLE`/`SVAR`, `LOWPASS 4`/`LP4`, `EQUALIZER`,
`COMB-`/`COMB+`, `LEGACY LP/HP`. Long name plus display abbreviation.

---

## 4. Safety cheat sheet

Established statically, not by flashing anything:

- **Recovery path**: bootstrap STARTUP menu (hold FUNC at power-on), independent
  of MAIN OS, accepts SysEx over **MIDI DIN only — not USB**. You need a USB-MIDI
  interface with a 5-pin DIN out.
- **The only irreversible operation is BOOTSTRAP UPGRADE**, gated at `0x80001c72`
  by `bcc` — it runs *only* when the incoming bootstrap version is strictly
  greater than the running one (`0x0200` in 1.15C). Patching sections 3/7 never
  presents a higher version, so it is unreachable.
- **Two independent version numbers.** Bootstrap version = section 2 header word
  at `0x80000408` (**never change**). Container version string = ELE3 `+0x13`,
  settable with the tool's `-V` (safe to bump).
- **The recovery path performs no version comparison** — re-flashing stock over
  patched is not gated. MAIN OS's USB path does carry "Downgrade not possible"
  (error code 6); whether it treats *equal* as a downgrade was never pinned down.
- **Back up the +Drive with Transfer before flashing anything.**
- Recommended bring-up order: (1) confirm you have MIDI DIN out; (2) back up
  +Drive; (3) **test recovery while healthy** — flash *stock* via the STARTUP
  menu; (4) flash an unmodified *rebuild*; (5) only then a real patch.

---

## 5. Traps that already cost time

1. **Capstone 5 silently mis-decodes ColdFire opcodes** — `MVS`/`MVZ` (including
   indexed mode) and `FF1`. A linear sweep loses sync *on the instruction that
   matters* — it sits directly on the bootstrap version gate, and misreading it
   inverts the safety answer. Use `dt2/coldfire.py` or Ghidra's
   `68000:BE:32:Coldfire`.
2. **Unicorn hard-aborts (SIGABRT) on `movec` with Rc=0x009** — not a catchable
   fault. Must be intercepted before Unicorn's decoder sees it. Handled in
   `harness.py`; do not remove.
3. **Write `SR` before `A7`.** m68k banks SSP/USP, so switching mode after
   setting the stack pointer writes the register the CPU is about to stop using.
   Surfaces as a bogus `UC_ERR_MAP`.
4. **Resume snapshots *into* a hooked machine.** Restoring onto a bare `Machine`
   drops the behaviour hooks and the run diverges while looking plausible
   (~50 addresses over 5M instructions). Use `dspboot.run(resume_from=...)`.
5. **A wrong `PixelData` renders as plausible dither, not an error.** Validate
   rendering against ground truth (`emu/screen.py selftest`), never by eye.
6. **Check byte-position histograms before interpreting a buffer.** The intro
   buffer was read as floats and described as a dither field; only byte 3 of each
   word is ever non-zero — they are integer `(x, y)` coordinates.
7. **"Stalled" metrics lie.** The stall detector flags any hot address after a
   window with no *new* coverage, so ordinary hot arithmetic (`__mulsf3` at
   `0x40175288`) reads as a hang.
8. **`ERROR_headerVersion_wrong`** and friends in MAIN OS are the **LZ4 frame
   error enum**, not OS versioning. A false lead.

---

## 6. Key addresses

| | |
|---|---|
| MAIN OS load / entry | `0x40000400` / `0x400004e8` |
| Vector table (VBR) | `0x40000000` (why MAIN OS is at +0x400) |
| Context switcher | `0x40000410`, incoming TCB written at `0x4000044a` |
| Ready-list cursor / current TCB | `0x4094c914` / `0x47d9adb4` |
| Bootstrap load | `0x80000400` (section 2; `dest` field is a *version*) |
| SPI NOR read (HLE'd) | `0x401296fe` — `read(offset, len, dest)` |
| Staged ELE3 slot in flash | `0x80000` (section table at `+0x20`) |
| CRC-32 | `0x80001bd0` (poly `0xEDB88320`, residue `0xDEBB20E3`) |
| aPLib depack | `0x80000432` — `depack(src, dst)`, src includes 8-byte header |
| Transport / completion sem | `0x40128c7c` / `0x44e4d69c` (pend at `0x40128d08`) |
| task_create / task_start | `0x400012c8` / `0x40001314` (16 sites, 10 reached) |
| print | `0x400054b4` |
| Bitmap::setPixel | `0x40104eb4` — `setPixel(Bitmap*, x, y, val)` |
| px_copy_to_bitmap | `0x400d315e` |
| Bitmap layout | `+04` w, `+08` h, `+0C` stride (words/column), `+10` data |
| Panel | 128x64, **1bpp**, column-major, 32 rows/word, MSB = lowest y |
