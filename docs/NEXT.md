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
uv sync                     # creates .venv on CPython 3.12 from uv.lock

# extract sections with mischa85/elektron-firmware-tool (MIT, supports dev 0x14)
elektron-firmware-tool -i Digitakt_II_OS1.15C.syx -o sections/

uv run python -m dt2.container Digitakt_II_OS1.15C.syx   # section table
uv run python emu/oracle.py                              # CRC oracle, seconds
uv run python emu/screen.py selftest                     # graphics, seconds
```

All three should pass. If `oracle.py` throws `UC_ERR_MAP`, see Trap 3 below.

Then watch it boot:

```sh
uv run python -m emu.gui                      # live panel in a window
uv run python -m emu.frame snapshots/boot400M.snap 20000000   # one frame, ASCII + PNG
```

**Why the Python version is pinned.** `pyproject.toml` requires 3.12, not the
3.14 Homebrew installs by default. Two reasons, both practical: binary wheels
are still thin on 3.14 (pygame, for one, only resolves to an sdist), and
Homebrew's `python@3.14` ships no `tkinter`, so `emu/gui.py` could not open a
window. uv's managed CPython bundles tkinter, so `uv sync` is the whole setup
-- no `brew install` step.

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
| Serial console model | `emu/console.py` | UART modelled; console task blocks on its input queue |
| Task/ready-list inspector | `emu/tasks.py` | parked PC per task from any snapshot |
| Blocker + hot-PC probe | `emu/probe.py` | pend sites, scheduler state, PC sampling |
| Rendered panel frame -> PNG | `emu/frame.py` | **works** -- 84 frames, real `setPixel` |
| Live panel GUI | `emu/gui.py` | **works** -- tkinter, emulator on a worker thread |
| Snapshot ladder from a snapshot | `emu/checkpoint.py extend` | works |

**The single most important result**: the device's *own* depacker, run under
emulation, decompresses our repacked image to byte-identical output. Byte-exact
repacking is therefore unnecessary — nothing in the acceptance path hashes the
original compressed bytes.

---

## 2. Work item A — the emulator

### Honest ceiling -- REVISED, the old one was measuring a bug

The previous version of this file said full boot was "not reachable on a useful
timescale", from "1 new task per ~250M instructions, and the gaps are widening".
That was not the firmware. It was `raise_vector` pushing the wrong PC into
`trap #0` exception frames, so any task that blocked could never be resumed.
See "The scheduler never worked" in FINDINGS. With that fixed:

- distinct TCBs scheduled went **1 -> 5**
- throughput is **~2.1-2.8M instr/sec** (scoped ISA hooks), not 0.83M
- the panel **draws**: 84 frames through the firmware's own `Bitmap::setPixel`

What is still true: no device interrupt ever fires under emulation, so with
faithful semantics every task eventually parks on a semaphore only real
hardware would post. That is a modelling gap, not a time budget.

**Two levers, both already wired:**

- `longrun.build(unblock=True)` force-satisfies any pend whose count is <= 0.
  This is what makes the draw task draw. It changes semantics -- nothing ever
  really waits -- so inter-task ordering under it is not the hardware's, and it
  is wrong to enable before ~400M (it livelocks the early boot).
- the boot-mode flag word at `0x40288190`: setting bit 5 creates the serial
  console task. Bit 6 is a deliberate halt; leave it clear.

**Fidelity rule, learned the hard way:** resuming a snapshot requires the same
*hook set*, not just the same Machine. `spin()` must not inject ticks at chunk
boundaries -- vector 32 is `trap #0`, so that forces a reschedule inside
arbitrary code and the run silently diverges. `build()` now installs the depack
clamp and idle-spin ticks to match `dspboot.run`; verified by reproducing the
from-entry task-creation timeline exactly.

### What *is* worth doing

1. **Use snapshots as the normal working mode.** Never re-run from entry.
   ```sh
   uv run python -m emu.checkpoint make 60000000,120000000,200000000,280000000
   uv run python -m emu.longrun snapshots/boot280M.snap 200000000
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

- **Console (nearest to done).** Set bit 5 of `0x40288190` before the init task
  reaches `0x400cf384`, resuming from `boot200M`; the task is created and
  starts. It then runs 22 instructions and blocks at
  `jsr $40001928` on the queue at `0x40388eac`. That primitive is a ring buffer:
  it loops while the item count at `4(a2)` is zero, pending on the semaphore at
  `a2+8` (`0x40388eb4`). Posting that semaphore is **not** enough -- an item has
  to be enqueued. The producer reaches the queue by pointer, so pull on the
  registration at `0x400cd5a8` (`jsr $40110592`, object `0x40303e50`).
  Hook `print` at `0x400054b4` to capture output; protocol words are `#HELLO`,
  `#BREAK`, `#UPGRADE`, not `help`.

- **Draw path: solved.** `emu/frame.py` from `boot400M` with `unblock=True`
  renders 84 frames into the panel Bitmap at **`0x4313b298`**. The rasteriser
  needed no callable entry point -- only a working scheduler.

- **Text rendering**: still never located. Unchanged from before; the font is
  probably runtime-constructed. Now that the panel actually draws, the cheaper
  attack is to diff `setPixel` traces between UI states rather than hunt for a
  glyph table statically.

- **The five other uncreated tasks** (`0x401136ee` p3, `0x40127c78` p4,
  `0x40127d9e` p4, `0x40127b24` p5, `0x4012606a` p6) are each gated somewhere
  similar; the console one was gated on a single flag bit.

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
7. **Vector 32 is `trap #0`.** Injecting it as a "timer tick" forces a
   scheduler reschedule inside whatever code is running. It is not a timer, and
   using it as one makes resumed runs diverge from the runs that produced their
   snapshots. Tick idle spins instead (`build()` does).
8. **A resumed run needs the same hooks, not just the same Machine.** Trap 4
   above is the loud version; the quiet version is a *missing* hook -- `build()`
   lacking the depack clamp and idle-spin ticks changed where boot went without
   any error surfacing.
9. **"Stalled" metrics lie.** The stall detector flags any hot address after a
   window with no *new* coverage, so ordinary hot arithmetic (`__mulsf3` at
   `0x40175288`) reads as a hang.
10. **`ERROR_headerVersion_wrong`** and friends in MAIN OS are the **LZ4 frame
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
| Boot-mode flag word | `0x40288190` -- bit5 = console task, bit6 = halt |
| TCB layout | `+00` next, `+0C` d0-d7/a0-a7, so `+2C` a0 and `+48` a7 |
| Parked task PC | on its own stack: `[a7]` frame word, `[a7+4]` PC |
| Panel Bitmap instance | `0x4313b298` |
| Console task / queue | entry `0x400cd594`, queue `0x40388eac`, sem `+8` |
| sem_pend A / B | `0x4000141a` / `0x400013a6`; sem_post `0x4000148c` |
| queue receive | `0x40001928` |
| Bitmap::setPixel | `0x40104eb4` — `setPixel(Bitmap*, x, y, val)` |
| px_copy_to_bitmap | `0x400d315e` |
| Bitmap layout | `+04` w, `+08` h, `+0C` stride (words/column), `+10` data |
| Panel | 128x64, **1bpp**, column-major, 32 rows/word, MSB = lowest y |
