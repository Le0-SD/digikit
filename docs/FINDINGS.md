# Digitakt II OS 1.15C — findings

Target SHA-256 `62d588456e47194bd56dfee9568fb9dd4521c4ff1e8b5427eb461355532e8c6c`
(matches the target of `lalzart/digitakt-ii-firmware-research-public`).

Evidence classes used below:
**[V]** verified by running it here · **[D]** documented by prior research, not
re-checked · **[O]** open / nobody has established this.

## Container

`.syx` → SysEx transport (13,346 × 128-byte messages, `F0 00 20 3C 14 00 …`)
→ 8-in-7 bit decode → 8-byte preamble (content checksum at +4) → ELE3
container, 1,347,728 bytes, five aPLib-compressed sections. Nothing encrypted. **[V]**

| id | name | decoded | dest / meaning | what it is |
|---|---|---|---|---|
| 5 | meta | 15 | — | build stamp `250910 15:18:30` |
| 2 | "DSP" | 30,302 | `0x0200` = **version**, loads `0x80000400` | **the bootstrap** — misnamed in the tool |
| 3 | MAIN OS | 3,177,312 | `0x40000400` | the C++ application |
| 4 | updater | 32,776 | `0x80000400` | stored raw, not compressed |
| 7 | blob | 320,780 | — | SHARC ADI loader records |

Section 2's `dest` is not a load address. All 101 absolute call targets in it
land in `0x8000____`; solving for the base that makes its pointer table hit real
string starts gives `0x80000400` with 96 hits. **[V]**

## Integrity — not a barrier to patching

- Per-packet transport checksum; 32-bit content checksum; **HMAC-SHA256** trailer.
- No RSA/ECDSA anywhere. The HMAC **key is derived from material inside the
  firmware itself** — anchor `be f9 a3 f7 c6 71 78 f2` at section 2 +`0x6BF4`,
  followed by `"Master Overdrive\0"` and a 32-byte constant. **[V]**
- Round-trip is lossless: extract → rebuild → re-extract returns all five
  sections byte-identical, checksums and HMAC verifying. The rebuilt `.syx` is
  *not* byte-identical (the tool's aPLib packer beats Elektron's by 80,880
  bytes) and **that does not matter** — see below. **[V]**

## Byte-identical packing is unnecessary

The device's own depacker at `0x80000432`, run under Unicorn, decompresses both
Elektron's original streams and the tool's repacked ones to **identical
SHA-256**, all three compressed sections including the full 3.1 MB MAIN OS.
Nothing in the acceptance path hashes the original compressed bytes. **[V]**

Reproduce: `./venv/bin/python emu/oracle.py`

## The version gate

Upgrade routine begins `0x80001c48`. The gate is at the top, before anything is
displayed or written:

```
80001c66  mvz.w  -$4(a6), d3        ; INCOMING bootstrap version
80001c6a  mvz.w  $80000408.l, d0    ; RUNNING bootstrap version (= 0x0200)
80001c70  cmp.l  d3, d0
80001c72  bcc.w  $800021dc          ; current >= incoming -> EXIT, no upgrade
```

`bcc` is unsigned ≥, so BOOTSTRAP UPGRADE runs **only** when the incoming
version is strictly greater. Re-flashing 1.15C over 1.15C never triggers it. **[V]**

`0x71F9` is `mvz.w`, a ColdFire-only opcode Capstone cannot decode — a naive
sweep desynchronises directly on top of this instruction and reads the gate as
garbage. Use Ghidra's `68000:BE:32:Coldfire` or `dt2/coldfire.py`.

The later "VERSION CHECK" screen at `0x80001e52` is a milder equality check that
the decompressed image declares the version its header claimed. **[V]**

## Recovery

The bootstrap owns the STARTUP menu (`0x8000650d`), the factory test mode, and
`READY TO RECEIVE` (`0x80006603`) — the legacy MIDI-DIN upgrade path. It is
independent of MAIN OS and validates only:

1. content checksum — word-sum, each word XORed with its index (`0x40003ca6`)
2. HMAC-SHA256 trailer (`0x80005e2a`; SHA-256 H0 at `0x800058bc`, K-table at `0x80006ef8`)

**No version comparison on this path.** On failure: "UPGRADE ABORTED" and a spin
loop, nothing written. **[V]** That a corrupt MAIN OS still lets the menu come up
is a strong inference from the code layout, not demonstrated. **[O]**

## What is patchable

MAIN OS holds parameter state and RPCs it to the SHARC — shared structs appear
under a `Digisharc` namespace (`sound_struct`, `fx_setup_struct`,
`logicalParamID_t`, `modTarget_t`, `rpcMsgHeader_t`, `kitStorage_v*`). Machines
and filters are labels and parameter IDs on the ColdFire; audio runs on the DSP. **[V]**

- **247,996 bytes (7.8% of MAIN OS) in 1,392 contiguous string tables.** Machine
  and filter names (table at `0x4022b20e`: `WERP`, `STRETCH`, `REPITCH`,
  `SLICED SMP`/`SLIC`, `STATE VARIABLE`/`SVAR`, `LOWPASS 4`/`LP4`, `EQUALIZER`,
  `COMB-`/`COMB+`, `LEGACY LP/HP`), 24 KB of factory sample paths, mod sources,
  song sections, the random-project-name word list. Same-length editable. **[V]**
- Constants, ranges, defaults; size-preserving ColdFire logic.
- **Adding a new machine**: not architecturally closed, but expensive and
  unverifiable. Section 7 is a real ADI loader stream (32 blocks, only 178,796
  of 320,780 bytes actually loaded, with unloaded gaps of 46/52/80/337/691 KB —
  unloaded is not the same as free). ADI's CCES compiler is a free download. The
  real blocker is that there is **no SHARC emulator or disassembler module**, so
  every DSP iteration is flash-and-listen on hardware. **[V]/[O]**

## Emulation

Function-level works well and is the practical path. Full boot was pushed as far
as it would go; four blockers were cleared, **two of them Unicorn defects**:

| # | blocker | nature | distinct addrs after |
|---|---|---|---|
| 0 | no exception dispatch / `rte` / interrupts | emulator | 444 |
| 1 | `FF1.L` at `0x401112de` — undecodable by Capstone, unimplemented in Unicorn | **emulator** | **36,474** |
| 2 | `USR8` bit 2 (TXRDY) poll, `0xEC070004` — **UART8** | hardware | 37,395 |
| 3 | `movec d0,Rc=0x009` at `0x400cf7e4` — aborts the Unicorn process (SIGABRT) | **emulator** | — |
| 4 | `DSPI0_SR` RXCTR poll, `0xFC05C02C` — **DSPI0** | hardware | 38,193 |

Peripherals identified from NXP *MCF54418RM* Rev. 5 (Table 1-4; ch. 40 §40.3.4–
40.3.7; ch. 41). Only eight distinct peripheral registers are read in the whole
boot, and peripheral setup is read-modify-write that works fine against zeros. **[V]**

### The SPI flash needs no physical dump — correction

An earlier reading of stall 4 concluded the firmware wanted "real bytes off an
SPI device we have no image of", implying a hardware dump was required. **That
was wrong.**

`0x401296fe` is the SPI NOR read routine, signature `read(offset, len, dest)` —
confirmed by `0x84020003 -> DSPI0_PUSHR`, whose low byte `0x03` is the NOR READ
command. Its callers scan the ELE3 section table at flash offset `0x80020`. The
flash content it wants at boot **is the staged OS container**, which is exactly
what `dt2.container` decodes out of the `.syx` we already have.

High-level-emulating that one function and backing it with the container (see
`emu/flashboot.py`) makes boot progress immediately, and the reads it issues
confirm the model is right: **[V]**

```
off=0x080000 len=32      -> 0x44e4d67c    ELE3 header, into the exact address
                                           MAIN OS compares at 0x40128b8c
off=0x080020 len=16  x5                    the five section-table entries
off=0x19be60 len=184844  -> 0x45020a90    section 7 = the SHARC DSP blob
```

Coverage 36,483 -> 37,627 distinct addresses, and the firmware is now loading the
DSP image. The next frontier is the ColdFire<->SHARC link (DSPI2/eDMA), not
another storage problem.

Note the UI draws into a `Bitmap` object (`SoundBrowser::drawMain(Bitmap&)`),
so rendering the screen is a matter of locating that buffer once boot gets far
enough — not of reverse-engineering a display controller. **[O]**

What a physical dump *would* still be needed for: the +Drive contents (samples,
projects), which live elsewhere in flash and are not required to boot.

Also unresolved: `m68k` `SR` must be written **before** `A7`, or the stack
pointer lands in the banked register the CPU is about to stop using. Cost an
hour; noted in `emu/harness.py`.

## Open questions

- Does MAIN OS's USB upgrade path reject a same-version image? It carries
  "Downgrade not possible" (error code 6, formatter at `0x400fb524`) but never
  reads the container version string at an absolute address, so the comparison
  was not located. **[O]**
- Is the bootstrap rewrite atomic once triggered? **[O]**
- Sample/project/preset on-flash layout. `MmcFs`, `/factory`, and the manager
  classes are visible; the partition and directory format is not mapped. **[O]**
- `ERROR_headerVersion_wrong` and friends in MAIN OS are the **LZ4 frame error
  enum**, not OS versioning — a false lead worth recording.

## Display

The panel is **128 x 64, 8 bits per pixel**, read straight out of the firmware's
own structures rather than guessed. **[V]**

`intro_dither::px_copy_to_bitmap(PixelData&, Bitmap&)` at `0x400d315e` — the
binary carries the *demangled* signature as an assert string at `0x401f7ef0`,
which makes it an unusually good anchor. From its argument handling and copy
loop:

```
Bitmap      +0x04  width
            +0x08  height
            +0x0C  stride -- 32-bit words per COLUMN
            +0x10  pixel data pointer
PixelData   +0x00  width
            +0x04  height
            +0x08  8bpp row-major source buffer
```

Pixels are **column-major, 1 bit per pixel**, 32 rows packed per big-endian
word, MSB = lowest y:

    word_index = x * stride + (y >> 5)      bit = 0x80000000 >> (y & 31)

recovered from `Bitmap::setPixel` at `0x40104eb4`. An earlier draft of this
document called `+0x0C` a setPixel function pointer; that was wrong -- it came
from a different routine at `0x400d3244` where the register did not hold a
Bitmap. The panel is 1bpp, not 8bpp: the 8bpp `PixelData` is a greyscale source
thresholded on the way in.

The intro's `PixelData` instance lives at `0x4028ae98` and reads
`width=128, height=64, buffer=0x43139290`. The loop bound `cmpi.l #$2000`
(8192 = 128x64) at `0x400d3640` corroborates it, as does the runtime struct,
which reads back `0x80, 0x40, 0x43139290` under emulation.

**Not yet captured: actual pixels.** The buffer is allocated at runtime and is
still all zeros after 80M instructions — boot parks in DSP init before the intro
renders. Two ways forward, neither attempted:

1. Progress boot past the ColdFire<->SHARC handshake so the UI runs naturally.
2. Call the intro renderer at `0x400d3372` directly. It has no direct callers
   (`jsr (a2)`, `jsr (a5)` — invoked via lambda/vtable), so a harness would have
   to supply the allocator and callback registers. **[O]**

Note the drawing path is pure ColdFire — `MainScreenView`, `SoundBrowser::drawMain(Bitmap&)`,
and ~140 item-renderer lambdas of shape `(int, Bitmap&, int, int, bool)`. Nothing
in it needs the DSP, so route 2 should not require the SHARC at all.

### Rendering firmware graphics without booting **[V]**

`emu/screen.py` runs the device's own drawing code and captures the output. The
mechanism, and one correction to the note above:

`px_copy_to_bitmap` does **not** dispatch through `Bitmap+0x0C`. It loads a
fixed address into `a4` and calls that: `0x40104eb4` is the real
`Bitmap::setPixel(Bitmap*, x, y, value)`. Intercepting that address captures
every pixel without needing to know how `Bitmap` stores them. (`+0x0C` is used
by a *different* renderer at `0x400d3220`, so the harness intercepts both.)

The source is thresholded to 1 bit on this path — `cmpi.l #$80` then `shi.b` at
`0x400d31d8` — so an 8bpp greyscale `PixelData` becomes a monochrome Bitmap.

Validated against ground truth rather than by eye: feed a synthetic 40x16 source
through the firmware routine and the captured pixels match the thresholded input
exactly, 640 setPixel calls for 640 pixels. `./venv/bin/python emu/screen.py selftest`

This matters because a wrong `PixelData` renders as *plausible dither* rather
than failing — several structs found by heuristic scanning are false positives.
Locating genuine static image assets is still open. **[O]**

### Text rendering — still open **[O]**

Not found yet, and the obvious routes came up empty:

- 27 distinct functions call `setPixel`; **none walk a string** (no `move.b (aN)+`
  over a char buffer), so text must go through a glyph blitter one character at
  a time, called from a higher-level loop.
- No standard 5x7 or 6x8 bitmap font table is present (searched for the
  distinctive `'!'` glyph `00 00 5F 00 00` and variants).
- `PopupWindow(const Bitmap*, ...)` and `VerticalMenuView(const char*, int,
  std::string, const Bitmap*, int)` show `Bitmap` is used as an icon type, but
  scanning for static instances in the recovered layout finds none - icons are
  constructed at runtime, so the glyph/icon data is probably stored compressed
  or generated.

The rendering harness itself is done and verified, so once a text routine is
located it can be driven immediately.

### Why full boot stalls — the real reason **[V]**

The RTOS task created at boot (entry `0x400cef6c`, stack `0x4000`, priority 1)
**is the DSP bring-up task**. Walking the call tree upward from the ColdFire<->SHARC
transport lands exactly on it:

```
0x40128c7c   transport: write arg -> DSPI 0xFC074004, kick 0x841b -> 0xFC074000,
             then block on a semaphore the completion ISR would signal
  <- 0x400cf000, 0x400cf928, 0x400cfd8a, 0x4012d46e   (4 call sites)
    <- 0x400cef6c   the task entry itself
```

The transport installs an ISR at vector 97 (`0x40000184`), enables INTC sources
`0x21`/`0x1d`, starts the transfer and waits. Firing the completion interrupt by
hand gains only ~330 addresses; stubbing the transport outright gains nothing and
just moves the stall to `0x400cf956`. Four call sites means DSP bring-up is a
**stateful conversation**, not one transfer.

This is a genuinely different wall from the SPI flash. There, the data we needed
already existed in the `.syx`. Here the ColdFire is waiting on replies from a
processor with no open emulator, so the responses would have to be *synthesised*
from a protocol nobody has documented. Boot cannot complete without that, and the
UI task presumably never starts because DSP init never finishes.

**Update (next session): the "do not pursue" call above was too pessimistic.**
The DSP handshake did not need real SHARC replies synthesized -- it needed the
*ColdFire-side* synchronization primitives satisfied, which turned out to be
inspectable and fakeable without modeling the SHARC at all. See "DSP bring-up
-- session 2" below: `task_create` sites reached went from 4/16 to 10/16 this
way. The capability table remains accurate for what *doesn't* need booting:

| capability | status |
|---|---|
| CRC-32 oracle (`0x80001bd0`) | works, byte-exact |
| aPLib depacker (`0x80000432`) | works, validates a 3.1 MB repack |
| firmware graphics rendering (`emu/screen.py`) | works, pixel-exact vs ground truth |
| Bitmap framebuffer encode/decode | works, verified two independent ways |
| full boot to UI | in progress -- 10/16 `task_create` sites reached, see below |

## DSP bring-up -- session 2

Starting point: 4/16 `task_create` (`0x400012c8`) call sites reached, ~37,627
distinct code addresses, stuck inside the DSP-transport wait at `0x40128c7c`.
Ending point: **10/16 `task_create` sites, 58,337 distinct addresses.** New
tooling: `emu/dspboot.py` (instrumented boot harness, reusable) and a scoped-hook
speedup added to `emu/harness.py`. All of it verified by running, not inferred.

### Blocker 1 (cleared): the transport is a mutex+semaphore wrapper, not an RPC

Re-reading `0x40128c7c` disassembly line by line (not just skimming) shows it
is **not** "send a request word, wait for a reply word" as the earlier session
guessed. It is:

```
lock mutex @0x44e4d6a4                          (0x400015a0)
  (first call only: install ISR @0x40128c4c at vector 97,
   enable INTC sources 0x21/0x1d, init completion sem @0x44e4d69c to 0)
write timeout(!) -> 0xFC074004
write control word 0x841b -> 0xFC074000          (kicks the transfer)
jsr 0x4000141a   (sem_pend on 0x44e4d69c)        <-- blocks here
unlock mutex (tail call into 0x400016d2)
```

The value each of the 4 call sites pushes (`0xF4240`, `0x3E8`, `0x64`,
`0x2DC6C0` = 1,000,000 / 1,000 / 100 / 3,000,000) is a **microsecond timeout**
written to hardware, not a command/payload word -- it is never read back by the
ColdFire side. The real completion signal is the semaphore at `0x44e4d69c`,
which the would-be completion ISR at `0x40128c4c` posts to via
`0x4000155c -> 0x400011ee`.

Critically, `0x4000141a` (sem-pend) has a fast, non-blocking path: if the
semaphore's count field is already `>0`, it clears it and returns immediately
without ever calling the scheduler (`trap #0`) -- and **every one of the 4
callers discards its D0 return value** (overwritten immediately after the
call), so nothing downstream ever checks "did the transfer really succeed."

**Patch**: at `PC == 0x40128d08` (the `jsr 0x4000141a` instruction itself),
write `1` into the 4 bytes at `0x44e4d69c` before it executes. No interrupt
firing, no scheduler re-entry, no `rte` -- just pre-satisfying the flag the
very next instruction is about to check. This is different from, and more
surgical than, the earlier session's attempts (firing vector 97/33/29 by hand,
or blanket-stubbing the whole transport function), which is presumably why
those only gained ~330 addresses or moved the stall without progress.

Result: the one transport call site actually reached at this point in boot
(`0x400cf928`, timeout `0x3E8`) goes through. Two more polled hardware status
registers immediately downstream needed the same treatment, discovered by
running and reading what changed at the new stall PC:

- `0xEC03802C` bit 31 (`0x400cf956`, a byte-at-a-time TX loop unrelated to the
  already-known UART8/DSPI0 mocks -- a *second* status register pair,
  `0xEC094018`/`0xEC03802C`, spent uploading what is very likely the SHARC ADI
  loader blob byte-by-byte after the handshake succeeds)
- `0xFC05C02C` bit 28 / RFDF (`0x40129da2`) -- same DSPI0 status register
  already mocked for RXCTR, but a *different* bit, tested by a second,
  synchronous SPI0 read routine reached only after the transport unblocks

Both mocked the same way as the pre-existing UART8/DSPI0 mocks: force the
polled bit permanently set in `Machine.mmio`.

### A red herring that turned out to be correct behavior, not a bug

Past the above, boot hit a second embedded aPLib-style depacker at
`0x4012ab70` (distinct from the bootstrap's `0x80000432`, and from the
flash-section-table depacker used by MAIN OS's own boot-time decompression --
this one runs on in-memory buffers during DSP bring-up). One invocation
(source `0x402489b4`, a *static address inside the already-loaded MAIN OS
image*, not flash- or DSP-reply-dependent) appeared to run away: 2.6M+ hits at
the same 3 addresses (`0x4012acba/bc/be`, its copy loop) with zero new code
coverage for tens of millions of instructions -- classic infinite-loop
signature.

It is not one. Register tracing (dump D2/D3/A1 on every entry to the copy
loop) showed match lengths never exceeding ~2KB; the "stall" was thousands of
small, legitimate tokens through a tight loop, which the coverage-based stall
heuristic cannot distinguish from a hang because it only tracks *new* PCs, not
forward progress within a loop. Independently ruled out a Unicorn MVZ/MVS
decode bug (the specific opcode class flagged as broken in Capstone) by
testing `mvz.b`/`mvs.b` in isolation, register and `(a0)`/`(a0)+` addressing --
all matched 68k semantics exactly. Given more instruction budget (400M+) this
depacker completes normally and boot proceeds. A defensive safety valve was
added anyway (clamp the copy count if it ever exceeds 64K, `DEPACK_COPY` in
`emu/dspboot.py`) but it has never actually fired -- included for whatever
comes next, not because it was needed here.

**Lesson for next time**: before concluding a repeating-PC "stall" is a hang,
dump the actual loop-bound register(s) a few times. A slow-but-finite loop and
an infinite one look identical to a coverage-only heuristic.

### Blocker 2 (cleared, and generalized): idle spins need timer ticks too

With the above fixed, boot progressed in a large burst: task_create sites went
4 -> 5 -> 9 -> 10 as longer instruction budgets were tried (47M, 257M, 416M).
Between two of those bursts, boot hung again -- this time truly, 139M+
instructions with zero new coverage, at `0x400cf3e0`.

`0x400cf3e0` disassembles to `bra.b $400cf3e0` -- a literal self-branch. This
is the **exact same idiom** as the already-known `HALT` idle loop
(`0x400ceeb6`, also `bra.b $self`), which the harness already fed periodic
timer ticks (vector 32) to keep the RTOS scheduler moving. But the harness only
ever ticked *that one hardcoded address* -- a second thread/task's own
idle-wait-for-scheduler point at a different address got no ticks at all, so
once execution reached it, nothing could ever preempt it.

**Fix, generalized rather than special-cased**: scanned all of MAIN OS for the
opcode `0x60FE` (`bra.b -2`, i.e. branch-to-self) -- 13 occurrences total --
and feed periodic timer ticks to *all* of them, not just the one instance
someone happened to hit first (`find_idle_spins` in `emu/dspboot.py`). This is
exactly the kind of fix the diverging/converging distinction in the task brief
calls for: a class of blocker, not a single address.

This got two of the three known idle points working correctly (`0x400ceeb6`
and `0x400cf3e0` both now receive ticks and both did unblock at least once,
confirmed by `spin_by_addr` counters saturating at clean multiples of
`tick_every`).

### Where it stands now: a new, different kind of stop

After the burst that reached 10/16 (last new task at instruction ~416M,
`0x400f1a6c` -> entry `0x400f1eb6`, prio 2), execution parked at `0x400cf3e0`
and stayed there for the rest of a 1.4B-instruction run -- ~48,000 further
timer ticks, zero new coverage.

Traced precisely (not just inferred from the address repeating): `0x400cf3e0`
sits between a one-shot guard and a permanent idle trap in the *same* function
that produces 3 of the burst's 4 tasks:

```
400cf3d6  moveq #$40,d0
400cf3d8  and.l $40288190.l,d0
400cf3de  beq.b 400cf3e2                 ; bit clear -> do the work (it was clear: confirmed 0x40288190=0x04 at runtime)
400cf3e0  bra.b 400cf3e0                 ; <-- idle trap, same idiom as HALT
400cf3e2  jsr 0x4011311c                 ; wrapper containing task_create site 0x401131d2 (prio 7)
400cf3e8  jsr 0x4014635e                 ; wrapper containing task_create site 0x4014638e (prio 5)
400cf3ee  jsr 0x400329ee                 ; wrapper containing task_create site 0x40032a20 (prio 6)
400cf3f4  bra.b 400cf3e0                 ; done -- park here forever by design, same as HALT
```

So this is **not** a guard repeatedly failing -- it passed once, did its
one-shot job (matching the 3 near-simultaneous hits at instructions
257710408/257710485/257710555), and then deliberately loops to the same idle
trap as its designed terminal state, exactly like `HALT`. There is nothing
further for *this* thread to do; it is functioning correctly. This resolves
what looked like an open question in an earlier draft of this note.

The real open question is why **no other** thread creates any of the
remaining 6 `task_create` sites even after tens of thousands of scheduler
ticks. The newly-created prio 2/5/6/7/8 tasks are themselves candidates to be
the ones that would create more (or not -- they may simply be leaf worker
tasks). Two live hypotheses, neither confirmed:

1. One of the **other three** DSP transport call sites (`0x400cf000` timeout
   `0xF4240`, `0x400cfd8a` timeout `0x64`, `0x4012d46e` timeout `0x2DC6C0`) is
   what some other task is blocked on -- all session, only one of the four
   (`0x400cf928`) has ever been exercised (`transport calls: 1` in every run).
   If a task is parked in a *real* semaphore wait (`trap #0`, correctly
   descheduled by the RTOS) rather than a self-branch idle loop, our idle-spin
   fix does not apply to it -- it needs the same treatment as blocker 1
   (satisfy whatever it is actually waiting on), not more timer ticks.
2. The remaining 6 sites are in code that is reachable only through a
   different subsystem-init path this cascade never calls into at all under
   this configuration (not blocked -- just not on the current call graph).

**Checked, and it points at hypothesis 1.** For each of the 6 tasks created
after the first burst (prio 7/8/7/5/6/2), coverage tracking shows the RTOS
scheduler *did* switch into every single one of them -- their entry addresses
are all in `seen`, each followed by a small additional cluster of newly-hit
addresses (6 to 31 distinct addresses within a few hundred bytes of its entry
point). So `task_start` is not merely called on all 10 tasks
(`task_start hits: 10`, already known) -- the scheduler genuinely gave CPU
time to the 6 newest ones, each ran a handful of real instructions, and then
every single one went quiet with no further coverage growth for the rest of
a 450M/1.4B-instruction run. That is the signature of each one reaching its
own short init sequence and then hitting a genuine blocking wait very
quickly -- not of the scheduler failing to reach them (hypothesis 2, now
effectively ruled out) and not of them running unboundedly (they are not
CPU-bound). **Concrete next step**: for each of these 6, disassemble the
handful of instructions right past where its coverage cluster ends -- that
boundary is exactly where each one blocks, and is a small, bounded amount of
code to read per task (nothing like the earlier multi-hundred-instruction
transport functions).

### Convergence assessment

Up to 10/16: **converging**. Each fix (semaphore fast-path, two MMIO bit
forces, generalized idle-spin ticking) unlocked either the next blocker or a
burst of several `task_create` sites at once, and the depacker "stall" that
looked alarming turned out to be a false alarm resolved by patience, not a
patch. Past 10/16: **stalled, not diverging** -- one clearly-identified
address, no new blockers appearing, but the fix used for the last two blockers
(generic timer ticking) is confirmed insufficient here and the next fix needs
actual tracing of `0x40288190`'s producer(s), most plausibly tied to one of
the three still-unexercised transport call sites.

### Performance: a 2x+ harness speedup, reusable

`emu/harness.py` and `emu/dspboot.py`'s original hot path ran a single global
`UC_HOOK_CODE` callback on *every instruction*, which for the FF1/MOVEC
patches did a `mem_read` + `struct.unpack` unconditionally to check "is this
one of the two rare opcodes" -- on every single instruction of the run, not
just the rare ones. `Machine.install_isa_patches_scoped` (new) pre-scans the
image once for the actual FF1 (`0x04C0`-`0x04C7`, 232 hits) and MOVEC
(`0x4E7A`/`0x4E7B`, 7 hits) opcode addresses and registers a Unicorn hook
scoped to each exact address (`begin=addr, end=addr`) instead. `emu/dspboot.py`
does the same for its own instrumentation points (`fast=True`, the default;
`fast=False` keeps the original global-hook path for cross-checking). Measured
on identical 60M-instruction runs: 146s -> 73s wall-clock, same result
(verified byte-for-byte identical task_create hits, addresses, priorities).
This matters because runs at the scale needed here are 400M-1.4B instructions
(9-25+ minutes each even with the speedup).

### Reusable artifacts from this session

- `emu/dspboot.py` -- the instrumented DSP bring-up harness. Reports
  `task_create` sites reached (with entry/priority/tcb), transport call sites
  hit, semaphore-satisfy count, depack-clamp count, idle-spin addresses found
  and hit counts, distinct-address coverage curve, and stall PCs. Run directly:
  `./venv/bin/python -m emu.dspboot <instruction_limit> <patch_sem 0|1>`.
- `emu/harness.py` -- added `Machine.install_isa_patches_scoped`, a drop-in,
  much faster alternative to `install_isa_patches` for long runs.

### Next blockers, named **[V]**

After reaching 10/16 tasks, the remaining ones start and then go quiet. Measured,
not guessed:

1. **They are not blocked on semaphores.** There are two counting-semaphore pend
   primitives, both with a fast path when count > 0: `0x4000141a` and
   `0x400013a6`. Logging every call to both across 150M instructions finds
   **exactly one** — the already-patched transport wait at `0x40128d0e`. So the
   stalled tasks are not waiting on anything; they are not being scheduled.
   (`emu/blockers.py` does this logging.)
2. **The scheduler is hand-cranked.** Injecting `trap #0` (vector 32 — the
   task-switch trap) is the only thing that helps. Compared at 60M instructions:

   | injected vector | tasks | distinct addrs |
   |---|---|---|
   | 32 (trap #0) | 5 | 38,247 |
   | 66 | 2 | 329 |
   | 221 | 2 | 260 |
   | 222 | 2 | 260 |

   The candidate hardware ISRs installed during init (vectors 221/222/66 →
   handlers `0x400019bc`/`0x400019e6`/`0x40001a10`) are **not** the system tick.
   So we are forcing context switches rather than running a real scheduler.

**The prize is identified.** Task `0x400d3fb6` (prio 7, created at instr 47M) is
the **intro/animation task**: it calls a RNG at `0x40144bd8`, compares results
against `0x7fdf` and `0x3ffe`, and selects among static structs at
`0x4028ae5c`/`0x4028ae6c` — the same neighbourhood as the known intro
`PixelData` at `0x4028ae98`. If that task runs, it draws, and `emu/screen.py`
can capture the result.

**So the next blocker to attack is the scheduler itself**, not another
peripheral: find the real tick source, or drive the context-switch path directly
against the ready-list/TCB structures so tasks round-robin properly. **[O]**
