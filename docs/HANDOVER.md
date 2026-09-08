# Handover: make interrupt delivery sound, then the OS can draw

Cold-start document for the next session. `docs/NEXT.md` is the project
overview, `docs/FINDINGS.md` is the evidence. This file is the current state
and what to do next.

---

## 0. Read this before believing any measurement

The chunk size is gone as a knob: `spin(..., pits=p)` runs to each timer
deadline exactly. The knob that remains is `INSTR_PER_SEC`, and **the run is
very sensitive to it**. Over 150M instructions from `postintro.snap`, at the
calibrated 4.68M the display task starts, six tasks spawn and nothing faults;
at 4.21M the display task never runs at all; at 5.62M the run reaches
`abort()`. Sweep it before believing anything downstream of interrupt
delivery. A result that only holds at one rate is not yet a finding.

Do not use `spin`'s `cap` argument for measurement. Subdividing `emu_start`
changes the emulated result once interrupts are being injected, even though
the injections land at identical instruction counts and the counts themselves
are exact. See section 5.

Related: commit `937541f` is titled *"Identify the post-intro blocker: a C++
throw nothing can unwind"*. **That conclusion is wrong** and is superseded by
`b2d06e7`. Do not take it at face value when reading the log.

---

## 1. Where things stand

The intro problem is solved, and the OS now draws. Delivering PIT3 gets the
first post-intro pixels out of the firmware. Clean A/B from
`postintro.snap` over 60M instructions, no probe hooks on either side, only
the channel list differing:

| channels | PIT0 | PIT2 | PIT3 | tasks | switches | setPixel |
|---|---|---|---|---|---|---|
| 0, 2 | 587 | 708 | 0 | 2 | 3 | 0 |
| 0, 2, 3 | 615 | 741 | 75 | 6 | 8 | **8** |

Eight pixels is not a screen, but it is the first drawing the OS has done on
its own, and it is the difference between a task that is blocked forever and
one that is running.

**The GUI drives the timers now -- but the screen still stops at the intro.**
`emu/gui.py` ran `run_until` with no PIT model at all. It now runs
`spin(m, pc, BUDGET, pits=pits)` in 1M-instruction passes and reports PIT0,
PIT2, PIT3 and the instruction count on the status line. From
`boot400M.snap` it renders the intro at about 3.4 frames/s, then spawns the
six OS tasks and draws eight more pixels -- and that is all. **Eight pixels
is not a screen, so `uv run python -m emu.gui` still looks like it stops
after the boot animation.** It is doing more than it was; it is not yet
drawing anything you can see. Do not read the six tasks as a working OS.

Three things had to be right for the GUI to agree with the harness, and all
three are worth knowing before touching that loop:

* **Deliver nothing until the intro hands over.** This one is a trap that was
  walked straight into: every post-intro measurement in this document was
  made from `postintro.snap`, where the intro is already over, so the
  intro-still-running path went untested. Delivering into a live intro is
  worse than delivering nothing -- from `boot400M.snap` over 90M
  instructions, channels `()` and `(0,)` both reach six tasks while `(2,)`,
  `(3,)`, `(0, 2)` and `(0, 2, 3)` all reach zero, and `(3,)` never lets the
  intro exit at all. PIT3 posts the frame semaphore that `unblock` is already
  force-satisfying, so the draw loop never reaches its exit test. Construct
  as `Pits(m, hold=intro_running(m))` and `release()` from a hook on
  `INTRO_DONE`; `emu/gui.py` does exactly that.

* **`on_pixel` must not call `emu_stop`.** Under `spin` a hook that stops the
  run early makes the instruction accounting a lie -- emu_start returns having
  executed fewer instructions than it was asked for, the loop credits itself
  the full step, and the deadlines drift off the instructions actually
  executed. The worker takes its pause/stop latency from BUDGET instead.
* **In `pits` mode `instrs` is a floor, not a ceiling.** `spin` finishes the
  deadline step it is on rather than truncating to the budget, so every
  emu_start boundary is a timer deadline however the caller splits its work.
  Verified: 20M instructions from `postintro.snap` taken as 1, 4, 20 or 100
  successive `spin` calls give byte-identical memory, registers, timer counts
  and instruction totals. Before this, 100 calls diverged from 1.

**Why PIT3 never fired, and the stopgap.** On the `boot400M.snap` path PIT3
was due 281 times over 250M instructions and taken none of them. The cause is
exact: PIT3's period is **precisely eight times** PIT2's (624018.15 /
78002.30 = 8.000000), so once their deadlines line up they collide on the
same instruction for ever, and both sources are INTC level 3. `service` walked
channels in order `(0, 2, 3)`, so PIT2 was taken first, raised IPL to 3, and
PIT3 was then refused by its own `ipl >= lvl` test. Of 73 misses in a 120M
run, 33 were that collision and the other 40 were the firmware genuinely at
IPL >= 3 for its own reasons.

The default channel order is now `(3, 2, 0)`, which takes PIT3 130 times
instead of 0 and costs PIT2 misses rising from 29 to 160. That is a stopgap,
not a model -- see the `Pits` class docstring for the two principled fixes
that were tried and are both worse, and for the fact that the real tie-break
belongs to the INTC and needs the manual.

**Where it stops now.** With PIT3 delivered the prio-6 display task does wake
-- 130 times -- looks at `0x44e2d5cc`, finds it still zero, and correctly goes
straight back to sleep. Nothing ever calls the geometry setter at
`0x40125f6a` that would make it non-zero, so **the panel still shows the last
intro frame plus eight stray pixels**. That flag is the next blocker, and
Ghidra now gives the trail:

* `0x40125f6a` is tail-jumped to from two argument-shuffling thunks at
  `0x4003230c` and `0x40032320`.
* Both thunks are referenced as **DATA**, from `0x40032caa` (in fn
  `0x40032c5c`) and `0x40032bc6` (in fn `0x40032b9a`) -- so the setter is
  reached through a function-pointer table, not a direct call.
* The display init itself, `0x40125faa` (it creates the task at `0x4012606a`
  *and* starts PIT3 at `0x40126004`), is called from fn `0x40032f5a` at two
  sites.

So the whole display subsystem is driven from a module around `0x40032xxx`.
Start there, not in `0x4012xxxx`.

**Instrument sparingly.** The probe hooks used to measure this change it: the
same run with a wider set of `at()` probes reported the prio-3 task spinning
9.7M times and one `px_copy_to_bitmap`, and with a narrower set reported the
task entered once and no copy. PIT3's own counts (75 fires, 75 ISR entries)
and the task count were stable across both. Trust what does not move when you
change the probes.

### Verify the tree first

    uv run python -m emu.hle          # header-mutation ok=True
    uv run python -m emu.softfloat    # 0 mismatches
    uv run python emu/oracle.py
    uv run python emu/screen.py selftest
    uv run python -m emu.frame snapshots/boot400M.snap 20000000 out/frame.png
        # expect: setPixel 616823, 75 frames, 344 lit   <- the canary

### The working harness

`snapshots/postintro.snap` (54.7M instructions past `boot400M.snap`) is the
one to use for OS work: intro over, draw task parked, all six OS tasks alive,
iterating takes seconds. It needs no special setup any more.

    from emu.longrun import build, spin
    from emu.pit import Pits
    m, ev, st, pc, inq, at = build('snapshots/postintro.snap', unblock=True,
                                   softfloat=True, bitmap=True)
    p = Pits(m)                       # channels default to PIT0, PIT2, PIT3
    spin(m, pc, 60_000_000, pits=p)   # steps to each deadline; do not pass cap

Currently gives PIT0 615, PIT2 741, PIT3 75, six tasks, eight setPixel calls,
no fault, no throw, no abort, in about 25 seconds. Do not service the timers
from `on_chunk` as well -- `spin` does it when `pits` is given.

Caveat: `postintro.snap` was written before `raise_vector` started using
format nibble 4, so exception frames already on task stacks in it carry
format 0. Harmless while `rte` is implemented in `on_intr` and ignores the
field; it would matter if that ever became format-aware.

---

## 2. Done: deadline-accurate delivery, honest accounting, PIT3

**Deadline stepping.** `Pits.step(done, remaining, cap)` returns the
instructions left before the next timer is due, and `spin(..., pits=p)` passes
that to `emu_start` instead of a fixed chunk. The chunk size stops being an
input. The old table it replaces, which was pure harness artifact:

| chunk | PIT0 | PIT2 | fault | display callbacks | tasks |
|---|---|---|---|---|---|
| 20,000 | 514 | 617 | **523** | 5,796 | 0 |
| 30,000 | 633 | 756 | 0 | 6,269 | 0 |
| 40,000 | 612 | 736 | 0 | 29,591 | 2 |
| 50,000 | 602 | 728 | 0 | 47,484 | 2 |

Note the flatness criterion this replaces was weaker than it looked: with
deadline stepping the chunk is simply unused, so of course it no longer moves
the result. The honest test is section 0's rate sweep.

**Honest accounting.** `install_exceptions` now records `m.halt_vec` before it
stops the run, and `spin` breaks on it. Previously an unhandled vector stopped
emulation from inside the hook, `emu_start` returned normally having executed
nothing, and the loop credited itself a full chunk and raced to the budget.
The chunk=20,000 row above is exactly that: re-measured, it stops honestly at
49.5M with `unhandled vector 257 at 0x4010fd52`. Its "523 faults" were a
report of a run that had already died.

**PIT0 is periodic after all.** The "one-shot re-armed per time slice"
hypothesis does not survive reading the write. The switcher's
`move.w #$53f,$fc080000` has RLD (bit 1) set, so the counter reloads from PMR
on its own, and EN is already 1, so the write reloads nothing. What it does
set is PIF (bit 2, write-1-to-clear): it is the interrupt ack, not a re-arm.
Leaving `Pits` periodic is correct.

**PIT3 was the actual blocker.** See section 1.

---

## 3. Then, in order

1. **Understand the rate sensitivity.** Section 0. At 4.68M the display task
   starts; 10% either side and it never runs. Until that is understood, every
   post-intro result is conditional on one number. Start by asking what
   differs: at the rates that fail, is the task never made ready, or made
   ready and never scheduled?
2. **Deliver more of the armed interrupts.** See the census in section 3a.
   PIT3 was not the last of its kind: nineteen vectors have a real handler and
   a live, unmasked INTC source, and we deliver none of them.
3. **Model the `0x8C000002` device.** With PIT3 delivered the prio-3 task at
   `0x400f1fce` runs and spins on it for 9.7M of 60M instructions. The
   routine is at `0x400cf4a8`: write `0x80` to `0x8C00000A`, spin on bit 0 of
   `0x8C000002`, then write eight 16-bit words -- per input byte,
   `(byte << 8) | 0x80` then `(byte << 8) | 0x00`, four bytes, high byte
   first. Data in the high byte and bit 7 of the low byte pulsed high then
   low is a **clock strobe into a latch chain**, not a bus transfer, and bit 0
   of the status read is its ready line.

   **The old "forcing bit 0 is wrong" verdict does not survive.** It was
   reached under the fixed-chunk harness and its evidence was 245 faults at
   `0x40111458` -- inside the heap allocator, which is exactly where the
   subdivision artifact in section 5 lands. Re-measured with deadline
   stepping over 60M instructions: forcing bit 0 gives **zero faults, zero
   throws, zero aborts**, and takes the burst routine from 1 run to 858,310.
   What is actually wrong with "always ready" is the opposite of a crash: the
   task free-runs, hammering the device far faster than hardware would. The
   next step is a busy time, not a refusal.
3. **Wire `Pits` into `emu/gui.py`.** It does not drive the PIT model at all,
   which is why the GUI shows none of this progress. Small change, and it is
   how you would actually see the next win.
4. **Performance, last.** See section 6.

---

## 3a. The interrupt census -- how to find the next PIT3 in a minute

PIT3 was found the slow way: chase a blocked task back to the semaphore
nothing posts. The general form is a table read. For every vector, is a real
handler installed, is its INTC source enabled and unmasked, and do we ever
deliver it? Reconstruct it by reading `VBR + vec*4` for all 256 vectors after
a run, and for each one with a handler below `0x48000000` reading the source's
ICR level at `<intc>+0x40+source` and its mask bit in IMRH/IMRL.

Measured from `postintro.snap` over 60M instructions, **nineteen** vectors are
armed, unmasked, have a real handler, and are never delivered:

| vec | INTC | src | level | handler | what it is |
|---|---|---|---|---|---|
| 65 | 0 | 1 | 5 | `0x400cf424` | EPORT pin 1 -- acks `0xFC090006` bit 1 |
| 66 | 0 | 2 | 7 | `0x40001a10` | |
| 68 | 0 | 4 | 5 | `0x400cf450` | EPORT pin 4 -- acks `0xFC090006` bit 4 |
| 97 | 0 | 33 | 2 | `0x40128c4c` | |
| 99 | 0 | 35 | 2 | `0x400c30e4` | installed during the run |
| 108 | 0 | 44 | 5 | `0x400d8158` | |
| 121 | 0 | 57 | 2 | `0x400da136` | |
| 134 | 1 | 6 | 4 | `0x40006ece` | |
| 156 | 1 | 28 | 4 | `0x400021a0` | |
| 157 | 1 | 29 | 4 | `0x40002102` | |
| 168 | 1 | 40 | 7 | `0x40001252` | same handler as PIT1's vector 206 |
| 170 | 1 | 42 | 6 | `0x400d56a0` | |
| 180 | 1 | 52 | 3 | `0x40001d00` | |
| 181 | 1 | 53 | 4 | `0x40001f86` | |
| 182 | 1 | 54 | 2 | `0x400ced8c` | |
| 191 | 1 | 63 | 5 | `0x4002d652` | |
| 209 | 2 | 17 | 6 | `0x40005e10` | |
| 221 | 2 | 29 | 6 | `0x400019bc` | |
| 222 | 2 | 30 | 5 | `0x400019e6` | |

A third handler in the same driver block, `0x400cf47c`, acks eDMA channel 14
through CINT at `0xFC04401C` -- so that block is EPORT IRQ1, EPORT IRQ4 and
eDMA ch14, each dispatching a one-shot callback pointer it then clears
(`0x429307c8`, `0x429307c4`, `0x429307bc`).

An armed source is not proof the device would assert; most of these need the
peripheral modelled before they mean anything. But it is the complete list of
places where the firmware is waiting for something we never send, and the
naming is a lookup, not a hunt: **the MCF5441x reference manual's interrupt
source assignment table maps every (INTC, source) pair above to a module.**
Get that table before guessing at any of them.

Which peripherals the firmware actually programs, same run:

| module | register writes | writing PCs |
|---|---|---|
| eDMA | 6930 | `0x40001e86`, `0x400022e8`, ... |
| INTC2 | 761 | `0x4000043e`, `0x400014f0`, `0x4012600e`, `0x40126016` |
| PIT2 | 741 | `0x40002a32` |
| PIT0 | 691 | `0x40000444` |
| PIT3 | 78 | `0x40125f56`, `0x40126026`, `0x4012602c`, `0x40126036` |
| INTC0 | 2 | `0x400c3128`, `0x400c3130` |
| FlexBus CS | 1 | `0x400cf4e4` |

Never written at all post-intro: UART8, GPIO, INTC1, DSPI0, PIT1, EPORT.
Note INTC1 is never written yet carries nine of the nineteen armed sources --
they were set up before the snapshot.

---

## 4. What was fixed this session

**eDMA channel 35 (UART8 TX) -- `emu/edma.py`.** Boot stalled at exactly frame
88 of 175. Not a semaphore: `0x4000220c` is the console-enqueue routine and it
spins waiting for room in a 4096-byte TX ring, computing free space from
`TCD35.CITER/BITER`. Nothing advanced the channel. The model runs the whole
major loop on a write of 35 to EDMA_SERQ, advances SADDR with the ring modulo,
reloads CITER from BITER at major-loop completion, and raises vector 155 so
the firmware's own ISR does the bookkeeping.

**`unblock` narrowed by caller, not by semaphore.** `queue_receive`
(`0x40001928`) pends on the queue's semaphore then re-reads `queue->count`, so
satisfying it spins instead of sleeping -- 8.9M iterations, ~92% of post-intro
cycles. The rule is caller-based, which also removes the intro handoff
entirely: the intro loop pends the frame semaphore from `0x400d4038` (satisfy)
and the park loop pends the *same* semaphore from `0x400d4068` (do not).
`RECHECK_PENDS` in `emu/longrun.py` holds all three known sites.

**PIT0 delivery -- this was the real bug.** PIT0 is the RTOS time slice: the
context switcher re-arms it and unmasks its INTC source on every switch, and
vector 205's handler *is* the switcher. Delivering PIT2 without PIT0 gave the
RTOS timer ticks while denying it preemption; the result was not slower, it
was unstable. Adding PIT0 removed every abort and every spurious exception.

**`spin` did not re-read PC after `on_chunk`.** An `on_chunk` that raises a
vector left emulation resuming at the interrupted address with an exception
frame stranded on the stack; the next `rts` popped it as a return address.
This is what the previous session recorded as "injecting PIT interrupts
crashes the firmware". It does not.

**Exception frame format.** `raise_vector` wrote format nibble 0. The ColdFire
PRM is explicit that an RTE whose frame format is not 4-7 raises a format
error. Never showed because `rte` is implemented in `on_intr` and ignores the
field, but anything reading a frame we built saw one hardware would reject.

**`count=` on `emu_start` costs 1.8x.** It installs an internal
per-instruction hook. `run_until` is the uncounted form; the GUI now stops per
completed frame and runs at ~62% of real time against ~30% before. A
wall-clock `timeout` is free (4.43s vs 4.45s over the same work) where `count`
is not, so `run_until` takes `timeout_ms` to stay responsive.

---

## 5. Ruled out -- do not spend the time again

* **Not a Unicorn CPU bug.** `TST.L An` sets Z correctly for An and Dn;
  replaying the exact instruction sequence with the exact runtime register
  values behaves correctly; live code is byte-identical to the ROM image.
* **Not user/supervisor stack confusion.** Supervisor mode at every injection
  point (400/400 samples), IPL 0 at 384 of 400.
* **Not the INTC gating or the frame format on their own.** Both measured to
  change no outcome. Kept because they are what the hardware does.
* **Not the synthetic vector-32 idle tick.** Disabling it entirely (patch
  `db.find_idle_spins` to return `[]`) leaves every outcome unchanged.
* **Not `unblock` breaking a mutex.** Over 40M instructions only six pends are
  even candidates, and the allocator makes no pend calls at all.
* **Not the depack shortcut.** `ev['depack_clamps']` is 0 over the relevant
  run.
* **Not a corrupt timer-callback list.** All seven nodes at `0x4094cdb8` point
  at real code.
* **`reg_read_batch` is not a perf win.** Measured 0.74x -- *slower* than
  individual `reg_read` calls in unicorn 2.1.4.
* **Not inexact instruction counts, and not lost condition codes.** Both were
  measured directly. `emu_start(count=N)` executes exactly N: over 300k
  instructions, split 60 ways or run in one call, a per-instruction hook
  counts N either way. And stopping between a compare and its branch does not
  lose the flags -- a standalone `cmp.l $10(a0),d0` / `bgt` with the boundary
  walked across every position branches correctly every time.

### The one that is still open: emu_start subdivision

Subdividing `emu_start` changes the emulated result, but only once interrupts
are being injected. Measured from `postintro.snap` with everything else held
identical -- same snapshot, same hooks, same process, deterministic on a
repeat: plain chunking, chunking plus the extra register reads, and deadline
stepping with no `service` all give byte-identical state at 400k instructions
for any cap. Add `service` and cap 5000 diverges from no cap. It is not the
extra `service` calls (servicing only when due diverges identically), not the
HLEs (they never fire in the window), not the exception stream (identical),
and not the instruction count (exact). Traced to the instruction, the first
divergence is a `bgt` at `0x40111070` -- the bounds check of the array setter
at `0x40111062` -- taking opposite branches from identical PC, A7, D0 and A0.
Instrumenting it with a global `UC_HOOK_MEM_WRITE` makes it disappear, which
is the signature of a translation-level effect rather than a data one.

This is why `cap` is documented as pacing-only and why the old chunk-size
table moved. It is very likely the true root of the C++ throw below.

### The C++ exception, for the record

`basic_string::_S_construct null not valid`, thrown at `0x401d3fba`, aborting
in libgcc's unwinder because `_Unwind_Find_FDE` finds no registered frame
info. **It is an artifact of preempting the heap allocator** -- every
injection preceding a failure landed in `0x40111044`-`0x4011137e` and the
faulting PC `0x40111458` is in the same allocator. A null `const char*` out of
a corrupted heap is exactly how it appears. It disappeared entirely once PIT0
was delivered.

Still worth knowing: `0x401d0e24` is a throw helper taking a `const char*` --
**hook it and read argument 1 as a C string to get any exception message
directly.** That is how this one was identified in one step.

---

## 6. Speed

The old "Unicorn m68k ceiling here 2.90M instr/s" claim in FINDINGS was
mis-attributed and has been corrected. A hook-free m68k loop measures
**250.8M instr/s**; the ceiling is our Python hook layer, not Unicorn.

cProfile over 10M instructions with both HLEs on:

| | share |
|---|---|
| `emu_start` -- Unicorn actually executing m68k | 34% |
| Unicorn's Python ctypes binding | ~54% |
| our own handler logic | ~12% |

1.02M of 10M instructions cross into Python; each crossing costs a ctypes
`create_string_buffer` per `mem_read` (1.94M) and an FFI call per `reg_write`
(1.85M). The wins are fewer and cheaper crossings, not a better peripheral
model. Untried: `mem_read` into a preallocated buffer; collapsing the 239
scoped ISA hooks into one guarded hook; Unicorn 2.1.4's `ctl_*` APIs
(`ctl_set_tcg_buffer_size`, `ctl_flush_tb`, `ctl_request_cache`,
`ctl_set_tlb_mode`). Real time is no longer ruled out.

---

## 7. Traps that have already cost time

1. **Only trust an A/B where both sides do the same work.** Has now bitten
   four times, including a fictitious **118x** speedup from stopping at a
   function's entry -- the resume landed on the same address, re-fired the
   hook, and counted iterations that did no work.
2. **A result that changes with the chunk size is an artifact, not a
   finding.** Sweep it before believing anything downstream of injection.
3. **Register values read inside a mid-function `UC_HOOK_CODE` lag.** Every
   existing hook in this codebase sits on a function entry -- a basic block
   boundary -- and reads correctly. A mid-function hook will report an operand
   that contradicts the branch the CPU then takes, which reads exactly like a
   CPU emulation bug and is not one. Read memory, hook the entry, or
   single-step with `count=1` to force a sync.
4. **Do not cache anything read from firmware structures** without proving it
   immutable. The Bitmap header cache is the standing example.
5. Only call `uc.emu_stop()` from a hook that has already advanced PC past the
   current instruction. The setPixel HLE writes `PC = return address`, so it
   qualifies; a plain code hook does not, and resuming re-enters it.
6. A hook-only stop condition needs a wall-clock timeout as a floor, or the
   caller hangs the moment the firmware stops meeting it. Compute any status
   you display *before* the blocking call.
7. A resumed run needs the *same hook set*, not just the same Machine.
7a. Two runs that executed a different number of instructions are not an A/B.
    In `pits` mode `spin` overshoots its budget by up to one timer period, so
    compare on what it *returned*, not on what you asked for. Testing the
    split-spin equivalence above the wrong way made four identical configs
    look like four different ones.
8. Snapshots are gitignored. `postintro.snap` for OS work, `boot400M.snap` for
   intro/draw work, `console450M.snap` for the console task.
9. `softfloat` and `bitmap` default **off** in `longrun.build`; `edma`
   defaults **on** -- it is a hardware model, not a shortcut.
10. If you write a snapshot yourself, `extra['tasks']` keys must be hex
    *strings*; `restore_into` does `int(k, 16)` on them.

---

## 8. Key addresses

| | |
|---|---|
| intro draw task | entry `0x400d3fb6`, tcb `0x43135210`, prio 7 |
| intro render fn / loop / exit | `0x400d3e94` / `0x400d402a` / `0x400d403c` |
| intro scene table | count `0x4313b290`, base `0x4313b294` (1 scene, 175 frames) |
| intro stop PIT3 / post done / park | `0x400d404a` / `0x400d4058` / `0x400d4060` |
| frame semaphore, satisfy-from / block-from | `0x43131200`, `0x400d4038` / `0x400d4068` |
| eDMA TX enqueue / free-space spin | `0x4000220c` / `0x4000221c` |
| eDMA ch35 TCD / SERQ / CERQ | `0xFC045460` / `0xFC044018` / `0xFC044019` |
| eDMA ch35 completion ISR / vector | `0x40001e7c` / 155 |
| TX ring state | base `0x4094cd7c`=`0x4FE1B000`, state `..74`, head `..88`, widx `..8c`, pending `..90`, drained `..94` |
| eDMA ch34 (RX) DADDR / vector | `0xFC045450` / 154 |
| `queue_receive` / `queue_send` | `0x40001928` / `0x400018e4` |
| pend-and-recheck sites (never unblock) | `0x40001946`, `0x400d4068`, `0x401260c2` |
| **RTOS context switcher** | `0x40000410` -- re-arms PIT0 and unmasks its INTC source every switch |
| **PIT2 ISR -> timer-wheel sem** | `0x40002a18` -> posts `0x47d9ade0` |
| **timer-wheel task / callback list** | `0x40002a46` / `0x4094cdb8` (7 nodes; mask 1 = every tick) |
| **display tick callback** | `0x4012651e` (mask 1) |
| prio-6 display task / its pend | `0x4012606a` / `0x401260c2`, sem `0x44e2d148`, flag `0x44e2d5cc` |
| **PIT3 start / stop (display)** | `0x40126004` / `0x4012604a` -- start writes vec 208, PMR `0x4323`, EN\|PIE |
| **PIT3 ISR (display)** | `0x40125f3c` -- acks PIT3 and posts `0x44e2d148` |
| display geometry setter | `0x40125f6a` -- writes `0x44e2d5d0` (position) and `0x44e2d5cc` (count) |
| vector 208 table slot | `0x40000340` -- repointed `0x400d2d70` -> `0x40125f3c` at runtime |
| bounds-checked array setter | `0x40111062` -- where a subdivided run first diverges |
| prio-3 task / FIFO poll / FIFO port | `0x400f1fce` / `0x400cf4ec` / `0x8C000002`, `0x8C00000A` |
| PIT0..3 PCSR | `0xFC080000` / `84000` / `88000` / `8C000` |
| PIT0/1/2/3 vectors | 205 `0x40000410` / 206 `0x40001252` / 207 `0x40002a18` / 208 `0x400d2d70` |
| **INTC ICR / IMR** | `<intc>+0x40+source` / `+0x08` IMRH, `+0x0C` IMRL; INTC2 = `0xFC050000`, vector 205 = source 13 |
| **PIT levels** | PIT0 1, PIT2 3, PIT3 3 |
| INTC1 SIMR / CIMR | `0xFC04C01C` / `0xFC04C01D` |
| **heap allocator** | malloc `0x4011122c`; body `0x40111044`-`0x4011137e` |
| **libgcc unwinder** | `_Unwind_Find_FDE` `0x4017a0e4`, LEB128/CFA parser `0x401772cc`, object lists `0x44f1de80`/`0x44f1de84`, `abort()` `0x4012d2fa` |
| **C++ throw helper (takes a message)** | `0x401d0e24` -- hook it, read arg 1 as a C string |
| `__cxa_throw` / `_S_construct` | `0x401d5680` / `0x401d3f16` |
| string-format helper (UI log) | `0x40000e82` |
| fault handler / HALT | `0x4010fcae` / `0x4010fd50` -- prints a full backtrace via `0x40000e82` |
| console print | `0x400054b4` |
| sem_pend A / B, sem_post | `0x4000141a` / `0x400013a6`, `0x4000148c` |
| scheduler lock / unlock | `0x40001608` / `0x4000172a` |
| current TCB / ready cursor | `0x47d9adb4` / `0x4094c914` |
| panel Bitmap instance | `0x4313b298` |

---

## 9. Tools

    uv sync
    uv run python -m emu.gui                       # live panel + Replay 15fps
    uv run python -m emu.frame <snap> <instrs>     # one frame, ASCII + PNG
    uv run python -m emu.frame export <snap> <n>   # all frames, packed 1bpp
    uv run python -m emu.tasks <snap>              # parked PC per task
    uv run python -m emu.probe <snap> <instrs>     # blocking sites, hot PCs
    uv run python -m dt2.coldfire sections/section_3_MAIN_OS.bin 0x40000400 <start> <end>

    tools/ghidra.sh import                         # one-time, ~3 min
    tools/ghidra.sh run Callers.java out.txt 0x40178424 0x401797ae
    tools/ghidra.sh run Decompile.java out.txt 0x4017a0e4

**Use Ghidra for anything structural.** `dt2/coldfire.py` is a linear sweep
with no cross-references, and the byte-search substitute for xrefs is actively
misleading: it misses every PC-relative call. `jsr $401772cc(pc)` encodes as
`4eba ee6c` and contains the target nowhere, so the byte search reported that
function as never called while it sat on the boot path.

Scripts in `tools/ghidra/` must be **Java** -- this Ghidra build has no
PyGhidra. But `pyghidra` 3.1.0 *is* installed in the venv and is better for
iterating:

    GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.3/libexec uv run python ...

Open the existing project with `pyghidra.open_project()` +
`pyghidra.program_context()` -- **not** `open_program()`, which tries to
re-import and fails with "No load spec found". Import `ghidra.*` only *after*
`pyghidra.start()`.

**Backtracing by hand:** scan the stack for words preceded by a real
`jsr`/`bsr` opcode (`4EB9` at -6, `4EBA`/`4EB8`/`6100` at -4, `4E8x` at -2).
Naive stack scanning gives nonsense.

**Get the MCF5441x reference manual.** The part is identified (FINDINGS: NXP
MCF5441x, ColdFire V4m). Several things cost real time this session that are
one table lookup in it: the PIT PCSR bit semantics (RLD reload, PIF
write-1-to-clear, load-on-enable -- worked out here from the bit pattern of
`0x53f`), the INTC source-to-module assignment that would name all nineteen
vectors in section 3a, and the FlexBus chip-select registers (CSAR/CSMR/CSCR)
that give the `0x8C000000` device its port width and timing directly. Reading
the manual is faster than inferring it, and inference here has been wrong
before.

**`tools/ghidra.sh` was broken the whole time, and is fixed.** The project
path defaulted to `$HOME/.cache/dt2-ghidra`, and Ghidra refuses any path
element beginning with a dot -- "Path element starting with '.' is not
permitted". `import` had therefore never once succeeded, and `run` failed the
same way but printed its error where it was easy to read as "the script found
nothing", which is exactly how it was read. The default is now
`$HOME/ghidra-projects/dt2`. Re-import once (`tools/ghidra.sh import`, ~3
min) and `run Callers.java` works; every cross-reference in section 1 came
out of it. Treat any past claim in this repo that rests on "Ghidra found no
callers" as unverified.
