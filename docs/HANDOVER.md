# Handover: make PIT injection sound, then the OS can draw

Previous goal (get past the intro into the main OS) is **half done, and be
precise about which half**. Internally the intro runs all 175 frames, exits
properly, and six previously-missing tasks spawn. **Visually nothing has
changed yet:** `uv run python -m emu.gui` still ends on the last intro frame
and the panel then sits still, because the task that drives the display is
blocked. The status line now says so honestly -- "running, no frame for Ns",
fps 0.00, tasks 6 -- instead of freezing while claiming 15 fps.

The new problem is different in kind from the old one: every task now blocks
*correctly*, and the system sits idle waiting for interrupts nothing
delivers. Getting a pixel onto the panel again means supplying one of the
three missing things in section 2, not undoing any of this.

Read `docs/NEXT.md` for the project overview and `docs/FINDINGS.md` for
evidence. This file is only about what is still open.

---

## 0. Working tree is clean

Three commits landed this session; nothing is left uncommitted. All checks
pass -- run them before doing anything else:

    uv run python -m emu.hle          # header-mutation ok=True
    uv run python -m emu.softfloat    # 0 mismatches
    uv run python emu/oracle.py
    uv run python emu/screen.py selftest
    uv run python -m emu.frame snapshots/boot400M.snap 20000000 out/frame.png
        # expect: setPixel 616823, 75 frames, 344 lit   <- the canary

The canary moved from 617694 this session (eDMA now drains the TX ring, so
the console-enqueue routine takes its short path instead of spinning). The
rendered output is unchanged: still 75 frames, still 344 lit pixels.

`snapshots/postintro.snap` (54.7M instructions past `boot400M.snap`) is new
and is the one to use -- the intro is over, the draw task is parked, all six
OS tasks exist. Iterating from it takes seconds.

---

## 1. What was actually wrong, and is now fixed

The previous handover's model was: `unblock=True` is needed for the intro and
poisons everything after it. That was the wrong cause. The intro was not
failing to *exit*, it was failing to *finish* -- it stopped at exactly frame
88 of 175 and never approached its exit path.

**The stall was eDMA channel 35, UART8 transmit.** `0x4000220c` spins waiting
for room in a 4096-byte TX ring, computed from `TCD35.CITER/BITER`. Nothing
advanced the channel, so the ring never drained and the prio-7 draw task span
there forever. `emu/edma.py` models it; vector 155 is the completion ISR.
Full detail in FINDINGS, "Boot reaches the main OS".

**`unblock` was narrowed, not removed.** It is caller-based now: never satisfy
a pend whose return address is `0x40001946` (inside `queue_receive`, which
re-checks `queue->count` afterwards, so satisfying it spins instead of
sleeping -- 8.9M iterations, ~92% of post-intro cycles). Post-intro pends
satisfied went 8.9M -> 1.

The intro/park handoff is gone: the intro loop pends the frame semaphore from
`0x400d4038` (satisfy) and the park loop pends the *same* semaphore from
`0x400d4068` (do not). Different callers, one rule, no state, survives a
snapshot taken after the intro.

---

## 2. The actual problem: our PIT injection is unsound

**Retraction.** An earlier version of this file said the blocker was a C++
exception (`basic_string::_S_construct null not valid`) thrown by the
firmware. That was wrong. The throw is **an artifact of where we inject the
PIT interrupt**, not firmware behaviour. It appears and disappears with the
chunk size, which no real firmware bug would do.

Same snapshot, same 60M instructions, only `spin`'s chunk size varying:

| chunk | outcome |
|---|---|
| 30,000 | abort spin, 56M iterations |
| 40,000 | 1280 faults |
| **50,000** | **clean: 6 tasks, 11,282 display callbacks, no fault/throw/abort** |
| 60,000 | the C++ throw, then abort |
| 80,000 | 719 faults |
| 100,000 | 535 faults |

chunk=50,000 working is luck. Nothing downstream of PIT injection can be
trusted until this is fixed, and no conclusion drawn from a single chunk size
means anything.

### What it is not

All checked and ruled out, so do not spend the time again:

* **Not user/supervisor stack confusion.** The CPU is in supervisor mode at
  every injection point (SR bit 0x2000 set, 400/400 samples) and at IPL 0 for
  384 of 400, so there is no USP/SSP switch being missed.
* **Not the missing IPL mask.** Raising SR's IPL to the source's level while
  the handler runs changes nothing (identical fire counts and outcomes).
* **Not interrupt priority gating.** The INTC2 ICRs give real levels -- PIT0
  level 1, PIT2 level 3, PIT3 level 3, at `0xFC050040 + source`, vector 205 =
  source 13. Gating delivery on `current IPL < level` changes nothing.
* **Not the synthetic vector-32 idle tick.** Disabling it entirely (patch
  `db.find_idle_spins` to return `[]`) leaves every outcome unchanged.
* **Not `unblock` breaking a mutex.** Over 40M instructions only six pends are
  even candidates for force-satisfying, and the allocator makes **no pend
  calls at all**.
* **Not a Unicorn CPU bug.** `TST.L An` sets Z correctly; replaying the exact
  instruction sequence with the exact runtime register values behaves
  correctly; live code is byte-identical to the ROM image.

### What it was: PIT0 was missing

**PIT0 is the RTOS time slice.** The context switcher at `0x40000410` re-arms
it on every switch (`move.w #$53f,$fc080000`) and unmasks its INTC source
(`and.l #$ffffdfff,$fc050014` clears IMRL bit 13 = source 13 = vector 205),
and vector 205's handler *is* the switcher. Delivering PIT2 without PIT0 gave
the RTOS timer-wheel ticks while denying it preemption.

That is now fixed (`emu/pit.py` defaults to channels `(0, 2)`), and it removed
every abort and every spurious exception:

| chunk | PIT2 only | PIT0 + PIT2 |
|---|---|---|
| 20,000 | throw + abort | 523 faults |
| 30,000 | abort, 56M iterations | clean |
| 40,000 | 1280 faults | clean, 29,591 display callbacks |
| 50,000 | clean, 11,282 callbacks | clean, 47,484 callbacks |
| 60,000 | throw + abort | clean |
| 80,000 | 719 faults | clean |
| 100,000 | 535 faults | 558 faults |

The mechanism: every injection preceding a failure landed in
`0x40111044`-`0x4011137e` and the faulting PC `0x40111458` is in the same
range -- the **heap allocator** (`0x4011122c` is malloc). Preempting it with a
reschedule the RTOS was not expecting corrupts the heap, and a null
`const char*` out of a corrupted heap is exactly how
`basic_string::_S_construct null not valid` appears.

Measured separately: the INTC gating and the exception-frame format fix change
no outcome on their own. PIT0 is what mattered. Both were kept anyway -- they
are what the hardware does, and the format field was a latent trap (the
ColdFire PRM: an RTE whose frame format is not 4-7 raises a format error; we
were writing 0, and only got away with it because `rte` is implemented in
`on_intr` and ignores the field).

### Still not sound -- fix this next

chunk=20,000 and chunk=100,000 still fault, and the display-callback count
swings between 2,511 and 47,484 across chunk sizes. **An outcome that depends
on the chunk size is still an artifact.**

The cause is structural: `Pits.service` is only called at chunk boundaries, so
an interrupt is delivered at whatever instruction the boundary happens to land
on rather than where the timer is actually due. The fix is to run to each
deadline exactly -- compute `next_deadline - done` and pass that as the
`count` to `emu_start`. A first attempt at this regressed badly, because
`done += step` over-counts when `emu_start` returns early (after a fault it
returns immediately, and the loop then races to the instruction budget in
seconds). Accumulate what actually executed, not what was requested.

PIT0 also is not really periodic -- the switcher re-arms it on every context
switch, so it is a one-shot restarted per slice. `Pits` models it as periodic.
Reading PCNTR is not an option (FINDINGS: MAIN OS never reads it), but
re-arming our own deadline when the firmware writes PCSR would be closer.

### The best run so far, and what blocks it

At chunk=50,000, 80M instructions from `postintro.snap`: 1007 PIT2 interrupts,
11,282 display callbacks, 6 tasks, no fault, no throw, no abort. The hot PC is
then `0x400cf4ec`/`0x400cf4f4` -- **the `0x8C000002` FIFO poll** -- 10.3M
polls, 76% of the time, in the prio-3 task.

That poll is therefore the next functional blocker once injection is sound.
`0x8C000000` is a FlexBus chip-select region and the device is still
**unidentified**. Forcing bit 0 ("FIFO always ready") is **wrong**: it
unblocks the task but the run then faults 245 times at `0x40111458`. Reads and
writes share the address (read = status, write = data), so blanket-forcing
reads corrupts anything that reads data from it. Identify the device first.

### Useful things found on the way

* **`0x4012651e`** is the display tick callback, mask 1, in the timer wheel's
  list at `0x4094cdb8` -- it runs at ~60 Hz once PIT2 ticks.
* The `0x40176000`-`0x4017a000` region is **libgcc's DWARF unwinder**:
  `0x4017a0e4` = `_Unwind_Find_FDE`, `0x401772cc` = the CFA/LEB128 parser,
  `0x44f1de80`/`0x44f1de84` = its object lists (both null; no frame info is
  ever registered), `0x4012d2fa` = `abort()`. `0x401d0e24` is a throw helper
  that takes a `const char*` -- **hook it and read the argument to get any
  exception message directly**. `0x401d5680` = `__cxa_throw`.
* The fault handler prints a **stack backtrace** through `0x40000e82`.
* To backtrace by hand, scan the stack for words preceded by a real
  `jsr`/`bsr` opcode (`4EB9` at -6, `4EBA`/`4EB8`/`6100` at -4, `4E8x` at -2).
  Naive stack scanning gives nonsense.

## 3. Speed: the previous ceiling claim was wrong

`FINDINGS.md` used to say "Unicorn m68k ceiling here 2.90M instr/s" and
concluded live 15 fps was unreachable. **That number was our Python hook
layer, not Unicorn.** A hook-free m68k loop measures **250.8M instr/s** on
this machine.

Landed this session: passing `count` to `emu_start` makes Unicorn install an
internal per-instruction hook to decrement the budget, costing **1.84x**
(8.07s -> 4.39s over the same 40 rendered frames). The cost is `count`
itself, not the call frequency -- 20k, 500k and 1e9 all measure within 3%.
`emu/longrun.py:run_until` is the uncounted form, and `emu/gui.py` now stops
per completed frame: **~8.7 fps, ~58% of the real 15.00 Hz, against ~30%**.

`run_until` also takes `timeout_ms` (default 250), because a hook-only stop
condition hangs the caller the moment the firmware stops meeting it -- which
is exactly what the end of the intro does. **A timeout is free, unlike
`count`.** Same 40 frames, identical 327,681 setPixel calls each way:

| | |
|---|---|
| `count=250_000` | 8.03s |
| uncounted | 4.45s |
| uncounted + 0.5s timeout | 4.43s |

`count` installs a per-instruction hook; a timeout only arms a timer thread.
So bound wall-clock time freely, and never bound instruction counts unless
something genuinely has to happen per fixed number of instructions.

Where the rest goes, cProfile over 10M instructions with both HLEs on:

| | share |
|---|---|
| `emu_start` -- Unicorn actually executing m68k | 34% |
| Unicorn's Python ctypes binding | ~54% |
| our own handler logic | ~12% |

1.02M of 10M instructions cross into Python; each crossing costs a ctypes
`create_string_buffer` per `mem_read` (1.94M) and an FFI call per `reg_write`
(1.85M). **The next wins are fewer and cheaper crossings, not a better
peripheral model.** Untried and worth trying, roughly in order:

1. ~~Batch register access~~ -- measured and rejected: `reg_read_batch` is
   **slower** than individual `reg_read` calls in unicorn 2.1.4 (0.74x over
   200k iterations of 4 registers).
2. Read memory into a preallocated buffer instead of letting `mem_read`
   allocate a fresh ctypes buffer per call.
3. `build()` installs 252 code hooks (239 scoped ISA patches + 13 idle
   spins). Unicorn range-checks hooks per basic block; measure whether
   collapsing the 239 into one guarded hook is cheaper or dearer.
4. Only then consider a native hook layer or a different core.

Real time is no longer ruled out. It is a 1.6x away, not a 3x away.

---

## 4. Traps that have already cost time

1. **Only trust an A/B where both sides do the same work.** This has now bitten
   four times: the `install_mmio` comparison, the "93% in handler bodies"
   reading, the "2.90M ceiling", and a fictitious **118x** speedup this
   session from stopping at a function's *entry* -- the resume landed on the
   same address, re-fired the hook, and counted iterations that did no work.
2. **Do not cache anything read from firmware structures** without proving it
   immutable. The Bitmap header cache is the standing example.
3. **A result that changes with the chunk size is an emulation artifact, not a
   finding.** A whole session was spent characterising a C++ exception as the
   post-intro blocker; it only occurs at some chunk sizes. Before believing
   anything downstream of interrupt injection, sweep the chunk size and check
   the result is stable. This is the same lesson as trap 1, one level up.
4. **Register values read inside a mid-function `UC_HOOK_CODE` lag.** Every
   existing hook in this codebase sits on a function entry, which is a basic
   block boundary, and those read correctly. A hook in the middle of a
   function does not, and it will happily report an operand that contradicts
   the branch the CPU then takes -- which reads exactly like a CPU emulation
   bug and is not one. Read memory rather than registers, hook the entry, or
   single-step with `count=1` to force a sync.
5. Only call `uc.emu_stop()` from a hook that has already advanced PC past the
   current instruction. The setPixel HLE writes `PC = return address`, so it
   qualifies; a plain code hook does not.
6. A hook-only stop condition needs a wall-clock timeout as a floor, or the
   caller hangs as soon as the firmware stops meeting the condition. Compute
   any status you display *before* the blocking call, not after -- otherwise
   the stale value is on screen for the whole block and the fresh one for
   microseconds.
7. A resumed run needs the *same hook set*, not just the same Machine.
8. Snapshots are gitignored. Use `postintro.snap` for OS work, `boot400M.snap`
   for intro/draw work, `console450M.snap` for the console task.
9. `softfloat` and `bitmap` default **off** in `longrun.build` (they change
   instruction counts); `edma` defaults **on** -- it is a hardware model, not
   a shortcut, and there is no faithful configuration with it off.
10. If you write a snapshot yourself, `extra['tasks']` keys must be hex
   *strings*; `restore_into` does `int(k, 16)` on them.

---

## 5. Key addresses

| | |
|---|---|
| intro draw task | entry `0x400d3fb6`, tcb `0x43135210`, prio 7 |
| intro render fn / loop / exit | `0x400d3e94` / `0x400d402a` / `0x400d403c` |
| intro scene table | count `0x4313b290`, base `0x4313b294` (1 scene, 175 frames) |
| intro exit: stop PIT3 / post done / park | `0x400d404a` / `0x400d4058` / `0x400d4060` |
| frame semaphore, satisfy-from / block-from | `0x43131200`, `0x400d4038` / `0x400d4068` |
| **eDMA TX enqueue / free-space spin** | `0x4000220c` / `0x4000221c` |
| **eDMA ch35 TCD / SERQ / CERQ** | `0xFC045460` / `0xFC044018` / `0xFC044019` |
| **eDMA ch35 completion ISR / vector** | `0x40001e7c` / 155 |
| **TX ring state** | base `0x4094cd7c`=`0x4FE1B000`, state `..74`, head `..88`, widx `..8c`, pending `..90`, drained `..94` |
| eDMA ch34 (RX) DADDR / vector | `0xFC045450` / 154 |
| `queue_receive` / its pend (never unblock) | `0x40001928` / `0x40001946` |
| `queue_send` | `0x400018e4` |
| prio-6 display task / its recheck pend | `0x4012606a` / `0x401260c2`, sem `0x44e2d148`, flag `0x44e2d5cc` |
| prio-3 task / FIFO poll / FIFO port | `0x400f1fce` / `0x400cf4ec` / `0x8C000002`, `0x8C00000A` |
| PIT0..3 PCSR | `0xFC080000` / `84000` / `88000` / `8C000` |
| PIT0/1/2/3 vectors | 205 `0x40000410` / 206 `0x40001252` / 207 `0x40002a18` / 208 `0x400d2d70` |
| INTC1 SIMR / CIMR | `0xFC04C01C` / `0xFC04C01D` |
| string-format helper (UI log) | `0x40000e82` |
| fault handler / HALT | `0x4010fcae` / `0x4010fd50` |
| console print | `0x400054b4` |
| sem_pend A / B, sem_post | `0x4000141a` / `0x400013a6`, `0x4000148c` |
| current TCB / ready cursor | `0x47d9adb4` / `0x4094c914` |
| panel Bitmap instance | `0x4313b298` |

## 6. Tools

**Use Ghidra for anything structural.** `dt2/coldfire.py` is a linear sweep
with no cross-references, no function boundaries and no decompiler, and the
byte-search substitute for xrefs is actively misleading: it misses every
PC-relative call. That is not hypothetical -- `jsr $401772cc(pc)` at
`0x4017845e` encodes as `4eba ee6c` and contains the target nowhere, so the
byte search reported `0x401772cc` as never called while it sat on the boot
path. The whole of section 2 above came out of Ghidra in minutes and would
have been days of linear sweeping. `tools/ghidra.sh` wraps the headless
analyzer; scripts live in `tools/ghidra/` and must be **Java**, since this
Ghidra build has no PyGhidra.

Measured and rejected: `reg_read_batch` is **slower** than individual
`reg_read` calls in unicorn 2.1.4's Python binding (0.74x over 200k
iterations of 4 registers), so that is not the FFI win it looks like.
Unicorn 2.1.4 does expose `ctl_*` (`ctl_set_tcg_buffer_size`,
`ctl_flush_tb`, `ctl_request_cache`, `ctl_set_tlb_mode`) which are untried.

    uv sync
    uv run python -m emu.gui                       # live panel + Replay 15fps
    uv run python -m emu.frame <snap> <instrs>     # one frame, ASCII + PNG
    uv run python -m emu.frame export <snap> <n>   # all frames, packed 1bpp
    uv run python -m emu.tasks <snap>              # parked PC per task
    uv run python -m emu.probe <snap> <instrs>     # blocking sites, hot PCs
    uv run python -m dt2.coldfire sections/section_3_MAIN_OS.bin 0x40000400 <start> <end>

    tools/ghidra.sh import                       # one-time, ~3 min
    tools/ghidra.sh run Callers.java out.txt     # real xrefs, incl. PC-relative
    tools/ghidra.sh run Decompile.java out.txt 0x4017a0e4
    uv run python -m emu.serial console '#HELLO'
    uv run python -m emu.checkpoint extend <snap> <points> <prefix>
