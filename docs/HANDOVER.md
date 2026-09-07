# Handover: the OS is up and idle -- make it draw

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

## 2. The actual problem now: the firmware throws a C++ exception

PIT2 is landed (`emu/pit.py`) and the RTOS heartbeat runs -- over 20M
instructions from `postintro.snap`, PIT2 fires 250 times, the software-timer
wheel and the display callback each run 5586 times, no fault, no HALT.

With the heartbeat running the init task gets further and then **throws a C++
exception that nothing can unwind**, so it calls `abort()` and spins there,
starving the system (51M iterations of the spin).

### The exception, exactly

Hooking the throw helper `0x401d0e24` and reading its argument as a C string:

    basic_string::_S_construct null not valid

That is libstdc++'s error for constructing a `std::string` from a NULL
`const char*`. The whole `0x40176000`-`0x4017a000` region is **libgcc's DWARF
unwinder**, which is why nothing there looked like application code:

| address | what it is |
|---|---|
| `0x401d0e24` | throw helper: `__cxa_allocate_exception(8)`, build `std::string`, `__cxa_throw` |
| `0x401d5680` | `__cxa_throw` |
| `0x401d3f16` | `basic_string::_S_construct` -- throws at `0x401d3fba` when `first == NULL && last != NULL` |
| `0x401d43c4` | `std::string::string(const char*)` |
| `0x4017a0e4` | `_Unwind_Find_FDE` |
| `0x401772cc` | CFA program parser (the "varint" decoding is LEB128) |
| `0x4012d2fa` | `abort()` -- `bra.b *`, jsr'd from 24 sites |
| `0x44f1de80` / `0x44f1de84` | the unwinder's `seen_objects` / `unseen_objects` |

`0x474e5543` = `'GNUC'` appearing in the arguments, and `GNUCC++` in the
fault-handler backtrace, is what identified it.

### Why it aborts rather than unwinding

`_Unwind_Find_FDE` finds **both** object lists null, returns 0, the CFA parser
returns an error and the caller at `0x4017847e` calls `abort()`. The three
functions that would populate those lists (`0x40179f90`, `0x40179ea8`,
`0x40179e64` -- i.e. `__register_frame_info` and friends) are referenced
**nowhere in the image at all**, confirmed by both Ghidra xrefs and a raw byte
search of ROM and live RAM. So no DWARF frame info is ever registered.

Two readings, and they need different fixes -- **settle which one first**:

1. **The throw is spurious**, caused by something we fail to provide, and on
   hardware it never happens. Then find the null and the abort is moot.
2. **The throw is normal** and on hardware it unwinds to a `catch`. Then the
   registration must happen somewhere we have not found, and the fix is to
   make the unwinder work.

Reading 1 is much more likely -- a boot that routinely throws and unwinds
would be odd -- but it is not proven.

### Backtrace at the throw

Built by scanning the stack for words preceded by a real `jsr`/`bsr` opcode
(the technique is worth reusing; naive stack scanning gives nonsense):

    0x401d3fba  throw            in _S_construct
    0x401d43e8                   in std::string::string(const char*)
    0x40055a72                   in fn 0x40055a56
    0x4003f5ca                   in fn 0x4003f528
    0x400445a8 / 0x400445cc      in fn 0x40044???
    0x401113ec, 0x401868cc, 0x40030d16, 0x40186968, 0x40032f76

`0x40055a56` is a constructor that builds a `std::string("Observable")` and
references `"Active Track"`; the literals near it are `Observable`,
`FxSetup::updateMirror`, `14DataChan...`. So this is FX / data-channel setup.

### What is NOT yet established, and the trap that got in the way

**The identity of the null pointer.** Three attempts each gave a different
answer, and two of them were wrong:

* Hooking `_S_construct`'s entry and reading args off `A7`: **no null in any
  call**, yet the throw happens.
* Reading `A2`/`A6` at the throw instruction: reports `first = 0x40224e95`
  ("Observable"), which cannot be right -- that path is only reachable when
  `first == 0`.
* A windowed `UC_HOOK_CODE` trace: shows `tst.l a2` with `a2 = 0x40224e95`
  followed by `beq.w` **being taken**.

That last one looks like a Unicorn bug and **is not one**. Checked and
disproved: `TST.L An` sets Z correctly for An and Dn, and replaying the exact
four-instruction sequence (`cmp.l a2,d0; beq.b; tst.l a2; beq.w`) with the
exact runtime register values falls through correctly. The live code at
`0x401d3f16..0x401d3fc6` is also byte-identical to the ROM image.

So the register values reported by mid-function `UC_HOOK_CODE` hooks are
**not trustworthy** here -- they lag. The codebase's existing hooks all sit on
function entry points, which are basic-block boundaries, and those are fine.

**Next step, with a method that cannot lag:** single-step (`emu_start` with
`count=1`) through the last few hundred instructions before the throw, which
forces a register sync at every step, and read `[a6+8]` from memory. Find the
first frame where the pointer is null and walk back to whoever produced it.

### Two smaller things still open

**The `0x8C000002` FIFO status bit.** The prio-3 task (`0x400f1fce`) polls bit
0 at `0x400cf4ec` before writing an 8-word burst, and nothing sets it.
`0x8C000000` is a FlexBus chip-select region, still **unidentified**. Forcing
the bit does unblock it and the task then does real work (610 genuinely
satisfied pends, not spins). Deliberately **not committed**: a guess about an
unnamed device, and the abort is reached identically without it.

**The display task has nothing to wake it.** `0x4012606a` (prio 6) blocks on
`0x44e2d148`. Note `0x40126004` in the same module re-enables PIT3 (PMR
0x4323, prescaler 1024), so the OS drives its own frame timer once it gets
that far -- and `emu/pit.py` is PCSR-gated, so it will start delivering vector
208 by itself when the firmware enables it.

### A debugging channel worth using

The fault handler prints a **stack backtrace** through `0x40000e82`, not just
the `EXCEPTION DS%.04s` / `V%02x M%x P%08x` line. Hooking `0x40000e82` and
decoding arguments as C strings is the cheapest window into any fault.

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

1. Batch register access -- `reg_read_batch`/`reg_write_batch` exist in the
   Unicorn Python binding and would collapse several FFI calls per hook into
   one.
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
3. **Register values read inside a mid-function `UC_HOOK_CODE` lag.** Every
   existing hook in this codebase sits on a function entry, which is a basic
   block boundary, and those read correctly. A hook in the middle of a
   function does not, and it will happily report an operand that contradicts
   the branch the CPU then takes -- which reads exactly like a CPU emulation
   bug and is not one. Read memory rather than registers, hook the entry, or
   single-step with `count=1` to force a sync.
4. Only call `uc.emu_stop()` from a hook that has already advanced PC past the
   current instruction. The setPixel HLE writes `PC = return address`, so it
   qualifies; a plain code hook does not.
5. A hook-only stop condition needs a wall-clock timeout as a floor, or the
   caller hangs as soon as the firmware stops meeting the condition. Compute
   any status you display *before* the blocking call, not after -- otherwise
   the stale value is on screen for the whole block and the fresh one for
   microseconds.
6. A resumed run needs the *same hook set*, not just the same Machine.
7. Snapshots are gitignored. Use `postintro.snap` for OS work, `boot400M.snap`
   for intro/draw work, `console450M.snap` for the console task.
8. `softfloat` and `bitmap` default **off** in `longrun.build` (they change
   instruction counts); `edma` defaults **on** -- it is a hardware model, not
   a shortcut, and there is no faithful configuration with it off.
9. If you write a snapshot yourself, `extra['tasks']` keys must be hex
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
