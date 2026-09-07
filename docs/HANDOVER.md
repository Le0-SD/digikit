# Handover: the OS is up and idle -- make it draw

Previous goal (get past the intro into the main OS) is **done**. The intro
runs all 175 frames, exits properly, and six previously-missing tasks spawn.
The new problem is different in kind: every task now blocks *correctly*, and
the system sits idle waiting for interrupts nothing delivers.

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

## 2. The actual problem now

From `snapshots/postintro.snap`, nine tasks reach clean blocking waits and
nothing runs. The system is behaving correctly for a machine with no
hardware attached. Three things are still missing:

### a. A FIFO status bit at `0x8C000002`

The prio-3 task (`0x400f1fce`) polls bit 0 of `0x8C000002` at `0x400cf4ec`
before writing an 8-word burst, and nothing sets it -- 70% of post-intro
time. `0x8C000000` is a FlexBus chip-select region and is **undocumented in
this project**; identifying the device is genuinely open. Forcing bit 0 high
("FIFO always ready", the same abstraction already used for UART TXRDY) does
unblock it and the task then does real work -- 610 genuinely-satisfied pends
on `0x44e4d69c`, not spins. That experiment is **not committed**: it is a
guess about a device we have not identified, and it should be pinned down
before it lands. It is 4 bytes in, 8 tagged words out (each byte becomes two
words, one with bit 7 set), with `0x80` written to `0x8C00000A` first --
looks like a bit-banged serial link, possibly the LED/encoder chain.

### b. The draw task has nothing to wake it

The prio-6 task `0x4012606a` is the display driver -- it calls `0x401262b4`
and `0x40126332`, the same frame-source functions the intro renderer used.
It blocks on `0x44e2d148` and nothing posts it. On hardware a timer does.

### c. PIT interrupts -- **tried, and it crashes**

Do not repeat this blind. A PCSR-gated model (deliver vec 205/207 only while
PCSR bit 0 and bit 3 are set, paced by an instruction-count proxy) was
implemented and run. Periods come out right: PIT0 93,600 instructions, PIT2
78,002, at 4.68M instructions per emulated second.

Result: **one PIT2 interrupt fired and the firmware immediately took a
vector-4 fault.** The fault handler printed

    EXCEPTION DS0071   V04 M0 P033C2004

and executed `HALT`, then span at `0x4010fd52` for the rest of the run. 78%
of injections were skipped because the CPU sat at IPL 7 (fired 1, missed 427
on PIT0 and 511 on PIT2).

So injecting an asynchronous interrupt at a chunk boundary is not safe as
written. Worth knowing before trying again:

* vector 205's handler *is* `0x40000410`, the context switcher -- the same
  handler as vector 32 / `trap #0`. Injecting it forces a reschedule inside
  arbitrary code.
* `raise_vector` pushes format 0 in the frame word. That is fine for the
  emulator's own `rte`, which only reads SR and PC back, but a handler that
  inspects the format field would not agree.
* PIT2's ISR is `0x40002a18`; PIT1's is `0x40001252`. Neither has been read.
  **Start by disassembling `0x40002a18`** -- the crash is one interrupt deep,
  so it is cheap to find.
* The prototype is not committed. It lives in this session's scratch only;
  re-deriving it from the numbers above is a ten-minute job.

---

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
per completed frame: **9.34 fps, 62% of the real 15.00 Hz, against ~30%**.

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
3. Only call `uc.emu_stop()` from a hook that has already advanced PC past the
   current instruction. The setPixel HLE writes `PC = return address`, so it
   qualifies; a plain code hook does not.
4. A resumed run needs the *same hook set*, not just the same Machine.
5. Snapshots are gitignored. Use `postintro.snap` for OS work, `boot400M.snap`
   for intro/draw work, `console450M.snap` for the console task.
6. `softfloat` and `bitmap` default **off** in `longrun.build` (they change
   instruction counts); `edma` defaults **on** -- it is a hardware model, not
   a shortcut, and there is no faithful configuration with it off.
7. If you write a snapshot yourself, `extra['tasks']` keys must be hex
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

    uv sync
    uv run python -m emu.gui                       # live panel + Replay 15fps
    uv run python -m emu.frame <snap> <instrs>     # one frame, ASCII + PNG
    uv run python -m emu.frame export <snap> <n>   # all frames, packed 1bpp
    uv run python -m emu.tasks <snap>              # parked PC per task
    uv run python -m emu.probe <snap> <instrs>     # blocking sites, hot PCs
    uv run python -m dt2.coldfire sections/section_3_MAIN_OS.bin 0x40000400 <start> <end>
    uv run python -m emu.serial console '#HELLO'
    uv run python -m emu.checkpoint extend <snap> <points> <prefix>
