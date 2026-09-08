# Digitone II 1.10E — handover

Status: **the intro renders, animates and hands over.** 109 distinct frames,
`intro_done` fires, the timers release and the RTOS starts scheduling. It then
goes idle: the prio-6 main application task never wakes, so nothing arms DTIM3
or starts the display module, and the panel keeps the intro's last frame.

Digitakt II 1.15C is **unregressed** — see Regression below.

Everything here is measured. Where a previous session's claim turned out to be
wrong, section 6 says so rather than deleting it.

---

## 1. What was actually wrong

Three separate bugs, all the same shape: an address hardcoded to Digitakt.

### 1.1 The soft-float HLE never fired (the big one)

`emu/softfloat.py` named all seven libgcc float routines by literal Digitakt
address. On Digitone the block sits at `0x401685fc`–`0x40169f5c`, not
`0x40174134`–`0x40175a94`, so **the HLE installed no hooks that could ever
fire** and the guest ground through the real arithmetic — which is 93% of the
intro's instructions by the module's own measurement. The intro could not
finish a single frame in 20M instructions; the profile was 100% shift-add
multiply loops inside `__mulsf3` at `0x401696cc`.

This was invisible because `install()` returned `len(ROUTINES)` whether or not
the addresses meant anything. It now returns the number actually installed,
and takes the resolved entry points from the profile.

Note the near miss: those seven hooks *write d0 and pop a return address*.
Pointed at unrelated code they would silently corrupt the guest. Measured over
20M instructions the Digitakt addresses are never executed on Digitone, so no
corruption happened — but that was luck, and an unresolved name is now dropped
rather than defaulted back to the Digitakt literal.

### 1.2 `intro_running()` answered False for the whole intro

`emu/pit.py` compared vector 208 against a hardcoded `INTRO_PIT3_ISR =
0x400d2d70`. Digitone's intro handler is `0x400d4fb8`, so the test never
matched: the GUI concluded the intro was over before it started, released the
timers into the middle of it and picked the wrong render path.

Measured at every rung of the Digitone ladder, PIT3 is `PCSR=0x093f`
(EN|PIE), `PMR=0x2191`, vector 208 → `0x400d4fb8` — byte-identical
configuration to Digitakt's. The intro was running the whole time.

### 1.3 The unblock policy used Digitakt's pend sites

`longrun.RECHECK_PENDS` — the pends that must be allowed to block — were four
Digitakt literals. On Digitone they name unrelated code, so the sites that
must block were satisfied and vice versa. All four now resolve per build.

---

## 2. Verified address map

Every value below is resolved from the image by `emu/symbols.py`, and every
Digitakt value equals the literal it replaced. `python -m emu.symbols <image>`
prints the table for either build.

| symbol | Digitakt 1.15C | Digitone 1.10E | how resolved |
|---|---|---|---|
| entry, task_create, task_start, sem_pend, pend_b | fixed | same | RTOS, byte-identical |
| `ctx_switch` | `0x40000410` | same | fixed, verified bytes |
| `current_tcb` | `0x47d9adb4` | `0x46487fdc` | `ctx_switch+0x0a` operand |
| `ready_cursor` | `0x4094c914` | `0x4057315c` | `ctx_switch+0x16` operand |
| `flash_read` | `0x401296fe` | `0x40126b46` | masked signature |
| `pend_call` | `0x40128d08` | `0x40126150` | xref + shape |
| `completion_sem` | `0x44e4d69c` | `0x4447c5e4` | `pend_call+10` −8 |
| `sleep_pend` | `0x40128d0e` | `0x40126156` | `pend_call+6` |
| `depack_copy` | `0x4012acb8` | `0x40128100` | opcode idiom |
| `panel_diff` | `0x40126332` | `0x4012377a` | masked signature |
| `fb_front`/`fb_back` | `0x4029f650`/`54` | `0x40287664`/`68` | operands in `panel_diff` |
| `px_copy` | `0x400d315e` | `0x400d53a6` | masked signature |
| **`intro_done`** | `0x400d403c` | **`0x400d6284`** | masked signature (was UNRESOLVED) |
| **`frame_sem`** | `0x43131200` | **`0x42a89a74`** | `intro_done+4` operand, −8 |
| **`intro_pit3_isr`** | `0x400d2d70` | **`0x400d4fb8`** | signature + `frame_sem` operand |
| `intro_park` | `0x400d4068` | `0x400d62b0` | masked signature |
| `display_wait` | `0x401260c2` | `0x4012350a` | masked signature |
| `pump_wait` | `0x400f1bb0` | `0x400f2adc` | masked signature |
| `queue_recv` | `0x40001946` | same | RTOS, byte-identical |
| **`set_pixel`** | `0x40104eb4` | **`0x40105964`** | 64-byte signature (was ambiguous) |
| **`get_pixel`** | `0x40104f80` | **`0x40105a30`** | 64-byte signature (was ambiguous) |
| `mainloop` | `0x40033492` | `0x4002eabe` | masked signature |
| `main_queue` | `0x4094ef3c` | `0x40583220` | `mainloop+2` operand |
| `job_pump` | `0x400f1b80` | `0x400f2aac` | masked signature |
| `display_start` | `0x40126004` | `0x4012344c` | masked signature |
| `sf_mulsf3` | `0x40175204` | `0x401696cc` | 64-byte signature |
| `sf_subsf3` | `0x40174f1c` | `0x401693e4` | 64-byte signature |
| `sf_addsf3` | `0x40174f22` | `0x401693ea` | 64-byte signature |
| `sf_divsf3` | `0x40175346` | `0x4016980e` | 64-byte signature |
| `sf_abssf2` | `0x40174134` | `0x401685fc` | 64-byte signature |
| `sf_fixsfsi` | `0x40175a94` | `0x40169f5c` | 64-byte signature |
| `sf_cmpsf2` | `0x40175834` | `0x40169cfc` | 64-byte signature |

`transport` / `call_sites` remain UNRESOLVED on Digitone. They are OPTIONAL and
diagnostic-only; the run degrades to "no transport-call logging".

### 2.1 Two new resolution rules

`SigWhere` — a masked signature that is deliberately not unique, narrowed by an
abs32 operand tying it to an already-resolved symbol. The intro's PIT3 handler
and the display module's are the same routine compiled twice; they differ only
in which semaphore they post, so `frame_sem` is what tells them apart. (The
other match is the display module's own handler: `0x40125f3c` on Digitakt,
`0x40123384` on Digitone.)

`Offset` — a fixed byte distance from a resolved symbol, for the case where two
names denote the same instruction from two directions (`sleep_pend` is the
return address of the `jsr sem_pend` that `pend_call` names).

`DATA_HI = 0x48000000` widens `Sig`'s mask to cover RAM variables above the
image. It is not free: the window is scanned unaligned, so a wider range also
masks bytes that merely *look* like an address in it (`45f9 4017....` — lea's
opcode plus the top half of its operand — is one that bites, and it is why
`intro_park` uses the default range). Use it only where verified.

### 2.2 The soft-float addresses are cross-validated

Two independent methods agree on `mulsf3`: the masked signature, and the `lea
<mulsf3>,a2` operand at `intro_park+14`. Calling all six arithmetic routines at
their resolved Digitone addresses and comparing against host binary32 gives
results **identical to Digitakt's** — same case counts, same six `mulsf3`
double-rounding edge cases, zero mismatches everywhere else.

---

## 3. Where the ladder rungs land

The ladder's rungs are fixed instruction counts, and the two firmwares do not
reach the same phase at the same count.

```
                  Digitakt                    Digitone
boot60M    intro live, running          intro not yet live
boot120M   intro live, running          intro live, running
boot200M   intro live, running          intro live, running
boot280M   intro live, running          intro live, running   <-- use this
boot400M   intro live, running   <--    intro live, PARKED on frame_sem
```

A parked intro **cannot be resumed**: the task is inside `sem_pend`, where
`unblock` can never see it (it only ever sees a pend on the way *in*), and the
GUI holds PIT3 for as long as the intro owns vector 208 — so the one thing that
could post the semaphore is switched off. The run sits there and the panel
stays black. That is what `boot400M.snap` does on Digitone.

`emu/run.py:usable_rung` now picks by state instead of by number: newest rung
first, take the first one whose intro is live and not already parked. Digitakt
qualifies at every rung and still gets 400M, unchanged; Digitone gets 280M.

Releasing the timers at 400M instead does **not** help — measured, 40M
instructions, zero frames. That state is the section-5 scheduling problem.

---

## 4. What now happens, and the new blocker

From `snapshots/Digitone_II_OS1.10E/boot280M.snap`, 150M instructions:

```
intro held=True
intro_done fired once at 62M      -> timers released
frames flushed 173, distinct 109  -> the intro animates and completes
setPixel 1,302,400                -> then stops
PIT0 919, PIT2 1104               -> the RTOS heartbeat is turning
PIT3 0, DTIM3 0                   -> neither is ever re-armed
3 TCBs scheduled, 4676 of them the prio-1 idle task
```

After the handover, **99.9% of instructions are at a single address**
(`0x400d155a`, an idle `bra.b $self`). Every real task is blocked; the system
is genuinely idle.

### The A/B against Digitakt is decisive

Digitakt, same experiment from `boot400M.snap`:

```
INTRO_DONE                     at 54.0M   (current TCB 0x43135210, the intro task)
TASK prio=2 entry=0x400f1eb6   at 74.2M   (current TCB 0x4094eee8)
TASK prio=6 entry=0x4012606a   at 74.2M
WRITE vector208 = 0x40125f3c   at 74.2M   <- display module claims PIT3
TASK prio=3 entry=0x400f1fce   at 76.8M
TASK prio=5 entry=0x40127b24   at 76.9M
TASK prio=4 entry=0x40127c78   at 76.9M
TASK prio=4 entry=0x40127d9e   at 77.1M
WRITE vector99  = 0x400c30e4   at 77.1M   <- DTIM3 handler installed
WRITE DTMR3     = 0x001d       at 77.1M   <- DTIM3 armed
```

**TCB `0x4094eee8` is the prio-6 main application task, entry `0x40032f5a`.**
It wakes ~20M instructions after the intro ends and does all of it: spawns the
six remaining tasks, re-points vector 208 at the display module's handler,
installs the DTIM3 vector and arms DTIM3. Everything downstream — the display
timer, the 30 Hz UI tick, the job workers — hangs off that one task waking.

On Digitone the equivalent task is prio 6, entry **`0x4002e688`**, tcb
`0x405831cc`. It is parked at `0x4000165c` and never runs. Nothing else in the
post-intro state differs in kind:

| | Digitakt @150M | Digitone @150M |
|---|---|---|
| new tasks spawned | 6 | 0 |
| vector 208 | `0x40125f3c` (display) | `0x400d4fb8` (still the intro's) |
| PIT3 | `0x093f` EN\|PIE, PMR `0x4323` | off, PMR still `0x2191` |
| DTMR3 | `0x001d` | `0x0000` |
| PIT3 / DTIM3 ticks | 72 / 265 | 0 / 0 |

DTIM3 is armed by post-intro code on **both** builds — it is `0x0000` in every
snapshot of both ladders — so this is not a missing initial condition. It is
that one task never waking.

---

## 4b. An emulator defect, not a firmware difference

The prio-6 task's stall traces back to the RTOS timer-wheel task (prio 10)
parking forever on **mutex `0x44460e40` whose owner is `nobody`**. That is a
lost wakeup, and the cause is in the emulator.

`0x400015a0` is `mutex_lock`: `+0` owner, `+4`/`+8` waiter list head/tail,
TCB `+0x50` link, blocking with `trap #0`. Its fast path is

```
0x400015aa  move.w  #$2700,sr        ; IPL 7 -- critical section
0x400015ae  movea.l <CURRENT_TCB>,a0
0x400015b4  move.l  (a2),d0          ; d0 = owner, sets Z
0x400015b6  beq.b   0x400015bc       ; free -> claim it
...
0x400015c2  (enqueue self and block)
```

Measured: **6,409 successful locks** all read `d0 = 0` and branched to the
claim. The one failure read `d0 = 0` **as well** — identical register state —
and fell through to the enqueue. The only difference is that a `spin()` chunk
boundary landed between the load and the branch.

### The minimal repro

```python
# move.l (a2),d0   with (a2) == 0   ->   beq   (should be taken)
uc.emu_start(BASE, 0, count=1)          # stop after the move.l
pc = uc.reg_read(UC_M68K_REG_PC)
sr = uc.reg_read(UC_M68K_REG_SR)        # <-- THIS destroys the pending flags
uc.emu_start(pc, 0, count=2)            # beq is NOT taken
```

| between the two emu_start calls | branch |
|---|---|
| nothing | taken (correct) |
| `reg_read(PC)` | taken (correct) |
| `reg_read(D1)` | taken (correct) |
| **`reg_read(SR)`** | **not taken — flags lost** |
| `reg_read(SR)` from inside a UC_HOOK_CODE, during execution | taken (correct) |

Unicorn's m68k keeps condition codes lazily; reading SR at an `emu_start`
boundary materialises them wrongly. `emu/pit.py:Pits.service` reads SR at every
chunk boundary to check the IPL before delivering a timer — so every timer
service is a chance to corrupt the flags of the instruction that just ran.

Confirmed by phase-shifting the boundaries: with `spin(..., cap=137777)` the
mutex enqueue and block **disappear entirely** on the same snapshot.

**This is general, and Digitakt is merely lucky.** The two firmwares' mutex
code is byte-identical apart from the relocated `CURRENT_TCB` literal (checked
byte by byte over `0x400015a0`–`0x40001710`). Digitakt locks the same mutex
17,150 times and never has a boundary land in that two-instruction window.

**The fix** is to stop reading SR at a boundary: shadow the IPL, updated from
scoped hooks on the SR-writing instructions — 620 sites on Digitakt, 389 on
Digitone (`move.w <ea>,sr`, `0x46xx`) — which is the pattern
`Machine.install_isa_patches_scoped` already uses. Do NOT "fix" it by writing
SR back: that installs a stale condition-code byte and makes things worse
(measured: the firmware reaches its own panic handler and HALTs).

Note this is *a* blocker, not proven to be the only one: with the boundary
phase shifted so the mutex never deadlocks, the OS still spawns no tasks
within 120M instructions.

## 5. Next steps, most promising first

1. **Fix the SR-read-at-boundary defect** (section 4b). Shadow the IPL from
   scoped hooks instead of reading SR in `Pits.service`. This is a correctness
   fix for both firmwares, and it is the only one of these steps that is
   fully specified and ready to implement.
2. **Then re-measure.** With the mutex deadlock gone the OS still spawned no
   tasks in 120M, so expect at least one more blocker behind it. Hook
   `sem_post`/`mutex_unlock` and find what the prio-6 task is waiting on;
   `main_queue` (`0x4094ef3c` / `0x40583220`) is resolved and is the queue its
   message loop pends on.
2. **Read the pend argument properly.** The `sp+0x0c` offset used for the task
   dumps in this session is not reliable for every task (it produced obvious
   nonsense like `sem 0x00000003`). Get it right before trusting any
   "blocked-on" column.
3. **Storage.** `read_blocks` still returns zeros. If the main task's first
   post-intro act is a filesystem read, that is the wake it never gets. Check
   before doing anything larger.
4. **`0xb5220070`** — the garbage callback pointer from the old 400M ladder. It
   was *not* the mis-aimed soft-float hooks: those seven Digitakt addresses are
   never executed on Digitone (measured, 20M instructions). Still unexplained,
   but it is a 400M-path symptom and the 280M path does not reach it.
5. `sqrtf` (`0x40167238` on Digitone, a 25-iteration restoring square root) is
   ~19% of post-HLE intro instructions and is **not** HLE'd on either build.
   Worth adding for both — it is not a Digitone-specific problem.

---

## 6. Corrections to the previous handover

- **"The display task blocks on FRAME_SEM and is never scheduled because the
  prio-10 timer task never blocks."** Not reproduced. In `boot400M.snap` the
  prio-10 task is blocked with count 0 and a recorded waiter, exactly like the
  others. The 76%-of-cycles figure was measured under the old (unresolved)
  address regime.
- **`SET_PIXEL` / `GET_PIXEL` "ambiguous"** — they are ambiguous at 48 bytes,
  which is where the previous attempt stopped. Each has a near-twin `0x66`
  bytes further on sharing its first 48 bytes; 64 bytes separates them, and
  picks the address already known correct on Digitakt.
- **`INTRO_DONE` "no signature match"** — it matches uniquely in both images
  with the mask widened to cover RAM operands (`DATA_HI`). Its two hard MMIO
  literals are what make it unique.
- **The Digitone snapshots were never poisoned.** `sections/.source-sha256`
  confirms the ladder was built from the right image. Rebuilding changes
  nothing, as the previous session found — it just was not the problem.

---

## 7. Commands

`sections/` holds exactly one firmware at a time, so keep two directories:

```sh
uv run python -m emu.extract Digitakt_II_OS1.15C.syx -o /tmp/sec-dt
uv run python -m emu.extract Digitone_II_OS1.10E.syx -o /tmp/sec-dn

DT2_SECTIONS=/tmp/sec-dn uv run python -m emu.symbols /tmp/sec-dn/section_3_MAIN_OS.bin

# the intro, headless, with the panel as ASCII + PNG
DT2_SECTIONS=/tmp/sec-dn uv run python -m emu.panel \
  snapshots/Digitone_II_OS1.10E/boot280M.snap 40000000 3 out/digitone_intro.png

# the GUI picks the right rung itself now
DT2_SECTIONS=/tmp/sec-dn uv run python -m emu.run Digitone_II_OS1.10E.syx

# rebuild the ladder (checkpoint make does NOT create the directory)
mkdir -p snapshots/Digitone_II_OS1.10E
DT2_SECTIONS=/tmp/sec-dn uv run python -m emu.checkpoint make \
  60000000,120000000,200000000,280000000,400000000 \
  snapshots/Digitone_II_OS1.10E/boot Digitone_II_OS1.10E.syx
```

pyGhidra is still the right tool for "what does this do". The image loads at
base 0, so pass `virtual - 0x40000400`; language `68000:BE:32:Coldfire`;
`analyzeHeadless` is at
`/opt/homebrew/Cellar/ghidra/12.1.3/libexec/support/analyzeHeadless`.
Capstone with `CS_MODE_M68K_040` decodes this ISA fine for short reads and is
much quicker to reach for.

---

## 8. Regression — Digitakt must stay exactly this

```
DT2_SECTIONS=/tmp/sec-dt uv run python -m emu.symbols
  -> every symbol resolves, values as in the table above

DT2_SECTIONS=/tmp/sec-dt uv run python emu/oracle.py
  -> CRC + residue pass

DT2_SECTIONS=/tmp/sec-dt uv run python -m emu.softfloat
  -> 1774 cases checked, 0 mismatches, 1154 deferred

DT2_SECTIONS=/tmp/sec-dt uv run python -m emu.dspboot 60000000
  -> 38247 distinct addrs, 5 tasks, pc=0x4012acbe, 13 idle spins

DT2_SECTIONS=/tmp/sec-dt uv run python -m emu.frame snapshots/boot400M.snap 20000000
  -> setPixel 616823, 75 frames, 344 lit

DT2_SECTIONS=/tmp/sec-dt uv run python -m emu.panel snapshots/boot400M.snap 40000000 3
  -> flushed 135, distinct 74, lit 411        (new baseline this session)
```

All verified after every change in this session.
