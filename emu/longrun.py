"""Long fast run: no per-instruction hook, chunked preemption, watch everything
that matters via begin==end hooks (free between hits).

`build()` is the reusable half: it stands up a Machine with the same behaviour
hooks dspboot.run installs (flash HLE, completion-semaphore patch, ISA patches,
MMIO, exceptions) and restores a snapshot onto it. Resuming onto a bare Machine
instead silently drops those hooks and the run diverges -- see snapshot.py.
"""
import struct, sys, os, time, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn import UcError, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.m68k_const import (UC_M68K_REG_A7, UC_M68K_REG_PC, UC_M68K_REG_SR,
                                UC_M68K_REG_D0, UC_M68K_REG_D2, UC_M68K_REG_A0)
import emu.dspboot as db
from emu.harness import Machine
from emu.snapshot import restore_into

TASK_CREATE, PRINT = 0x400012c8, 0x400054b4
SETPIXEL, PXCOPY   = 0x40104eb4, 0x400d315e
SWITCH_TO          = 0x4000044a
USR8, UDR8         = 0xEC070004, 0xEC07000C


MAIN_IMG = 'sections/section_3_MAIN_OS.bin'


PEND_A, PEND_B = 0x4000141a, 0x400013a6   # sem object is the arg at 4(a7)

# Sites that decide how far `unblock` may go. Each of these is a pend whose
# caller re-checks a condition afterwards and loops, so force-satisfying the
# semaphore turns a sleep into an infinite spin. Blocking is the correct
# behaviour at all of them: nothing has arrived.
#
#   QUEUE_RECV  the pend inside queue_receive (0x40001928). It waits on the
#               queue's own semaphore at queue+8, then re-reads queue->count.
#               Measured at 8.9M iterations, ~92% of all post-intro cycles.
#   INTRO_PARK  the intro task's park loop (0x400d4060). It pends the SAME
#               semaphore the intro loop pends at 0x400d4038, which must be
#               satisfied -- so this has to be told apart by caller, not by
#               semaphore. Blocking here is what frees the CPU once the intro
#               is over, and unlike the INTRO_DONE hook below it also works on
#               a snapshot taken after the intro had already finished.
#   DISPLAY_WAIT  the prio-6 progress-screen task (0x4012606a) waiting on
#               0x44e2d148 and re-checking a flag at 0x44e2d5cc. Note this is
#               the loading screen, not the user interface -- see HANDOVER.
#   PUMP_WAIT   the job worker pool's "is there work" pend, at the top of the
#               pump 0x400f1b80 (`jsr (a5)` at 0x400f1bae, a5 = PEND_B). The
#               semaphore is a plain count of queued jobs, so satisfying it
#               hands the worker a ring slot nobody wrote. It then runs a job
#               that is not there and destroys the record, whose std::string
#               has a null data pointer -- and `_M_dispose` frees
#               `_M_data() - sizeof(_Rep)`, which for a null is 0xfffffff4.
#               That trips the allocator's own bounds check and takes vector 4
#               at the `illegal` opcode at 0x40111458. It is very likely the
#               whole "C++ throw nothing can unwind" story of section 9: the
#               recorded message is `basic_string::_S_construct null not
#               valid`, which is the same null string seen from the other end.
#               Measured from postintro.snap with dsp=True: blocking here takes
#               a run that faulted at 70.2M to a clean 100M, and takes the pump
#               from one job to two.
#   SLEEP_PEND  the microsecond sleep in `0x40128c7c`. It arms DMA timer 1
#               and pends `0x44e4d69c` at `0x40128d08`, and the timer's own
#               ISR `0x40128c4c` posts it. Satisfying it makes every sleep
#               in the firmware a no-op, which is only harmless while
#               DTIM1 is not delivered -- see emu/dtim.py. Blocking here is
#               correct once it is, and is what stops the priority-3 job
#               worker monopolising the CPU.
QUEUE_RECV   = 0x40001946
INTRO_PARK   = 0x400d4068
DISPLAY_WAIT = 0x401260c2
PUMP_WAIT    = 0x400f1bb0
SLEEP_PEND   = 0x40128d0e
RECHECK_PENDS = (QUEUE_RECV, INTRO_PARK, DISPLAY_WAIT, PUMP_WAIT)

# Only correct when DTIM1 is actually delivered; see build(real_sleep=...).
REAL_SLEEP_PENDS = (SLEEP_PEND,)

INTRO_DONE = 0x400d403c                   # intro loop's exit branch target
FRAME_SEM  = 0x43131200                   # intro frame-pacing semaphore


def build(snapshot, send=b'', syx='Digitakt_II_OS1.15C.syx', isa='scoped',
          unblock=False, softfloat=False, bitmap=False, on_pixel=None,
          unblock_except=(), edma=True, real_sleep=False, dsp=False,
          srtrap=False, weakptr=False):
    """Stand up a hooked Machine and restore `snapshot` onto it.

    -> (m, ev, st, pc, inq, at) where `at(addr, fn)` registers a further
    begin==end code hook and `inq` is the UART8 receive queue (a deque of
    ints; append to it to feed the firmware input).

    isa='scoped' pre-scans MAIN OS for the FF1/MOVEC addresses and hooks only
    those, instead of running a Python callback on every instruction. This is
    what dspboot.run's fast path uses, so it is also what produced the
    snapshots -- resuming with it keeps the run faithful *and* is ~3x quicker.
    isa='global' is the belt-and-braces version: it also catches those opcodes
    outside the MAIN OS image, at the cost of that per-instruction callback.

    unblock=True force-satisfies every sem_pend whose count is <= 0, so the
    wait takes the primitive's non-blocking fast path. Without it every task
    but the idle one parks forever waiting on a device event -- DSP, panel,
    MIDI -- that no emulated hardware will ever raise. dspboot already does
    this for the one DSP transport semaphore; this is the same trick applied
    to every wait, and it is what makes the draw task actually draw.
    It does change semantics: nothing ever really waits, so inter-task
    ordering is not the hardware's. `unblock_except` lists semaphore objects
    to leave alone, for waits you want to drive properly instead -- the intro
    frame semaphore 0x43131200 is the case that matters, since satisfying it
    is what makes the animation run unpaced.

    `unblock` never satisfies a pend from any of RECHECK_PENDS -- call sites
    that re-check a condition after the wait and loop, so satisfying them
    spins instead of sleeping. It also stops satisfying the intro frame
    semaphore by itself once the intro's exit path is reached, which covers a
    run that executes the intro; RECHECK_PENDS covers a run resumed from a
    snapshot taken after it.

    softfloat=True runs the firmware's float routines natively instead of
    emulating them. It is OFF by default: it is bit-exact but changes
    instruction counts, and too much in this project depends on a resumed run
    matching the run that made its snapshot. Turn it on for watching, leave it
    off for coverage, differential or checkpoint work. 93% of executed instructions were soft-float, so this is
    the difference between ~2M and ~20M instructions/sec. It is bit-exact --
    only the fast path is intercepted and everything else defers to the real
    routine (see emu/softfloat.py) -- so program state evolves identically.
    Instruction *counts* do not: a run with it on is not comparable to one
    without, so turn it off for coverage or differential work.

    bitmap=True does the same for Bitmap::setPixel/getPixel, the top cost once
    the float work is gone. `on_pixel(x, y, val)` then receives every pixel
    drawn, which is how the frame capture observes drawing -- so callers must
    not also register their own setPixel hook.

    `edma` models eDMA channel 35, the UART8 transmit ring. It defaults ON
    because without it the firmware's console-enqueue routine spins forever
    waiting for ring space and boot cannot get past the intro -- see
    emu/edma.py. Unlike the softfloat/bitmap HLEs this is a hardware model,
    not a shortcut, so there is no faithful configuration with it off.

    real_sleep=True makes `0x40128c7c` a real sleep instead of a no-op, by
    letting `unblock` block at SLEEP_PEND instead of force-satisfying it.
    It requires that DTIM1 is being delivered (see emu/dtim.py) or the
    priority-3 job worker will block forever.

    srtrap=True routes exception entry through guest code so the frame
    carries the CPU's real condition codes. Unicorn's m68k never reports
    computed flags through `reg_read(UC_M68K_REG_SR)`, so the frame we used to
    build carried a stale CCR that `rte` then installed over the flags of the
    code being resumed -- see Machine.install_srtrap. Default off because the
    fix is not finished: it delivers interrupts and runs the ISRs correctly
    but the boot stops progressing.

    dsp=True backs the `0x8C000000` coprocessor port's ready line, without
    which the priority-3 job worker wedges on its first transfer -- see
    emu/dsp.py. Default off because it is new, in the same spirit as
    softfloat and bitmap defaulting off.

    weakptr=True neutralises the two branches in `weak_ptr::lock` that send
    the main task into the terminal loop at `0x4012d2fa`:

        40188b40  6714 beq.b $40188b56  ->  4e71 nop     (a0 is NOT null)
        40188b50  660a bne.b $40188b5c  ->  600a bra.b   (d0 is NOT zero)

    Both branches contradict the memory they were taken on -- measured at the
    hang the control block reads 0x4509e3f0 and the use count reads 2 -- so
    this is the condition-code corruption of HANDOVER section 10 showing
    through, not a firmware decision. It is a DIAGNOSTIC, not a fix: it papers
    over one symptom of the exception model and leaves the cause alone.

    It is a two-byte memory write applied before `emu_start` is ever called,
    so it adds no hook (HANDOVER warning 2) and no translation block can be
    stale. Without it the main task burns the CPU forever -- 252,977,319 of
    300M instructions in a `bra.b` to itself -- and the message loop stops at
    153. With it there is no terminal loop and the loop reaches 168.
    """
    flash = db.build_flash(syx)
    m = Machine(); st = {'seen': set(), 'n': 0, 'task_create_hits': {}}
    ev = {'tasks': [], 'prints': [], 'setpixel': 0, 'pxcopy': 0,
          'switch': collections.Counter(), 'switch_seq': [],
          'uart_out': bytearray(), 'satisfied': 0, 'depack_clamps': 0}
    inq = collections.deque(send)
    main_img = open(MAIN_IMG, 'rb').read()
    if isa == 'scoped':
        m.install_isa_patches_scoped(main_img, db.MAIN_LOAD)
    else:
        m.install_isa_patches()

    def at(addr, fn):
        m.uc.hook_add(UC_HOOK_CODE, fn, begin=addr, end=addr)

    def flash_read(uc, a, s, d):
        sp = uc.reg_read(UC_M68K_REG_A7)
        ret, off, ln, dest = struct.unpack('>IIII', uc.mem_read(sp, 16))
        if ln and dest and off + ln <= len(flash):
            for p in range(0, ln + 0x100000, 0x100000): m.ensure(dest + p)
            uc.mem_write(dest, flash[off:off + ln])
        uc.reg_write(UC_M68K_REG_D0, 0); uc.reg_write(UC_M68K_REG_A7, sp + 4)
        uc.reg_write(UC_M68K_REG_PC, ret)

    def task_create(uc, a, s, d):
        sp = uc.reg_read(UC_M68K_REG_A7)
        _r, tcb, entry, prio = struct.unpack('>IIII', uc.mem_read(sp, 16))
        ev['tasks'].append((entry, prio, tcb))
        print('   TASK entry=0x%08x prio=%d tcb=0x%08x' % (entry, prio, tcb), flush=True)

    def do_print(uc, a, s, d):
        sp = uc.reg_read(UC_M68K_REG_A7)
        p = struct.unpack('>I', uc.mem_read(sp + 4, 4))[0]
        try: txt = bytes(uc.mem_read(p, 160)).split(b'\x00')[0].decode('latin1')
        except Exception: txt = '<0x%08x>' % p
        ev['prints'].append(txt)
        print('   PRINT %r' % txt, flush=True)

    def switch_to(uc, a, s, d):
        tcb = uc.reg_read(UC_M68K_REG_A0)
        ev['switch'].update([tcb])
        if not ev['switch_seq'] or ev['switch_seq'][-1] != tcb:
            ev['switch_seq'].append(tcb)

    at(db.FLASH_READ, flash_read)
    at(db.PEND_CALL, lambda uc,a,s,d: uc.mem_write(db.COMPLETION_SEM, struct.pack('>I',1)))
    at(TASK_CREATE, task_create)
    at(PRINT, do_print)
    at(SETPIXEL, lambda uc,a,s,d: ev.__setitem__('setpixel', ev['setpixel']+1))
    at(PXCOPY,   lambda uc,a,s,d: ev.__setitem__('pxcopy',  ev['pxcopy']+1))
    at(SWITCH_TO, switch_to)

    # dspboot.run installs two more behaviour hooks, and the snapshots were
    # made with them. Leaving them out here makes a resumed run diverge from
    # the run that produced the snapshot -- the same trap as resuming onto a
    # bare Machine, just less obvious: the init task then never reaches its
    # own flag test at 0x400cf384.
    def depack_clamp(uc, a, s, d):
        if uc.reg_read(UC_M68K_REG_D2) > db.DEPACK_LEN_CAP:
            uc.reg_write(UC_M68K_REG_D2, 1)
            ev['depack_clamps'] += 1
    at(db.DEPACK_COPY, depack_clamp)

    tx = None
    if edma:                           # see emu/edma.py
        from emu.edma import install as install_edma
        tx = install_edma(m, at, ev)

    if dsp:                            # see emu/dsp.py
        from emu.dsp import install as install_dsp
        install_dsp(m, ev)

    spins = {'n': 0}

    def do_halt(uc, a, s, d):
        spins['n'] += 1
        if tx is not None:
            tx.deliver()
        if spins['n'] % 20000 == 0:
            m.raise_vector(32)
    for spin_addr in db.find_idle_spins(main_img, db.MAIN_LOAD):
        at(spin_addr, do_halt)

    if softfloat:                      # see emu/softfloat.py
        from emu.softfloat import install as install_softfloat
        ev['softfloat'] = collections.Counter()
        install_softfloat(at, ev['softfloat'])

    if bitmap:
        from emu.hle import install_bitmap
        ev['bitmap'] = collections.Counter()
        install_bitmap(at, ev['bitmap'], on_pixel)

    if unblock:
        # Both sets are kept mutable and exposed on `ev` so a run can change
        # policy partway through, which the intro needs: its frame semaphore
        # has to be satisfied while the intro runs and must NOT be once it
        # finishes, or the draw task busy-spins at prio 7 and starves the rest
        # of the system. That handoff is wired up below rather than left to
        # each caller -- getting it wrong is silent, it just looks like a hang.
        skip = set(unblock_except)
        ev['unblock_skip'] = skip
        skip_callers = set(RECHECK_PENDS)
        if real_sleep:
            skip_callers |= set(REAL_SLEEP_PENDS)
        ev['unblock_skip_callers'] = skip_callers

        def satisfy(uc, a, s, d):
            sp = uc.reg_read(UC_M68K_REG_A7)
            ret, sem = struct.unpack('>II', uc.mem_read(sp, 8))
            if not sem or sem in skip or ret in skip_callers:
                return
            try:
                if struct.unpack('>i', uc.mem_read(sem, 4))[0] <= 0:
                    uc.mem_write(sem, struct.pack('>I', 1))
                    ev['satisfied'] += 1
            except Exception:
                pass
        at(PEND_A, satisfy); at(PEND_B, satisfy)
        at(INTRO_DONE, lambda uc, a, s, d: skip.add(FRAME_SEM))

    def onr(uc, typ, addr, size, val, data):
        if addr == USR8: uc.mem_write(USR8, bytes([0x04 | (0x01 if inq else 0)]))
        elif addr == UDR8: uc.mem_write(UDR8, bytes([inq.popleft() if inq else 0]))
    def onw(uc, typ, addr, size, val, data):
        if addr == UDR8: ev['uart_out'].append(val & 0xFF)
    m.uc.hook_add(UC_HOOK_MEM_READ, onr, begin=USR8, end=UDR8+3)
    m.uc.hook_add(UC_HOOK_MEM_WRITE, onw, begin=USR8, end=UDR8+3)
    m.mmio[0xFC05C02C] = 0x100000F0; m.mmio[0xEC03802C] = 0x80000000
    # Route exception entry through guest code that writes the TRUE SR into
    # the frame. Off by default: it is a correct fix for a proven defect (see
    # Machine.install_srtrap) but it is not yet a working one -- with it on,
    # the main task is still scheduled and the ISRs still run, yet it never
    # reaches task_create and the boot makes no progress. Finish that before
    # turning it on. HANDOVER section 10 has the standing warning about how
    # sensitive this run is to anything that touches the exception path.
    if srtrap:
        m.install_srtrap()
    m.install_exceptions()
    weak_sites = ((0x40188b40, b'\x67\x14', b'\x4e\x71'),
                  (0x40188b50, b'\x66\x0a', b'\x60\x0a'))
    # restore_into merges the snapshot's own mmio entries, and install_mmio
    # registers a hook per address, so it has to come after the merge or a
    # snapshot-carried address would go unhooked.
    pc = restore_into(m, snapshot, st)
    if weakptr:
        # After restore_into, or the snapshot's own copy of MAIN OS would
        # overwrite the patch.
        for addr, want, new in weak_sites:
            cur = bytes(m.uc.mem_read(addr, 2))
            if cur != want:
                raise RuntimeError('weakptr: %#010x holds %s, expected %s'
                                   % (addr, cur.hex(), want.hex()))
            m.uc.mem_write(addr, new)
    m.install_mmio()
    if tx is not None:
        from emu.edma import kick
        kick(m, tx)
    return m, ev, st, pc, inq, at


def run_until(m, pc, timeout_ms=250):
    """Run with no instruction budget until a hook calls `uc.emu_stop()`.

    -> (pc, stop_reason). Prefer this over `spin` wherever the stopping
    condition can be written as a hook, because passing `count` to emu_start
    makes Unicorn install an internal per-instruction hook to decrement the
    budget, and that defeats its fast dispatch path. Measured over the same 40
    rendered frames: 8.03s with `count=250_000` against 4.45s with no count,
    a 1.8x difference for identical work.

    The cost is in `count` itself, not in how often emu_start is called --
    over the same 100 frames, count=20k (1308 calls), count=500k (53 calls)
    and count=1e9 (1 call) all land within 3% of each other.

    `timeout_ms` bounds how long a single call may stay inside Unicorn, so a
    caller that also has to honour a pause or stop flag keeps responding even
    when the firmware stops doing whatever the hook was watching for. Without
    it, a hook-only stop condition hangs the caller the moment the firmware
    stops meeting it -- which is exactly what happens when the intro ends and
    nothing draws any more. A timeout return is not distinguishable from a
    hook return, so the caller re-checks its own condition and calls again,
    which is what a loop does anyway. Pass 0 for no bound.

    Unlike `count`, a timeout is free: over those same 40 frames, uncounted
    measures 4.45s and uncounted with a 0.5s timeout measures 4.43s. `count`
    installs a per-instruction hook; a timeout only arms a timer thread.

    Stop only from a hook that has already moved PC past the current
    instruction -- the setPixel HLE writes PC = return address, so it
    qualifies. Stopping from a plain code hook leaves PC on the hooked
    address, and resuming re-enters the same hook immediately: the run then
    spins making no progress while appearing to iterate.
    """
    try:
        m.uc.emu_start(pc, 0, timeout=timeout_ms * 1000)
        stop = 'stopped'
    except UcError as e:
        stop = str(e)
    return m.uc.reg_read(UC_M68K_REG_PC), stop


def spin(m, pc, instrs, chunk=500_000, on_chunk=None, tick=False, pits=None,
         cap=None):
    """Run in chunks. -> (pc, executed, stop_reason).

    Pass `pits` (an emu.pit.Pits) to run to each timer deadline exactly
    instead of to a fixed chunk. `chunk` is then unused: the step is
    whatever remains before the next PIT is due, so an interrupt lands on
    the instruction the timer was due at. Without this, the same run from
    the same snapshot gives different fault counts and different display
    callback counts for nothing but a different chunk size. `cap` bounds a
    single step for a caller that needs to regain control periodically.
    Servicing the timers is part of this loop when `pits` is given, so do
    not also service them from `on_chunk`.

    A `Pits` holds its deadlines as absolute instruction counts, and `done`
    here restarts at zero on every call, so successive calls with the same
    `Pits` resume from `pits.now` rather than rewinding the clock. Without
    that, a caller that spins in a loop -- the GUI does -- gets timer ticks
    during its first call and silence afterwards, because every deadline is
    already in the past-that-is-now-the-future.

    In `pits` mode `instrs` is a floor, not a ceiling: the loop finishes the
    deadline step it is on, so it returns having executed up to one timer
    period more than asked. That is deliberate. It makes one call of N
    instructions and ten calls of N/10 execute the identical instruction
    stream, which is what lets the GUI and the measurement harness agree.

    Accounting is of what actually executed, not what was requested. When a
    vector has no handler, `install_exceptions` stops the run from inside
    the hook: emu_start returns normally, having executed nothing, and a
    loop that credits itself the full step races to the instruction budget
    in seconds and reports a run that never happened.

    tick=True injects a vector-32 (scheduler) trap at every chunk boundary.
    That is NOT what the hardware does and NOT what dspboot.run does -- it
    forces a reschedule in the middle of whatever code happens to be running,
    and a resumed run then diverges from the run that produced the snapshot
    (the init task never reaches its own flag test at 0x400cf384). Ticking
    idle spins, which build() does, is the faithful mechanism. Left available
    only for deliberate "shake it and see" experiments.

    Every chunk boundary costs a `count=` argument to emu_start, which is
    ~1.8x slower than running uncounted -- see run_until. Use spin only when
    something genuinely has to happen per fixed number of instructions.
    """
    done, stop = 0, 'limit'
    base = pits.now if pits is not None else 0      # resume, do not rewind
    while done < instrs:
        # No `remaining` in pits mode: run the whole deadline step and
        # overshoot `instrs` rather than truncating, so every emu_start
        # boundary is a timer deadline no matter how the caller splits its
        # budget. See Pits.step.
        step = (pits.step(base + done, None, cap) if pits is not None
                else min(chunk, instrs - done))
        m.halt_vec = None
        try: m.uc.emu_start(pc, 0, count=step)
        except UcError as e: stop = str(e); break
        pc = m.uc.reg_read(UC_M68K_REG_PC)
        if m.halt_vec is not None:
            stop = 'unhandled vector %d at %#010x' % (m.halt_vec, pc)
            break
        done += step
        if pits is not None:
            pits.now = base + done
            pits.service(base + done)
            # raise_vector moves PC. Resuming at the stale one leaves the
            # exception frame stranded on the stack: the next rts pops it as
            # a return address and jumps to nowhere. Cost a session once, as
            # a vector-4 fault exactly one timer tick after the first.
            pc = m.uc.reg_read(UC_M68K_REG_PC)
        if on_chunk:
            on_chunk(pc, done)
            pc = m.uc.reg_read(UC_M68K_REG_PC)
        if tick and (m.uc.reg_read(UC_M68K_REG_SR) & 0x0700) != 0x0700:
            m.raise_vector(32); pc = m.uc.reg_read(UC_M68K_REG_PC)
    return pc, done, stop


def main(snapshot, instrs, chunk=500_000, send=b'', unblock=False, fast=False):
    m, ev, st, pc, inq, at = build(snapshot, send, unblock=unblock,
                                   softfloat=fast, bitmap=fast)
    t0 = time.time()

    def note(pc_, done):
        if done % 250_000_000 == 0:
            print('  .. %dM instrs, %.1fs, tasks=%d prints=%d setPixel=%d'
                  % (done//1_000_000, time.time()-t0, len(ev['tasks']),
                     len(ev['prints']), ev['setpixel']), flush=True)

    pc, done, stop = spin(m, pc, instrs, chunk, on_chunk=note)
    return m, ev, done, time.time()-t0, stop


if __name__ == '__main__':
    snap = sys.argv[1]; n = int(sys.argv[2])
    send = (sys.argv[3]+'\r\n').encode() if len(sys.argv) > 3 else b''
    m, ev, done, dt, stop = main(snap, n, send=send,
                                 unblock=bool(os.environ.get('UNBLOCK')),
                                 fast=bool(os.environ.get('FAST')))
    print('\n=== %d instrs in %.0fs (%.2fM/s) stop=%s ===' % (done, dt, done/dt/1e6, stop))
    print('new tasks : %d' % len(ev['tasks']))
    print('prints    : %d' % len(ev['prints']))
    print('setPixel  : %d   px_copy_to_bitmap: %d' % (ev['setpixel'], ev['pxcopy']))
    print('distinct TCBs scheduled: %d   pends satisfied: %d'
          % (len(ev['switch']), ev['satisfied']))
    print('uart out  : %r' % bytes(ev['uart_out'])[:200])
    w,h,buf = struct.unpack('>III', m.uc.mem_read(0x4028ae98, 12))
    px = bytes(m.uc.mem_read(buf, w*h))
    print('intro framebuffer 0x%08x nonzero: %d/%d' % (buf, sum(1 for b in px if b), w*h))
