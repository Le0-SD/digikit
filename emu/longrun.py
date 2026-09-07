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

# Sites that decide how far `unblock` may go. QUEUE_RECV is the pend inside
# queue_receive (0x40001928): it waits on the queue's own semaphore at
# queue+8, then re-reads queue->count and loops. Satisfying that semaphore
# without also enqueuing an item turns a sleep into an infinite spin --
# measured at 8.9M iterations, ~92% of all post-intro cycles, on one queue.
# Blocking there is the correct behaviour: nothing has arrived.
QUEUE_RECV = 0x40001946                   # return address of that pend
INTRO_DONE = 0x400d403c                   # intro loop's exit branch target
FRAME_SEM  = 0x43131200                   # intro frame-pacing semaphore


def build(snapshot, send=b'', syx='Digitakt_II_OS1.15C.syx', isa='scoped',
          unblock=False, softfloat=False, bitmap=False, on_pixel=None,
          unblock_except=(), edma=True):
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

    `unblock` never satisfies a pend made from inside queue_receive: that one
    re-checks the queue's item count after the wait, so satisfying it without
    enqueuing anything spins instead of sleeping. It also stops satisfying the
    intro frame semaphore by itself once the intro's exit path is reached.

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
        skip_callers = {QUEUE_RECV}
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
    m.install_exceptions()
    # restore_into merges the snapshot's own mmio entries, and install_mmio
    # registers a hook per address, so it has to come after the merge or a
    # snapshot-carried address would go unhooked.
    pc = restore_into(m, snapshot, st)
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


def spin(m, pc, instrs, chunk=500_000, on_chunk=None, tick=False):
    """Run in chunks. -> (pc, executed, stop_reason).

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
    while done < instrs:
        try: m.uc.emu_start(pc, 0, count=min(chunk, instrs - done))
        except UcError as e: stop = str(e); break
        pc = m.uc.reg_read(UC_M68K_REG_PC); done += chunk
        if on_chunk: on_chunk(pc, done)
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
