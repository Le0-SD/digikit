"""Why does only one task ever run?

Resumes a snapshot with the full behaviour-hook set and answers three questions
at once:

  * which tasks exist, and which TCB the scheduler actually switches to
  * where every blocking wait happens: the two counting-semaphore pend
    primitives, logged with caller, semaphore object and the count seen on
    entry (count > 0 takes the non-blocking fast path; count == 0 blocks)
  * where the running task spends its time, by sampling PC between chunks

Usage: python -m emu.probe [snapshot] [instrs] [chunk]
"""
import struct, sys, os, time, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC, UC_M68K_REG_SR
from emu.longrun import build, spin

PENDS = {0x4000141a: 'pend_A', 0x400013a6: 'pend_B'}
READY_CURSOR, CURRENT_TCB = 0x4094c914, 0x47d9adb4


def u32(m, addr):
    try: return struct.unpack('>I', m.uc.mem_read(addr, 4))[0]
    except Exception: return None


def main(snapshot, instrs, chunk=20_000):
    m, ev, st, pc, inq, at = build(snapshot)

    pends = collections.Counter()      # (prim, caller, sem) -> hits
    blocked = collections.Counter()    # same, but only when count == 0
    for addr, name in PENDS.items():
        def make(name):
            def h(uc, a, s, d):
                sp = uc.reg_read(UC_M68K_REG_A7)
                ret, obj = struct.unpack('>II', uc.mem_read(sp, 8))
                cnt = u32(m, obj) if obj else None
                key = (name, ret, obj)
                pends[key] += 1
                if cnt == 0: blocked[key] += 1
            return h
        at(addr, make(name))

    samples = collections.Counter()
    pc, done, stop = spin(m, pc, instrs, chunk,
                          on_chunk=lambda p, n: samples.update([p]))

    print('\n=== %d instrs, stop=%s, pc=0x%08x ===' % (done, stop, pc))
    print('carried coverage: %d addrs, %d tasks from snapshot'
          % (len(st['seen']), len(st['task_create_hits'])))

    print('\ntasks created before the snapshot:')
    for site, info in sorted(st['task_create_hits'].items(),
                             key=lambda kv: kv[1]['prio']):
        print('  entry=0x%08x prio=%-3d tcb=0x%08x stack=0x%08x'
              % (info['entry'], info['prio'], info['tcb'], info['stack']))

    print('\nscheduler:')
    print('  ready cursor @0x%08x = 0x%08x' % (READY_CURSOR, u32(m, READY_CURSOR) or 0))
    print('  current TCB @0x%08x = 0x%08x' % (CURRENT_TCB, u32(m, CURRENT_TCB) or 0))
    print('  distinct TCBs switched to: %d  %s'
          % (len(ev['switch']), ['0x%08x' % t for t in ev['switch']]))
    print('  switch sequence (deduped runs, first 20): %s'
          % ['0x%08x' % t for t in ev['switch_seq'][:20]])

    print('\nblocking waits (sem_pend sites), count==0 means it BLOCKED:')
    print('  %-7s %-11s %-11s %-8s %s' % ('prim', 'caller', 'sem obj', 'hits', 'blocked'))
    for key, c in pends.most_common(25):
        prim, ret, obj = key
        print('  %-7s 0x%08x  0x%08x  %-8d %d' % (prim, ret, obj, c, blocked[key]))
    if not pends:
        print('  (none reached)')

    print('\nhot PCs (sampled every %d instrs, %d samples):' % (chunk, sum(samples.values())))
    for a, c in samples.most_common(15):
        print('  0x%08x  %d' % (a, c))




# --- follow-up: what is the running draw task actually doing? ---------------
# The prio-7 task at entry 0x400d3fb6 is the only one scheduled, and it spends
# all of its time in the soft-float helpers at 0x4017xxxx. That says nothing
# about *which* of its own loops is calling them, so: histogram the return
# address at each soft-float entry, and take ranged coverage of the task's own
# code region.
SOFTFLOAT = {0x40175288: '__mulsf3', 0x40174fac: 'sf_b', 0x40175644: 'sf_c',
             0x40174ff8: 'sf_d', 0x40175680: 'sf_e'}
DRAW_LO, DRAW_HI = 0x400d0000, 0x400d5fff


def draw(snapshot, instrs, chunk=500_000):
    from unicorn import UC_HOOK_CODE
    m, ev, st, pc, inq, at = build(snapshot)
    callers = collections.Counter()
    for a, name in SOFTFLOAT.items():
        def make(name):
            def h(uc, ad, s, d):
                sp = uc.reg_read(UC_M68K_REG_A7)
                callers[(name, struct.unpack('>I', uc.mem_read(sp, 4))[0])] += 1
            return h
        at(a, make(name))

    region = collections.Counter()
    m.uc.hook_add(UC_HOOK_CODE, lambda uc, ad, s, d: region.update([ad]),
                  begin=DRAW_LO, end=DRAW_HI)

    pc, done, stop = spin(m, pc, instrs, chunk)
    print('\n=== draw-task probe: %d instrs, stop=%s ===' % (done, stop))
    print('\nsoft-float callers:')
    for (name, ret), c in callers.most_common(20):
        print('  %-9s <- 0x%08x  %d' % (name, ret, c))
    print('\ncoverage inside 0x%08x-0x%08x: %d distinct addrs, %d executions'
          % (DRAW_LO, DRAW_HI, len(region), sum(region.values())))
    for a, c in region.most_common(25):
        print('  0x%08x  %d' % (a, c))





# --- follow-up 2: run past one full particle pass ---------------------------
# The generator is a 64x64 nested loop (inner `cmpi.l #$80,d3`, outer 64) that
# writes 4,096 (x,y) pairs, ~18.5k instructions each -> ~76M instructions for a
# complete pass, ending at the `rts` at 0x400d39ea. Run past that and watch for
# the stages downstream of it.
GEN_RTS   = 0x400d39ea      # particle generator returns here
SHIFT_LOOP = 0x400d3628     # the >>2 loop, 8bpp -> 8bpp
PX8_A, PX8_B = 0x43139290, 0x43137290
PARTICLES = 0x44f52000


def frame(snapshot, instrs, chunk=500_000):
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    m, ev, st, pc, inq, at = build(snapshot)
    hits = collections.Counter()
    for name, addr in (('gen_rts', GEN_RTS), ('shift_loop', SHIFT_LOOP)):
        at(addr, (lambda n: lambda uc, a, s, d: hits.update([n]))(name))

    writes = collections.Counter()
    for name, lo in (('px8_a', PX8_A), ('px8_b', PX8_B)):
        m.uc.hook_add(UC_HOOK_MEM_WRITE,
                      (lambda n: lambda uc, t, a, s, v, d: writes.update([n]))(name),
                      begin=lo, end=lo + 8192 - 1)

    t0 = time.time()
    def note(p, n):
        if n % 25_000_000 == 0:
            print('  .. %dM  %.0fs  gen_rts=%d shift=%d setPixel=%d pxcopy=%d '
                  'px8_a writes=%d' % (n // 1_000_000, time.time() - t0,
                  hits['gen_rts'], hits['shift_loop'], ev['setpixel'],
                  ev['pxcopy'], writes['px8_a']), flush=True)

    pc, done, stop = spin(m, pc, instrs, chunk, on_chunk=note)
    print('\n=== frame probe: %d instrs in %.0fs, stop=%s ===' % (done, time.time()-t0, stop))
    print('generator returns (0x%08x) : %d' % (GEN_RTS, hits['gen_rts']))
    print('shift loop  (0x%08x)       : %d' % (SHIFT_LOOP, hits['shift_loop']))
    print('setPixel %d   px_copy_to_bitmap %d' % (ev['setpixel'], ev['pxcopy']))
    print('8bpp writes: a=%d b=%d' % (writes['px8_a'], writes['px8_b']))
    for name, lo in (('particles', PARTICLES), ('px8_a', PX8_A), ('px8_b', PX8_B)):
        blob = bytes(m.uc.mem_read(lo, 8192))
        print('%-10s @0x%08x nonzero %d/8192' % (name, lo, sum(1 for b in blob if b)))
    print('prints: %r' % ev['prints'][:20])


if __name__ == '__main__':
    snap = sys.argv[1] if len(sys.argv) > 1 else 'snapshots/boot280M.snap'
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 20_000_000
    ch = int(sys.argv[3]) if len(sys.argv) > 3 else 20_000
    mode = os.environ.get("MODE", "")
    {"draw": lambda: draw(snap, n), "frame": lambda: frame(snap, n)}.get(
        mode, lambda: main(snap, n, ch))()
