"""Name the remaining blockers: log every blocking wait and who made it.

Tasks stop by calling the semaphore/event wait primitive at 0x4000141a. The
return address on the stack at that moment identifies the exact site each task
blocks at -- which is the list of what still has to be satisfied.
"""
import struct, sys, os, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn.m68k_const import UC_M68K_REG_A7
import emu.dspboot as db

# Two counting-semaphore pend primitives, both with a fast path when count > 0:
PENDS = {0x4000141a: 'pend_A', 0x400013a6: 'pend_B'}

pend = collections.Counter()      # (ret_addr, sem_obj) -> count
first = {}                        # (ret_addr, sem_obj) -> instruction number


def watch(uc, addr, size, st):
    if addr not in PENDS:
        return
    sp = uc.reg_read(UC_M68K_REG_A7)
    ret, obj = struct.unpack('>II', uc.mem_read(sp, 8))
    count = struct.unpack('>I', uc.mem_read(obj, 4))[0] if obj else 0
    key = (PENDS[addr], ret, obj)
    pend[key] += 1
    first.setdefault(key, (st['n'], count))


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000_000
    img = open('sections/section_3_MAIN_OS.bin', 'rb').read()
    m, st, stop = db.run('Digitakt_II_OS1.15C.syx', img, limit=limit,
                         extra_hook=watch, fast=False)
    print('instructions %d   distinct %d   tasks %d/16'
          % (st['n'], len(st['seen']), len(st['task_create_hits'])))
    print('\nblocking waits (sem_pend call sites) -- these ARE the remaining blockers:')
    print('%-8s %-12s %-12s %-8s %-12s %s'
          % ('prim', 'caller', 'sem object', 'hits', 'first@instr', 'sem count then'))
    for key, c in sorted(pend.items(), key=lambda kv: kv[1]):
        prim, ret, obj = key
        n, cnt = first[key]
        print('  %-6s 0x%08x  0x%08x  %-7d %-12d %d' % (prim, ret, obj, c, n, cnt))


if __name__ == '__main__':
    main()
