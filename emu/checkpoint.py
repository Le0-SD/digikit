"""Create a boot snapshot, and resume from one.

  make:   ./venv/bin/python -m emu.checkpoint make 45000000 snapshots/boot.snap
  resume: ./venv/bin/python -m emu.checkpoint resume snapshots/boot.snap 5000000
"""
import struct, sys, os, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn import UcError
from unicorn.m68k_const import UC_M68K_REG_PC
import emu.dspboot as db
from emu.snapshot import save, restore

IMG = 'sections/section_3_MAIN_OS.bin'
SYX = 'Digitakt_II_OS1.15C.syx'


def make(points, prefix='snapshots/boot'):
    """Save a LADDER of checkpoints in one pass.

    `points` is a list of instruction counts. Saving mid-run is safe because
    save() only reads state; emulation continues afterwards. One slow pass
    yields several resume points, so later blocker work can start deep.
    """
    img = open(IMG, 'rb').read()
    points = sorted(points)
    todo = list(points)
    box = {'m': None, 'saved': []}

    def hook(uc, addr, size, st):
        if todo and st['n'] >= todo[0]:
            at = todo.pop(0)
            path = '%s%dM.snap' % (prefix, at // 1_000_000)
            info = save(box['m'], path,
                        extra={'n': st['n'], 'seen': sorted(st['seen']),
                               'tasks': {hex(k): v for k, v in st['task_create_hits'].items()}})
            box['saved'].append((at, path, info, len(st['seen']),
                                 len(st['task_create_hits']),
                                 uc.reg_read(UC_M68K_REG_PC)))
            print('  [%dM] %s  %d addrs, %d tasks, pc=0x%08x, %d B'
                  % (at // 1_000_000, path, len(st['seen']),
                     len(st['task_create_hits']), uc.reg_read(UC_M68K_REG_PC),
                     info['bytes_on_disk']), flush=True)

    m, st, stop = db.run(SYX, img, limit=points[-1] + 1_000_000,
                         extra_hook=hook, fast=True, verbose=False,
                         machine_out=box)
    return box['saved']


def resume(path, extra_instrs, hook=None):
    """Restore and run forward. Returns (machine, new_addrs, stop_reason)."""
    m, extra, regs = restore(path)
    seen = set(extra['seen'])
    fresh = set()
    n = [0]

    def code(uc, addr, size):
        n[0] += 1
        if addr not in seen:
            seen.add(addr); fresh.add(addr)
        if hook:
            hook(uc, addr, size, n[0])

    m.install_isa_patches(extra_code_hook=code)
    m.install_mmio()
    m.install_exceptions()
    try:
        m.uc.emu_start(regs['pc'], 0, count=extra_instrs)
        stop = 'limit'
    except UcError as e:
        stop = str(e)
    return m, fresh, stop, n[0]


if __name__ == '__main__':
    if sys.argv[1] == 'make':
        make([int(x) for x in sys.argv[2].split(',')])
    else:
        path = sys.argv[2]
        extra = int(sys.argv[3]) if len(sys.argv) > 3 else 2_000_000
        import time
        t0 = time.time()
        m, fresh, stop, n = resume(path, extra)
        print('resumed: ran %d instrs in %.1fs, %d NEW addrs, stop=%s pc=0x%08x'
              % (n, time.time() - t0, len(fresh), stop, m.uc.reg_read(UC_M68K_REG_PC)))
