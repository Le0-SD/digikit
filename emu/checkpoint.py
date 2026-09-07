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


def make(at, path):
    img = open(IMG, 'rb').read()
    box = {}

    def hook(uc, addr, size, st):
        if st['n'] >= at and 'done' not in box:
            box['done'] = True
            uc.emu_stop()

    m, st, stop = db.run(SYX, img, limit=at + 5_000_000,
                         extra_hook=hook, fast=True, verbose=False)
    info = save(m, path, extra={'n': st['n'], 'seen': sorted(st['seen']),
                                'tasks': {hex(k): v for k, v in st['task_create_hits'].items()}})
    print('snapshot at instr %d, pc=0x%08x' % (st['n'], m.uc.reg_read(UC_M68K_REG_PC)))
    print('  %(pages)d non-zero pages of %(mapped)d mapped; %(bytes_live)d B live '
          '-> %(bytes_on_disk)d B on disk' % info)
    print('  coverage carried: %d distinct addrs, %d tasks'
          % (len(st['seen']), len(st['task_create_hits'])))
    return m, st


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
        make(int(sys.argv[2]), sys.argv[3])
    else:
        path = sys.argv[2]
        extra = int(sys.argv[3]) if len(sys.argv) > 3 else 2_000_000
        import time
        t0 = time.time()
        m, fresh, stop, n = resume(path, extra)
        print('resumed: ran %d instrs in %.1fs, %d NEW addrs, stop=%s pc=0x%08x'
              % (n, time.time() - t0, len(fresh), stop, m.uc.reg_read(UC_M68K_REG_PC)))
