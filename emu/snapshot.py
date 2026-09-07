"""Save and restore a whole emulated machine.

Chasing a boot blocker meant re-running from the entry point every time --
replaying ~32M instructions of identical setup (a memory-clear loop alone is
~8M) before reaching anything new. That made each experiment 10-20 minutes.

A snapshot removes that: run once to a checkpoint, dump registers and memory,
then restore and iterate forward from there in seconds.

Snapshots are firmware-derived state, so they are gitignored like everything
else derived from the .syx.
"""
import struct, zlib, pickle, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn.m68k_const import (UC_M68K_REG_D0, UC_M68K_REG_A0, UC_M68K_REG_A7,
                                UC_M68K_REG_PC, UC_M68K_REG_SR)
from emu.harness import Machine, PAGE

REGS = ([('d%d' % i, UC_M68K_REG_D0 + i) for i in range(8)] +
        [('a%d' % i, UC_M68K_REG_A0 + i) for i in range(8)] +
        [('pc', UC_M68K_REG_PC), ('sr', UC_M68K_REG_SR)])


def save(machine, path, extra=None):
    """Dump registers + every non-zero mapped page. Zero pages are skipped;
    most of the 128MB SDRAM is zeros, so this stays small."""
    pages = {}
    for base in sorted(machine.mapped):
        data = bytes(machine.uc.mem_read(base, PAGE))
        if data.strip(b'\x00'):
            pages[base] = zlib.compress(data, 6)
    blob = {
        'regs': {name: machine.uc.reg_read(rid) for name, rid in REGS},
        'pages': pages,
        'all_mapped': sorted(machine.mapped),
        'mmio': dict(machine.mmio),
        'ctlregs': dict(machine.ctlregs),
        'ff1_count': machine.ff1_count,
        'movec_count': machine.movec_count,
        'extra': extra or {},
    }
    with open(path, 'wb') as f:
        pickle.dump(blob, f, protocol=4)
    raw = sum(len(zlib.decompress(v)) for v in pages.values())
    return {'pages': len(pages), 'mapped': len(blob['all_mapped']),
            'bytes_on_disk': os.path.getsize(path), 'bytes_live': raw}


def restore(path):
    """-> (Machine, extra). Hooks are NOT installed; the caller installs the
    same ones it would use for a fresh run, then calls uc.emu_start(regs['pc'])."""
    with open(path, 'rb') as f:
        blob = pickle.load(f)
    m = Machine()
    for base in blob['all_mapped']:
        m.ensure(base)
    for base, comp in blob['pages'].items():
        m.uc.mem_write(base, zlib.decompress(comp))
    m.mmio.update(blob['mmio'])
    m.ctlregs.update(blob['ctlregs'])
    m.ff1_count = blob['ff1_count']
    m.movec_count = blob['movec_count']
    # SR before A7 -- m68k banks SSP/USP (see harness.call)
    m.uc.reg_write(UC_M68K_REG_SR, blob['regs']['sr'])
    for name, rid in REGS:
        if name == 'sr':
            continue
        m.uc.reg_write(rid, blob['regs'][name])
    return m, blob['extra'], blob['regs']


def restore_into(machine, path, st=None):
    """Load a snapshot onto an ALREADY-configured Machine (hooks installed).

    This is the correct way to resume: dspboot.run installs its behaviour hooks
    (flash HLE, semaphore patch, scheduler tick, task tracking) and only then
    calls this. Restoring onto a bare Machine instead silently drops those and
    the run diverges -- which it did, by ~50 addresses over 5M instructions.

    Returns the PC to start at, and seeds `st` with the carried coverage so
    the resumed run reports totals rather than only what is new.
    """
    with open(path, 'rb') as f:
        blob = pickle.load(f)
    for base in blob['all_mapped']:
        machine.ensure(base)
    for base, comp in blob['pages'].items():
        machine.uc.mem_write(base, zlib.decompress(comp))
    machine.mmio.update(blob['mmio'])
    machine.ctlregs.update(blob['ctlregs'])
    machine.ff1_count = blob['ff1_count']
    machine.movec_count = blob['movec_count']
    machine.uc.reg_write(UC_M68K_REG_SR, blob['regs']['sr'])   # SR before A7
    for name, rid in REGS:
        if name != 'sr':
            machine.uc.reg_write(rid, blob['regs'][name])
    if st is not None:
        st['seen'].update(blob['extra'].get('seen', []))
        st['n'] = blob['extra'].get('n', 0)
        for k, v in blob['extra'].get('tasks', {}).items():
            st['task_create_hits'].setdefault(int(k, 16), v)
    return blob['regs']['pc']
