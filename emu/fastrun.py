"""Run the emulator at native speed.

The per-instruction Python hook used for coverage tracking caps throughput at
~300k instr/sec. Almost none of it is needed: the HLE side effects all live at
known addresses, and Unicorn hooks registered with begin==end are only invoked
there, costing nothing in between.

The one thing that seemed to need a global hook was the preemption tick, which
fired on an instruction count. It doesn't: `emu_start(pc, 0, count=N)` returns
after N instructions, so the tick can be driven by chunking instead -- run N
instructions natively, inject, resume.
"""
import struct, sys, os, time, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn import UcError, UC_HOOK_CODE
from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_SR, UC_M68K_REG_A7, UC_M68K_REG_D0
import emu.dspboot as db
from emu.harness import Machine
from emu.snapshot import restore_into

CHUNK = 200_000


def run(snapshot, instrs, watch=None, chunk=CHUNK):
    """watch: {addr: fn(uc)} -- per-address hooks, free between hits."""
    flash = db.build_flash('Digitakt_II_OS1.15C.syx')
    m = Machine()
    st = {'seen': set(), 'n': 0, 'task_create_hits': {}, 'stall_pcs': collections.Counter(),
          'reads': [], 'curve': [], 'spin': 0, 'transport_calls': [], 'sem_kicks': 0,
          'depack_clamps': 0, 'task_start_hits': {}, 'last_new_n': 0,
          'spin_by_addr': collections.Counter(), 'idle_spins_found': []}

    def flash_read(uc):
        sp = uc.reg_read(UC_M68K_REG_A7)
        ret, off, ln, dest = struct.unpack('>IIII', uc.mem_read(sp, 16))
        if ln and dest and off + ln <= len(flash):
            for p in range(0, ln + 0x100000, 0x100000):
                m.ensure(dest + p)
            uc.mem_write(dest, flash[off:off + ln])
        uc.reg_write(UC_M68K_REG_D0, 0)
        uc.reg_write(UC_M68K_REG_A7, sp + 4)
        uc.reg_write(UC_M68K_REG_PC, ret)

    def pend_patch(uc):
        uc.mem_write(db.COMPLETION_SEM, struct.pack('>I', 1))

    hooks = {db.FLASH_READ: flash_read, db.PEND_CALL: pend_patch}
    hooks.update(watch or {})

    m.install_isa_patches_scoped(open('sections/section_3_MAIN_OS.bin', 'rb').read(),
                                 db.MAIN_LOAD) \
        if hasattr(m, 'install_isa_patches_scoped') else m.install_isa_patches()
    for addr, fn in hooks.items():
        m.uc.hook_add(UC_HOOK_CODE, (lambda f: lambda uc, a, s, d: f(uc))(fn),
                      begin=addr, end=addr)
    m.mmio[0xEC070004] = 0x0D000000
    m.mmio[0xFC05C02C] = 0x100000F0
    m.mmio[0xEC03802C] = 0x80000000
    m.install_mmio()
    m.install_exceptions()
    pc = restore_into(m, snapshot, st)

    done = 0
    t0 = time.time()
    stop = 'limit'
    while done < instrs:
        n = min(chunk, instrs - done)
        try:
            m.uc.emu_start(pc, 0, count=n)
        except UcError as e:
            stop = str(e); break
        pc = m.uc.reg_read(UC_M68K_REG_PC)
        done += n
        if (m.uc.reg_read(UC_M68K_REG_SR) & 0x0700) != 0x0700:
            m.raise_vector(32)
            pc = m.uc.reg_read(UC_M68K_REG_PC)
    return m, done, time.time() - t0, stop


if __name__ == '__main__':
    snap = sys.argv[1] if len(sys.argv) > 1 else 'snapshots/boot280M.snap'
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 50_000_000
    m, done, dt, stop = run(snap, n)
    print('ran %d instrs in %.1fs = %.2fM instr/sec  (%s)' % (done, dt, done / dt / 1e6, stop))
