"""Boot MAIN OS with a flash-backed SPI NOR model.

The stall the earlier boot experiments hit was NOT a missing hardware model.
`0x401296fe` is the SPI NOR read routine -- signature `read(offset, len, dest)`,
confirmed by `0x84020003 -> DSPI0_PUSHR` (low byte 0x03 = NOR READ command).
Its callers scan the ELE3 section table at flash offset 0x80020.

That flash content is the staged OS container, which we already have: it is
exactly what `dt2.container` decodes out of the .syx. So instead of emulating
DSPI transactions, high-level-emulate the read and serve real bytes.
"""
import struct, sys, os, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn import UcError, UC_HOOK_CODE
from unicorn.m68k_const import (UC_M68K_REG_A7, UC_M68K_REG_PC, UC_M68K_REG_SR,
                                UC_M68K_REG_D0)
from emu.harness import Machine, VBR
from dt2.container import container

MAIN_LOAD, ENTRY = 0x40000400, 0x400004e8
FLASH_READ = 0x401296fe
SLOT       = 0x80000          # staged ELE3 container lives here
HALT       = 0x400ceeb6


def build_flash(syx_path, size=0x1000000):
    """Sparse flash image with the ELE3 container at the staged slot."""
    flash = bytearray(size)
    c = container(syx_path)
    flash[SLOT:SLOT + len(c)] = c
    return bytes(flash)


def run(syx_path, main_img, limit=120_000_000, tick_vec=32, tick_every=20000):
    flash = build_flash(syx_path)
    m = Machine()
    st = {'n': 0, 'seen': set(), 'reads': [], 'spin': 0, 'curve': []}

    def extra(uc, addr, size):
        st['n'] += 1
        st['seen'].add(addr)
        if st['n'] % 10_000_000 == 0:
            st['curve'].append((st['n'] // 1_000_000, len(st['seen'])))
        if addr == FLASH_READ:                       # HLE the SPI NOR read
            sp = uc.reg_read(UC_M68K_REG_A7)
            ret, off, ln, dest = struct.unpack('>IIII', uc.mem_read(sp, 16))
            if ln and dest and off + ln <= len(flash):
                for p in range(0, ln + 0x100000, 0x100000):
                    m.ensure(dest + p)
                uc.mem_write(dest, flash[off:off + ln])
                st['reads'].append((off, ln, dest))
            uc.reg_write(UC_M68K_REG_D0, 0)
            uc.reg_write(UC_M68K_REG_A7, sp + 4)     # caller pops the args
            uc.reg_write(UC_M68K_REG_PC, ret)
            return
        if addr == HALT:
            st['spin'] += 1
            if st['spin'] % tick_every == 0:
                m.raise_vector(tick_vec)

    # Status registers the firmware polls before it ever reaches the flash.
    m.mmio[0xEC070004] = 0x0D000000   # UART8 USR8: RXRDY|TXRDY|TXEMP
    m.mmio[0xFC05C02C] = 0x000000F0   # DSPI0 SR: RXCTR non-zero
    m.install_isa_patches(extra_code_hook=extra)
    m.install_mmio()
    m.install_exceptions()
    m.load(main_img, MAIN_LOAD)
    m.ensure(0x40800000)
    m.uc.reg_write(UC_M68K_REG_SR, 0x2700)
    m.uc.reg_write(UC_M68K_REG_A7, 0x40800000)
    try:
        m.uc.emu_start(ENTRY, 0, count=limit)
        stop = 'instruction limit'
    except UcError as e:
        stop = str(e)
    return m, st, stop


if __name__ == '__main__':
    syx = sys.argv[1] if len(sys.argv) > 1 else 'Digitakt_II_OS1.15C.syx'
    img = open('sections/section_3_MAIN_OS.bin', 'rb').read()
    m, st, stop = run(syx, img)
    print('instructions      : %d' % st['n'])
    print('distinct addrs    : %d' % len(st['seen']))
    print('stopped           : %s (pc=0x%08x)' % (stop, m.uc.reg_read(UC_M68K_REG_PC)))
    print('FF1 emulated      : %d   MOVEC emulated: %d' % (m.ff1_count, m.movec_count))
    print('flash reads served: %d' % len(st['reads']))
    for off, ln, dest in st['reads'][:12]:
        print('    off=0x%06x len=%-7d -> 0x%08x' % (off, ln, dest))
    print('curve:', '  '.join('%dM:%d' % c for c in st['curve']))
