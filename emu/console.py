"""Talk to the emulated firmware over its serial console.

MAIN OS carries a command protocol -- strings like `#HELLO` / `HOW DO YOU DO?`,
`#BREAK`, `#UPGRADE`, `#WRITE`, `#DUMP_AUDIO`, `#ENTER_TEST_MODE`, `READY FOR OS`
-- spoken over UART8 (identified from NXP MCF54418RM, Table 1-4 / ch. 41):

    0xEC070004  USR8   status; bit 0 = RXRDY, bit 2 = TXRDY
    0xEC07000C  URB8/UTB8  data register (read = receive, write = transmit)

Instead of pinning USR8 to a constant, model it: RXRDY reflects whether we have
queued input, TXRDY is always ready, and reads of the data register pop a byte.
Writes to it are captured as firmware output.
"""
import struct, sys, os, time, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn import UcError, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_SR, UC_M68K_REG_A7, UC_M68K_REG_D0
import emu.dspboot as db
from emu.harness import Machine
from emu.snapshot import restore_into
from emu import config

USR8 = 0xEC070004
UDR8 = 0xEC07000C
RXRDY, TXRDY = 0x01, 0x04


class Console:
    def __init__(self, snapshot, send=b''):
        self.out = bytearray()
        self.inq = collections.deque(send)
        self.flash = db.build_flash(config.firmware())
        self.m = Machine()
        self.st = {'seen': set(), 'n': 0, 'task_create_hits': {}}
        m = self.m
        self._install()
        self.pc = restore_into(m, snapshot, self.st)

    def _install(self):
        m = self.m

        def flash_read(uc, a, s, d):
            sp = uc.reg_read(UC_M68K_REG_A7)
            ret, off, ln, dest = struct.unpack('>IIII', uc.mem_read(sp, 16))
            if ln and dest and off + ln <= len(self.flash):
                for p in range(0, ln + 0x100000, 0x100000):
                    m.ensure(dest + p)
                uc.mem_write(dest, self.flash[off:off + ln])
            uc.reg_write(UC_M68K_REG_D0, 0)
            uc.reg_write(UC_M68K_REG_A7, sp + 4)
            uc.reg_write(UC_M68K_REG_PC, ret)

        def pend(uc, a, s, d):
            uc.mem_write(db.COMPLETION_SEM, struct.pack('>I', 1))

        m.install_isa_patches()
        m.uc.hook_add(UC_HOOK_CODE, flash_read, begin=db.FLASH_READ, end=db.FLASH_READ)
        m.uc.hook_add(UC_HOOK_CODE, pend, begin=db.PEND_CALL, end=db.PEND_CALL)

        def on_read(uc, typ, addr, size, val, data):
            if addr == USR8:
                s = TXRDY | (RXRDY if self.inq else 0)
                uc.mem_write(USR8, bytes([s]))
            elif addr == UDR8:
                uc.mem_write(UDR8, bytes([self.inq.popleft() if self.inq else 0]))

        def on_write(uc, typ, addr, size, val, data):
            if addr == UDR8:
                self.out.append(val & 0xFF)

        m.uc.hook_add(UC_HOOK_MEM_READ, on_read, begin=USR8, end=UDR8 + 3)
        m.uc.hook_add(UC_HOOK_MEM_WRITE, on_write, begin=USR8, end=UDR8 + 3)
        m.mmio[0xFC05C02C] = 0x100000F0
        m.mmio[0xEC03802C] = 0x80000000
        m.install_mmio()
        m.install_exceptions()

    def run(self, instrs, chunk=200_000):
        done, t0, stop = 0, time.time(), 'limit'
        pc = self.pc
        while done < instrs:
            try:
                self.m.uc.emu_start(pc, 0, count=min(chunk, instrs - done))
            except UcError as e:
                stop = str(e); break
            pc = self.m.uc.reg_read(UC_M68K_REG_PC)
            done += chunk
            if (self.m.uc.reg_read(UC_M68K_REG_SR) & 0x0700) != 0x0700:
                self.m.raise_vector(32)
                pc = self.m.uc.reg_read(UC_M68K_REG_PC)
        self.pc = pc
        return done, time.time() - t0, stop


if __name__ == '__main__':
    snap = sys.argv[1] if len(sys.argv) > 1 else 'snapshots/boot280M.snap'
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 40_000_000
    send = (sys.argv[3] + '\r\n').encode() if len(sys.argv) > 3 else b''
    c = Console(snap, send=send)
    done, dt, stop = c.run(n)
    print('ran %d instrs in %.1fs (%.2fM/s), stop=%s' % (done, dt, done / dt / 1e6, stop))
    print('firmware serial output: %d bytes' % len(c.out))
    if c.out:
        print('---')
        print(c.out.decode('latin1'))
        print('---')
        print('hex:', c.out[:200].hex())
