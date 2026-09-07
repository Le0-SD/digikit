"""Unicorn m68k harness for running real Digitakt II ColdFire code.

Unicorn's m68k core has gaps that matter here. All are handled below:

  * FF1.L (0x04C0-0x04C7) is not implemented. Left alone, boot stalls at 444
    distinct code addresses; emulated, it reaches 36,474. Biggest single win.
  * MOVEC with Rc=0x009 does not fault -- it aborts the process (SIGABRT).
    It must be intercepted in the code hook, before Unicorn's decoder sees it.
  * m68k exceptions are never dispatched through the vector table.
  * `rte` is surfaced as intr number 0x100 (QEMU's EXCP_RTE) and must be
    implemented by hand.

See docs/FINDINGS.md for how each was found.
"""
import struct
from unicorn import (Uc, UcError, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN,
                     UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_INVALID,
                     UC_HOOK_MEM_READ)
from unicorn.m68k_const import (UC_CPU_M68K_CFV4E, UC_M68K_REG_A7,
                                UC_M68K_REG_PC, UC_M68K_REG_SR, UC_M68K_REG_D0)

PAGE = 0x100000
EXCP_RTE = 0x100
VBR = 0x40000000            # m68k vector table; MAIN OS loads at VBR+0x400


class Machine:
    """A ColdFire machine with memory mapped on demand."""

    def __init__(self, cpu=UC_CPU_M68K_CFV4E):
        self.uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        self.uc.ctl_set_cpu_model(cpu)
        self.mapped = set()
        self.mmio = {}          # addr -> int, forced on read
        self.ctlregs = {}       # MOVEC control registers
        self.ff1_count = 0
        self.movec_count = 0
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self._fault)

    # -- memory ------------------------------------------------------------
    def ensure(self, addr):
        base = addr & ~(PAGE - 1)
        if base in self.mapped:
            return
        try:
            self.uc.mem_map(base, PAGE)
            self.mapped.add(base)
        except UcError:
            pass

    def _fault(self, uc, typ, addr, size, val, data):
        self.ensure(addr)
        return True

    def install_mmio(self):
        """Force `self.mmio` values on read. Use for status registers whose
        ready bits the firmware polls (e.g. UART8 USR8, DSPI0 SR)."""
        def on_read(uc, typ, addr, size, val, data):
            for a, v in self.mmio.items():
                if a <= addr < a + 4:
                    try:
                        uc.mem_write(a, struct.pack('>I', v))
                    except UcError:
                        pass
        self.uc.hook_add(UC_HOOK_MEM_READ, on_read)

    def load(self, image, addr):
        for off in range(0, len(image), PAGE):
            self.ensure(addr + off)
        self.ensure(addr)
        self.uc.mem_write(addr, image)

    # -- ISA gaps ----------------------------------------------------------
    def install_isa_patches(self, extra_code_hook=None):
        """Emulate the ColdFire instructions Unicorn lacks."""
        def on_code(uc, addr, size, data):
            w = struct.unpack('>H', uc.mem_read(addr, 2))[0]
            if 0x04C0 <= w <= 0x04C7:                 # FF1.L Dn
                n = w & 7
                reg = UC_M68K_REG_D0 + n
                v = uc.reg_read(reg) & 0xFFFFFFFF
                # count leading zeros; FF1 of 0 is defined as 32
                out = 32 if v == 0 else 31 - v.bit_length() + 1
                uc.reg_write(reg, out)
                uc.reg_write(UC_M68K_REG_PC, addr + 2)
                self.ff1_count += 1
                return
            if w in (0x4E7A, 0x4E7B):                 # MOVEC -- crashes Unicorn
                ext = struct.unpack('>H', uc.mem_read(addr + 2, 2))[0]
                rc = ext & 0x0FFF
                reg = UC_M68K_REG_D0 + ((ext >> 12) & 7)   # data regs only
                if w == 0x4E7B:
                    self.ctlregs[rc] = uc.reg_read(reg)
                else:
                    uc.reg_write(reg, self.ctlregs.get(rc, 0))
                uc.reg_write(UC_M68K_REG_PC, addr + 4)
                self.movec_count += 1
                return
            if extra_code_hook:
                extra_code_hook(uc, addr, size)
        self.uc.hook_add(UC_HOOK_CODE, on_code)

    def install_exceptions(self, on_unhandled=None):
        """Dispatch exceptions via the vector table and implement `rte`."""
        def on_intr(uc, vec, data):
            if vec == EXCP_RTE:
                sp = uc.reg_read(UC_M68K_REG_A7)
                _fmt, sr, pc = struct.unpack('>HHI', uc.mem_read(sp, 8))
                uc.reg_write(UC_M68K_REG_SR, sr)
                uc.reg_write(UC_M68K_REG_PC, pc)
                uc.reg_write(UC_M68K_REG_A7, sp + 8)
                return
            if not self.raise_vector(vec):
                if on_unhandled:
                    on_unhandled(vec)
                uc.emu_stop()
        self.uc.hook_add(UC_HOOK_INTR, on_intr)

    def raise_vector(self, vec):
        """Push an exception frame and jump to the handler. -> bool taken."""
        handler = struct.unpack('>I', self.uc.mem_read(VBR + vec * 4, 4))[0]
        if handler == 0 or handler >= 0x48000000:
            return False
        pc = self.uc.reg_read(UC_M68K_REG_PC)
        sr = self.uc.reg_read(UC_M68K_REG_SR)
        sp = self.uc.reg_read(UC_M68K_REG_A7) - 8
        self.uc.mem_write(sp, struct.pack('>HHI', (vec << 2) & 0xFFFF, sr, pc))
        self.uc.reg_write(UC_M68K_REG_A7, sp)
        self.uc.reg_write(UC_M68K_REG_PC, handler)
        return True


def call(machine, func, args, ret_magic=0xDEADBEE0, stack_top=None, limit=800_000_000):
    """Call a firmware routine with C-style stacked args. -> D0."""
    uc = machine.uc
    if stack_top is None:
        machine.ensure(0x10000000)
        stack_top = 0x10000000 + PAGE - 0x100
    frame = struct.pack('>I', ret_magic) + b''.join(struct.pack('>I', a) for a in args)
    uc.mem_write(stack_top, frame)
    # SR before A7: m68k banks SSP/USP, so switching mode after setting the
    # stack pointer silently writes the register the CPU is about to stop using.
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, stack_top)
    uc.emu_start(func, ret_magic, count=limit)
    return uc.reg_read(UC_M68K_REG_D0) & 0xFFFFFFFF
