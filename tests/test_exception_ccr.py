# pyright: reportMissingImports=false
"""Timer-boundary exception entry must preserve the interrupted CCR."""

import struct
import unittest

from unicorn import UC_HOOK_CODE
from unicorn.m68k_const import (
    UC_M68K_REG_A0,
    UC_M68K_REG_A2,
    UC_M68K_REG_A3,
    UC_M68K_REG_A7,
    UC_M68K_REG_D0,
    UC_M68K_REG_D2,
    UC_M68K_REG_D4,
    UC_M68K_REG_PC,
    UC_M68K_REG_SR,
)

from emu.harness import VBR, Machine


class ExceptionCcrTest(unittest.TestCase):
    def _branch_after_timer_boundary(self, srtrap, equal):
        """Run CMP to a deadline, then inject before the separately-run BEQ."""
        machine = Machine()
        uc = machine.uc
        machine.install_exceptions()
        if srtrap:
            machine.install_srtrap()

        code, handler = 0x40001000, 0x40001100
        # cmp.l a2,d4; beq taken; moveq #1,d0; bra done; moveq #2,d0; nop
        machine.load(bytes.fromhex("b88a67047001600270024e71"), code)
        machine.load(bytes.fromhex("4e73"), handler)
        machine.ensure(0x20000000)
        uc.mem_write(VBR + 64 * 4, struct.pack(">I", handler))
        uc.reg_write(UC_M68K_REG_SR, 0x2004)  # deliberately stale seeded Z
        uc.reg_write(UC_M68K_REG_A7, 0x20001000)
        uc.reg_write(UC_M68K_REG_A2, 0x12345678)
        uc.reg_write(UC_M68K_REG_D4, 0x12345678 if equal else 0x12345679)

        # Pits.service injects only after this emu_start call returns, rather
        # than from a UC_HOOK_CODE callback inside the CMP/BEQ translation.
        uc.emu_start(code, 0, count=1)
        self.assertEqual(uc.reg_read(UC_M68K_REG_PC), code + 2)
        self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0x1F, 4 if equal else 0)
        self.assertTrue(machine.raise_vector(64, level=3))

        frame = []

        def observe(uc_, address, size, data):
            if address == handler:
                sp = uc_.reg_read(UC_M68K_REG_A7)
                frame.append(bytes(uc_.mem_read(sp, 8)))
            elif address == code + 10:
                uc_.emu_stop()

        uc.hook_add(UC_HOOK_CODE, observe, begin=code + 10, end=handler)
        uc.emu_start(uc.reg_read(UC_M68K_REG_PC), 0, count=20)
        self.assertEqual(uc.reg_read(UC_M68K_REG_PC), code + 10)
        self.assertEqual(len(frame), 1)
        fmt, saved_sr, saved_pc = struct.unpack(">HHI", frame[0])
        self.assertEqual(fmt, 0x4100)
        self.assertEqual(saved_pc, code + 2)
        return uc.reg_read(UC_M68K_REG_D0), saved_sr

    def test_timer_boundary_preserves_compare_flags_across_exception_and_rte(self):
        for srtrap in (False, True):
            self.assertEqual(
                self._branch_after_timer_boundary(srtrap, True), (2, 0x2004)
            )
            self.assertEqual(
                self._branch_after_timer_boundary(srtrap, False), (1, 0x2000)
            )

    def test_cmp_count_boundary_syncs_when_started_at_cmp_or_preceding_block(self):
        # The real site is preceded by these three instructions.  Check both
        # direct entry and a count boundary that lands immediately before BEQ.
        cmp_code = bytes.fromhex("b88a672c")
        preceding = bytes.fromhex("282a0018588b2442") + cmp_code
        for code, start, count in (
            (cmp_code, 0x40002000, 1),
            (preceding, 0x40002100, 4),
        ):
            machine = Machine()
            uc = machine.uc
            machine.load(code, start)
            machine.ensure(0x20000000)
            uc.mem_write(0x20000018, struct.pack(">I", 0x44605678))
            uc.reg_write(UC_M68K_REG_SR, 0x2001)
            uc.reg_write(UC_M68K_REG_A2, 0x20000000)
            uc.reg_write(UC_M68K_REG_A3, 0)
            uc.reg_write(UC_M68K_REG_D2, 0x44605678)
            uc.reg_write(UC_M68K_REG_D4, 0x44605678)
            if code is cmp_code:
                uc.reg_write(UC_M68K_REG_A2, 0x44605678)
            uc.emu_start(start, 0, count=count)
            self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0x1F, 4)

    def test_context_movem_and_rte_restore_frame_ccr_before_cmp(self):
        machine = Machine()
        uc = machine.uc
        machine.install_exceptions()
        restore, cmp = 0x40003000, 0x40003100
        tcb, stack = 0x20000000, 0x20001000
        # movem.l $c(a0),d0-d7/a0-a7; rte: the RTOS restore tail.
        machine.load(bytes.fromhex("4ce8ffff000c4e73"), restore)
        machine.load(bytes.fromhex("b88a672c"), cmp)
        machine.ensure(tcb)
        machine.ensure(stack)
        regs = [0] * 16
        regs[0] = 0
        regs[4] = 0x44605678  # restored D4
        regs[8] = tcb
        regs[10] = 0x44605678  # restored A2
        regs[15] = stack
        uc.mem_write(tcb + 0x0C, struct.pack(">16I", *regs))
        uc.mem_write(stack, struct.pack(">HHI", 0x4334, 0x2004, cmp))
        uc.reg_write(UC_M68K_REG_SR, 0x2001)
        uc.reg_write(UC_M68K_REG_A0, tcb)
        uc.reg_write(UC_M68K_REG_D4, 0x44605678)
        uc.emu_start(restore, 0, count=2)
        self.assertEqual(uc.reg_read(UC_M68K_REG_PC), cmp)
        self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0x1F, 4)
        uc.emu_start(cmp, 0, count=1)
        self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0x1F, 4)


if __name__ == "__main__":
    unittest.main()
