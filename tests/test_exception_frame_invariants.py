# pyright: reportMissingImports=false
"""ColdFire exception entry/exit invariants for `Machine.raise_vector`.

Isolated from tests/test_exception_ccr.py, which is about CCR preservation
across a timer-boundary injection specifically. This file checks the frame
shape and the handler's *live* SR on entry, independent of any timer.
"""

import struct
import unittest

from unicorn.m68k_const import (
    UC_M68K_REG_A7,
    UC_M68K_REG_PC,
    UC_M68K_REG_SR,
)

from emu.harness import VBR, Machine


class ExceptionFrameShapeTest(unittest.TestCase):
    """The pushed frame is exactly {format/vector, interrupted SR, PC}."""

    def _raise(self, vec, interrupted_sr, pc, handler_code=b"\x4e\x71", **kw):
        machine = Machine()
        uc = machine.uc
        code, handler = 0x40001000, 0x40001100
        machine.load(b"\x4e\x71", code)
        machine.load(handler_code, handler)
        machine.ensure(0x20000000)
        uc.mem_write(VBR + vec * 4, struct.pack(">I", handler))
        uc.reg_write(UC_M68K_REG_SR, interrupted_sr)
        uc.reg_write(UC_M68K_REG_A7, 0x20001000)
        uc.reg_write(UC_M68K_REG_PC, pc)
        taken = machine.raise_vector(vec, **kw)
        self.assertTrue(taken)
        return machine

    def test_asynchronous_frame_bytes_are_exactly_format_vector_sr_pc(self):
        machine = self._raise(96, 0x2704, 0x40002000, level=2)
        uc = machine.uc
        sp = uc.reg_read(UC_M68K_REG_A7)
        self.assertEqual(sp, 0x20001000 - 8)
        fmt, sr, pc = struct.unpack(">HHI", uc.mem_read(sp, 8))
        self.assertEqual(fmt, 0x4000 | ((96 << 2) & 0x0FFC))
        self.assertEqual(sr, 0x2704)  # interrupted SR, unmodified
        self.assertEqual(pc, 0x40002000)  # asynchronous: PC not advanced
        self.assertEqual(uc.reg_read(UC_M68K_REG_PC), 0x40001100)

    def test_frame_vector_field_is_correct_for_every_vector_number(self):
        for vec in (32, 64, 96, 155, 205, 255):
            machine = self._raise(vec, 0x2000, 0x40003000, level=3)
            sp = machine.uc.reg_read(UC_M68K_REG_A7)
            fmt = struct.unpack(">H", machine.uc.mem_read(sp, 2))[0]
            self.assertEqual((fmt >> 2) & 0x3FF, vec)
            self.assertEqual(fmt & 0xF000, 0x4000)

    def test_synchronous_trap_frame_pc_is_advanced_past_the_trap(self):
        trap = 0x40002000
        machine = Machine()
        uc = machine.uc
        handler = 0x40001100
        machine.load(b"\x4e\x40", trap)  # trap #0, 2 bytes
        machine.load(b"\x4e\x71", handler)
        machine.ensure(0x20000000)
        uc.mem_write(VBR + 32 * 4, struct.pack(">I", handler))
        uc.reg_write(UC_M68K_REG_SR, 0x2704)
        uc.reg_write(UC_M68K_REG_A7, 0x20001000)
        uc.reg_write(UC_M68K_REG_PC, trap)
        self.assertTrue(machine.raise_vector(32, from_instruction=True, level=None))
        sp = uc.reg_read(UC_M68K_REG_A7)
        fmt, sr, pc = struct.unpack(">HHI", uc.mem_read(sp, 8))
        self.assertEqual(pc, trap + 2)
        self.assertEqual(sr, 0x2704)  # interrupted SR still unmodified


class HandlerLiveSrTest(unittest.TestCase):
    """The CPU's live SR while the handler runs, not the frame's copy."""

    def _raise(self, interrupted_sr, **kw):
        machine = Machine()
        uc = machine.uc
        code, handler = 0x40001000, 0x40001100
        machine.load(b"\x4e\x71", code)
        machine.load(b"\x4e\x71", handler)
        machine.ensure(0x20000000)
        uc.mem_write(VBR + 96 * 4, struct.pack(">I", handler))
        uc.reg_write(UC_M68K_REG_SR, interrupted_sr)
        uc.reg_write(UC_M68K_REG_A7, 0x20001000)
        uc.reg_write(UC_M68K_REG_PC, code)
        self.assertTrue(machine.raise_vector(96, **kw))
        return uc.reg_read(UC_M68K_REG_SR)

    def test_asynchronous_interrupt_sets_supervisor_and_raises_ipl(self):
        # Interrupted from user mode (S=0), IPL 0, Z set.
        live = self._raise(0x0004, level=5)
        self.assertTrue(live & 0x2000, "S bit must be set for the handler")
        self.assertEqual((live >> 8) & 7, 5, "IPL must be raised to the level")
        self.assertEqual(live & 0x1F, 0x04, "CCR must survive unmodified")

    def test_asynchronous_interrupt_from_supervisor_still_raises_ipl(self):
        live = self._raise(0x2100, level=6)  # already supervisor, IPL 1
        self.assertTrue(live & 0x2000)
        self.assertEqual((live >> 8) & 7, 6)

    def test_synchronous_trap_sets_supervisor_but_leaves_ipl_alone(self):
        live = self._raise(0x0500, from_instruction=True, level=None)
        self.assertTrue(live & 0x2000, "S bit must be set even for a trap")
        self.assertEqual((live >> 8) & 7, 5, "IPL must be UNCHANGED for trap #N")

    def test_ipl_zero_is_a_real_level_not_left_alone(self):
        live = self._raise(0x2500, level=0)
        self.assertTrue(live & 0x2000)
        self.assertEqual((live >> 8) & 7, 0)


class RteRestoresOriginalContextTest(unittest.TestCase):
    """`rte` must restore exactly the frame's SR, PC and A7 -- see
    Machine.install_exceptions's EXCP_RTE branch."""

    def test_rte_restores_sr_pc_and_pops_the_frame(self):
        machine = Machine()
        machine.install_exceptions()
        uc = machine.uc
        code, handler = 0x40001000, 0x40001100
        machine.load(b"\x4e\x71", code)  # nop, the interrupted insn
        machine.load(b"\x4e\x73", handler)  # rte
        machine.ensure(0x20000000)
        uc.mem_write(VBR + 96 * 4, struct.pack(">I", handler))
        uc.reg_write(UC_M68K_REG_SR, 0x0704)  # user, IPL 7, Z set
        uc.reg_write(UC_M68K_REG_A7, 0x20001000)
        uc.reg_write(UC_M68K_REG_PC, code)
        self.assertTrue(machine.raise_vector(96, level=3))
        pushed_sp = uc.reg_read(UC_M68K_REG_A7)
        self.assertEqual(pushed_sp, 0x20001000 - 8)

        uc.emu_start(uc.reg_read(UC_M68K_REG_PC), 0, count=1)  # runs `rte`

        self.assertEqual(uc.reg_read(UC_M68K_REG_PC), code)
        self.assertEqual(uc.reg_read(UC_M68K_REG_SR) & 0xFFFF, 0x0704)
        self.assertEqual(uc.reg_read(UC_M68K_REG_A7), 0x20001000)


if __name__ == "__main__":
    unittest.main()
