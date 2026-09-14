"""TaskProfile accounting with a stub Unicorn (no emulator needed)."""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn.m68k_const import UC_M68K_REG_A7

from emu import taskprof

SWITCH = 0x4000044a
CURRENT = 0x47d9adb4
STACK = 0x1000


class StubUc:
    """RAM at 0..0x2000 holds the stack; the current-TCB variable is kept
    apart."""

    def __init__(self):
        self.ram = bytearray(0x2000)
        self.current = 0
        self.a0 = 0

    def mem_read(self, addr, n):
        if addr == CURRENT and n == 4:
            return self.current.to_bytes(4, 'big')
        if 0 <= addr and addr + n <= len(self.ram):
            return bytes(self.ram[addr:addr + n])
        raise ValueError('unmapped read at 0x%x' % addr)

    def reg_read(self, reg):
        return STACK if reg == UC_M68K_REG_A7 else self.a0

    def put(self, addr, *longs):
        struct.pack_into('>%dI' % len(longs), self.ram, addr, *longs)


class StubProfile:
    ctx_switch_load = SWITCH
    current_tcb = CURRENT


class StubMachine:
    def __init__(self, uc):
        self.uc = uc


class TaskProfileTest(unittest.TestCase):
    def setUp(self):
        self.uc = StubUc()
        self.hooks = {}
        self.now = 0
        self.prof = taskprof.TaskProfile(
            StubMachine(self.uc), self.hooks.__setitem__, StubProfile(),
            lambda: self.now, [(0x40032f5a, 5, 0x100)], spins={'n': 7})

    def switch(self, at, outgoing, incoming, pc=0x40001234):
        self.now = at
        self.uc.current = outgoing
        self.uc.put(STACK + 4, pc)
        self.uc.a0 = incoming
        self.hooks[SWITCH](self.uc, SWITCH, 6, None)

    def test_charges_outgoing_task(self):
        self.switch(100, 0x100, 0x200, pc=0x40000001)   # nothing charged
        self.switch(400, 0x200, 0x100, pc=0x40000002)   # 300 to 0x200
        self.switch(1000, 0x100, 0x200, pc=0x40000001)  # 600 to 0x100
        lines = self.prof.summary(1100)  # 100 more to the running 0x200
        self.assertEqual(lines[0].split(), [
            '[tasks]', 'window', 'charged=1000', 'switches=3',
            'mismatches=0', 'errors=0', 'idle-spins=0'])
        self.assertEqual(lines[1].split(), [
            '[tasks]', '60.0%', '600', 'in=1', 'entry=0x40032f5a', 'prio=5',
            'tcb=0x00000100'])
        self.assertEqual(lines[2].split(), ['[tasks]', 'pcs', '0x40000001*2'])
        self.assertEqual(lines[3].split(), [
            '[tasks]', '40.0%', '400', 'in=2', 'tcb=0x00000200'])
        self.assertEqual(lines[4].split(), ['[tasks]', 'pcs', '0x40000002*1'])
        self.assertEqual(lines[5].split(), [
            '[tasks]', 'last-out', 'entry=0x40032f5a', 'prio=5',
            'tcb=0x00000100', 'at', '1000', 'pc=0x40000001', 'via', '-'])
        self.assertEqual(len(lines), 6)   # 0x200 is running: no last-out
        self.assertEqual(self.prof.errors, 0)

    def test_counts_missed_switch(self):
        self.switch(100, 0x100, 0x200)
        self.switch(200, 0x300, 0x100)   # 0x200 went in, 0x300 comes out
        self.assertEqual(self.prof.mismatches, 1)

    def test_window_resets(self):
        self.switch(100, 0x100, 0x200)
        self.prof.summary(500)
        lines = self.prof.summary(700)
        self.assertEqual(lines[1].split()[:3], ['[tasks]', '100.0%', '200'])
        self.assertEqual(lines[2].split()[:2], ['[tasks]', 'last-out'])
        self.assertEqual(len(lines), 3)

    def test_parked_call_chain(self):
        self.uc.put(STACK + 8, 0x12345678, 0x40012345, 0, 0x40054321)
        self.switch(100, 0x300, 0x100, pc=0x400015e6)
        lines = self.prof.summary(200)
        self.assertEqual(lines[-1].split(), [
            '[tasks]', 'last-out', 'tcb=0x00000300', 'at', '100',
            'pc=0x400015e6', 'via', '0x40012345', '0x40054321'])


if __name__ == '__main__':
    unittest.main()
