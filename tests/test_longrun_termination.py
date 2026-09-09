# pyright: reportMissingImports=false
"""Termination sentinels must not be counted as completed work."""

import unittest

from emu.harness import Machine
from emu.longrun import run_until, spin


class _ZeroAfterStartUc:
    """Minimal Unicorn surface whose first emu_start returns the zero sentinel."""

    def __init__(self):
        self.pc = 0x40000000
        self.starts = 0

    def emu_start(self, pc, until, count=0):
        self.starts += 1
        self.pc = 0

    def reg_read(self, register):
        return self.pc


class _ZeroAfterStartMachine:
    def __init__(self):
        self.uc = _ZeroAfterStartUc()
        self.halt_vec = None


class _Timers:
    def __init__(self):
        self.now = 0
        self.steps = 0
        self.services = 0

    def step(self, done, remaining):
        self.steps += 1
        return 10

    def service(self, done):
        self.services += 1


class LongrunTerminationTest(unittest.TestCase):
    def test_spin_pc_zero_credits_no_step_and_does_not_service_timers(self):
        timers = _Timers()
        pc, executed, stop = spin(Machine(), 0, 100, pits=timers)
        self.assertEqual((pc, executed, stop), (0, 0, "pc zero"))
        self.assertEqual(timers.steps, 0)
        self.assertEqual(timers.services, 0)

    def test_run_until_reports_pc_zero_sentinel(self):
        self.assertEqual(run_until(Machine(), 0), (0, "pc zero"))

    def test_spin_zero_returned_after_emu_start_credits_no_step_or_timer_service(self):
        timers = _Timers()
        machine = _ZeroAfterStartMachine()
        pc, executed, stop = spin(machine, machine.uc.pc, 100, pits=timers)
        self.assertEqual((pc, executed, stop), (0, 0, "pc zero"))
        self.assertEqual(machine.uc.starts, 1)
        self.assertEqual(timers.steps, 1)
        self.assertEqual(timers.services, 0)


if __name__ == "__main__":
    unittest.main()
