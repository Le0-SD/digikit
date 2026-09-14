# pyright: reportMissingImports=false
"""Unicorn's ColdFire V4e core against the manual's EMAC semantics.

The interrupt handler that sends the SHARC control frame (Digitakt II
0x4002d652, Digitone II 0x40025e36) saves the EMAC state with `movclr` and
moves from MACSR, MASK and ACCext. Before emulating that handler we need to
know Unicorn executes these instructions. Unicorn exposes no EMAC registers,
so each case sets them with instructions and copies them back into D and A
registers. Expected values come from the ColdFire Programmer's Reference
Manual (docs/refs/CFPRM.pdf, chapter 6), not from running Unicorn.

Two differences from the manual are pinned as known gaps, so a Unicorn
change that fixes or alters them fails here and gets noticed.
"""

import struct
import unittest

from unicorn import UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_PROT_ALL, Uc, UcError
from unicorn import m68k_const

CODE = 0x10000

# (name, words, initial registers, instruction count, expected registers)
CASES = (
    (
        # move.l D7,MACSR; move.l D3,ACC0; movclr.l ACC0,D4; move.l ACC0,D5
        # p.6-6: ACC -> Rx, 0 -> ACC while MACSR[OMC] = 0.
        "movclr moves and clears the accumulator",
        ["a907", "a103", "a1c4", "a185"],
        {"D3": 0xDEADBEEF, "D7": 0},
        4,
        {"D4": 0xDEADBEEF, "D5": 0},
    ),
    (
        # move.l D2,MASK; move.l MASK,D6
        # p.6-20: only the low word is written; p.6-13: Rx[31:16] = 0xFFFF.
        "MASK round trip keeps the low word",
        ["ad02", "ad86"],
        {"D2": 0x1234ABCD},
        2,
        {"D6": 0xFFFFABCD},
    ),
    (
        # move.l D6,MACSR; move.l D7,MASK; move.l D6,ACC0;
        # mac.l D1,D2,ACC0 (two words); move.l ACC0,D0
        # p.6-2: ACCx + Ry * Rx -> ACCx in signed integer mode.
        "mac.l without load accumulates the product",
        ["a906", "ad07", "a106", "a401", "0800", "a180"],
        {"D1": 5, "D2": 7, "D6": 0, "D7": 0xFFFF},
        5,
        {"D0": 35},
    ),
    (
        # Setup: move.l D0..D3,ACC0..ACC3; move.l D4,ACCext01;
        # move.l D5,ACCext23; move.l D6,MASK; move.l D7,MACSR.
        # ACCx are loaded before ACCext because a move to ACCx rewrites that
        # accumulator's extension (p.6-15). Then the handler prologue:
        # move.l MACSR,A0; move.l #0,MACSR; move.l ACCext01,D4;
        # move.l ACCext23,D5; movclr.l ACC0..ACC3,D0..D3; move.l MASK,D6.
        # Then move.l ACC0..ACC3,A1..A4 to show the accumulators are 0.
        # D7 = 0xC21 has no bits above 11, so the MACSR gap below does not
        # affect A0.
        "handler prologue saves and clears the EMAC state",
        [
            "a100", "a301", "a502", "a703", "ab04", "af05", "ad06", "a907",
            "a988", "a93c", "0000", "0000", "ab84", "af85",
            "a1c0", "a3c1", "a5c2", "a7c3", "ad86",
            "a189", "a38a", "a58b", "a78c",
        ],
        {
            "D0": 0x12345678, "D1": 0x00000001, "D2": 0xFFFFFFFF,
            "D3": 0x7FFFFFFF, "D4": 0x11223344, "D5": 0x55667788,
            "D6": 0x000000FF, "D7": 0x00000C21,
        },
        21,
        {
            "A0": 0x00000C21, "D0": 0x12345678, "D1": 0x00000001,
            "D2": 0xFFFFFFFF, "D3": 0x7FFFFFFF, "D4": 0x11223344,
            "D5": 0x55667788, "D6": 0xFFFF00FF,
            "A1": 0, "A2": 0, "A3": 0, "A4": 0,
        },
    ),
)


def reg(name):
    return getattr(m68k_const, "UC_M68K_REG_" + name)


def run(words, init, count):
    code = b"".join(struct.pack(">H", int(word, 16)) for word in words)
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(m68k_const.UC_CPU_M68K_CFV4E)
    uc.mem_map(CODE, 0x1000, UC_PROT_ALL)
    uc.mem_write(CODE, code)
    uc.reg_write(reg("SR"), 0x2700)
    for name, value in init.items():
        uc.reg_write(reg(name), value)
    uc.emu_start(CODE, CODE + len(code), count=count)
    return uc, CODE + len(code)


class UnicornEmacTest(unittest.TestCase):
    def test_cases(self):
        for name, words, init, count, expect in CASES:
            with self.subTest(name):
                uc, end = run(words, init, count)
                self.assertEqual(uc.reg_read(reg("PC")), end, "stopped early")
                for register, value in expect.items():
                    self.assertEqual(
                        uc.reg_read(reg(register)) & 0xFFFFFFFF,
                        value,
                        "%s: %s = %#010x" % (name, register, uc.reg_read(reg(register))),
                    )

    def test_known_gap_macsr_read_keeps_high_bits(self):
        # move.l #$ffffffff,MACSR; move.l MACSR,D0
        # p.6-12 clears Rx[31:12]; Unicorn returns all 32 bits.
        uc, end = run(["a93c", "ffff", "ffff", "a980"], {}, 2)
        self.assertEqual(uc.reg_read(reg("PC")), end)
        self.assertEqual(uc.reg_read(reg("D0")) & 0xFFFFFFFF, 0xFFFFFFFF)

    def test_known_gap_move_acc_to_acc_not_implemented(self):
        # move.l D7,MACSR; move.l D1,ACC1; move.l D2,ACC2; move.l ACC1,ACC2
        # p.6-14 defines a511; Unicorn takes an exception on it, which shows
        # up as an unmapped read because no vector table is mapped.
        with self.assertRaises(UcError):
            run(
                ["a907", "a301", "a502", "a511"],
                {"D1": 0x11111111, "D2": 0x22222222, "D7": 0},
                4,
            )


if __name__ == "__main__":
    unittest.main()
