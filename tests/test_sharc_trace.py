"""Synthetic tests for the deliberately small SHARC delay tracer."""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from importlib import import_module
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools"))
T = import_module("sharc_trace")
Instruction = import_module("sharc_disasm").Instruction
L = import_module("sharcldr")
encode = import_module("test_sharc_disasm").encode


def loader_block(code, address, count, arg=0, payload=b""):
    """Build a checksum-valid synthetic loader block."""
    header = bytearray(struct.pack("<IIII", code | 0xAD000000, address, count, arg))
    header[2] = 0
    checksum = 0
    for byte in header:
        checksum ^= byte
    header[2] = checksum
    return bytes(header) + payload


def loader_memory(*blocks):
    return L.LoadedMemory.from_stream(b"".join(blocks))


def insn(name, fields, length=4, kind="confident"):
    return Instruction(0, length, name, fields, kind=kind)


class TraceTest(unittest.TestCase):
    def run_one(self, state, record):
        return T._execute(state, record)[0]

    def test_type21_nops_advance_without_changing_state(self):
        for name, length, expected_pc in (("21a", 6, 0x13), ("21c", 2, 0x11)):
            with self.subTest(name=name):
                state = T.State(0x10, {0: T.Const(7)})
                advanced = self.run_one(state, insn(name, {}, length=length))
                self.assertEqual(advanced.pc_sw, expected_pc)
                self.assertEqual(advanced.steps, 1)
                self.assertEqual(advanced.uregs, {0: T.Const(7)})
                self.assertEqual(advanced.trace, [])

    def test_type6b_executes_selected_shift_immediate_operations(self):
        cases = (
            ("bset0", 0x023E00300000, 0, 0, 1),
            ("bclr0", 0x023E00310000, 0, 0xFFFFFFFF, 0xFFFFFFFE),
            ("bset2", 0x023E00300200, 0, 0, 4),
            ("fext30", 0x023E38108022, 2, 0xFFFFFFFF, 0x3FFFFFFF),
            ("fext31", 0x023E3810C022, 2, 0xFFFFFFFF, 0x7FFFFFFF),
            ("lshift-10", 0x023E7800F611, 1, 0xFFFFFFFF, 0x003FFFFF),
            ("ashift-8-frame-reader", 0x023E7801F822, 2, 0x80000000, 0xFF800000),
            ("bset-r2", 0x023E00300022, 2, 0, 1),
            ("fext16", 0x023E20100022, 2, 0xFFFFFFFF, 0xFFFF),
            ("bclr25", 0x023E00311922, 2, 0xFFFFFFFF, 0xFDFFFFFF),
        )
        for label, word, register, initial, expected in cases:
            with self.subTest(label=label):
                words = (word >> 32, (word >> 16) & 0xFFFF, word & 0xFFFF)
                record = T.decode_at(struct.pack("<3H", *words), 0, 0)
                self.assertEqual(
                    (record.type_name, record.length_bytes, record.kind),
                    ("6b_shiftimm", 6, "confident"),
                )
                state = T.State(0x10, {register: T.Const(initial)})
                record.offset = 0
                advanced = self.run_one(state, record)
                self.assertEqual(advanced.pc_sw, 0x13)
                self.assertEqual(advanced.uregs[register], T.Const(expected))
                self.assertEqual(advanced.trace[-1]["action"], "compute")

    def test_type6b_rejects_unimplemented_predicates_and_opcodes(self):
        base = {
            "cond[4:0]": 0x1E,
            "dataex[3:0]": 0,
            "shiftimm[22:16]": 0x30,
            "shiftimm[15:0]": 0,
        }
        stopped = self.run_one(T.State(0x10), insn("6b_shiftimm", base, length=6))
        self.assertEqual(stopped.stopped, "unsupported Type6b predicate")
        base["cond[4:0]"] = 0x1F
        base["shiftimm[22:16]"] = 0x08
        stopped = self.run_one(T.State(0x10), insn("6b_shiftimm", base, length=6))
        self.assertEqual(stopped.stopped, "unsupported ShiftImm opcode 0x8")

    def test_type11c_immediate_conditional_and_delayed_rts(self):
        immediate = {"x": 0, "j": 0, "cond[4:0]": 0x1F, "lr": 0}
        state = T.State(0x10, call_stack=[0x200])
        returned = self.run_one(state, insn("11c", immediate, length=2))
        self.assertEqual((returned.pc_sw, returned.call_stack), (0x200, []))
        self.assertEqual(returned.trace[-1]["action"], "loaded-call-return")

        conditional = dict(immediate, **{"cond[4:0]": 0})
        states = T._execute(
            T.State(0x10, call_stack=[0x200]),
            insn("11c", conditional, length=2),
        )
        self.assertEqual(
            sorted((state.pc_sw, state.call_stack) for state in states),
            [(0x11, [0x200]), (0x200, [])],
        )

        delayed = dict(immediate, j=1)
        state = self.run_one(
            T.State(0x10, call_stack=[0x200]), insn("11c", delayed, length=2)
        )
        self.assertEqual((state.pc_sw, state.pending.slots), (0x11, 2))
        state = self.run_one(state, insn("21c", {}, length=2))
        state = self.run_one(state, insn("21c", {}, length=2))
        self.assertEqual((state.pc_sw, state.call_stack), (0x200, []))

        loop_entry = self.run_one(
            T.State(
                0x10,
                call_stack=[0x13],
                loops=[T.Loop(0x13, 0x20, 2, 1)],
            ),
            insn("11c", immediate, length=2),
        )
        self.assertEqual(loop_entry.stopped, "return reached loop PC-stack entry")

    def test_fixed_pass_drives_eq_return_from_documented_astat_flags(self):
        astatx = T.UREG_CODES["ASTATX"]
        mode1 = T.UREG_CODES["MODE1"]
        pass_zero = {
            "srcureghigh[4:0]": 0,
            "srcureglow[1:1]": 0,
            "srcureglow[0:0]": 0,
            "dstureg[6:0]": 24,
            "cond[4:0]": 0x1F,
            "compute[22:16]": 2,
            "compute[15:0]": 0x1000,
        }
        state = self.run_one(
            T.State(
                0x1C0FB9,
                {0: T.Const(0), astatx: T.Const(0xFFFFFFFF), mode1: T.Const(0)},
                call_stack=[0x200],
            ),
            insn("5a_move", pass_zero, length=6),
        )
        self.assertEqual(state.uregs[24], T.Const(0))
        self.assertEqual(state.uregs[astatx], T.Const(0xFFFFFFC1))
        self.assertTrue(T._predicate(state, 0x00))
        self.assertFalse(T._predicate(state, 0x10))

        returned = T._execute(
            state,
            insn(
                "11c",
                {"x": 0, "j": 0, "cond[4:0]": 0x00, "lr": 0},
                length=2,
            ),
        )
        self.assertEqual(len(returned), 1)
        self.assertEqual((returned[0].pc_sw, returned[0].call_stack), (0x200, []))

    def test_fixed_pass_sets_an_and_invalidates_unknown_astat(self):
        astatx = T.UREG_CODES["ASTATX"]
        mode1 = T.UREG_CODES["MODE1"]
        short_pass = {"compute[11:0]": 0x201}

        negative = self.run_one(
            T.State(
                0x10,
                {
                    1: T.Const(0x80000000),
                    astatx: T.Const(0xFFFF0000),
                    mode1: T.Const(0),
                },
            ),
            insn("2c", short_pass, length=2),
        )
        self.assertEqual(negative.uregs[astatx], T.Const(0xFFFF0004))
        self.assertFalse(T._predicate(negative, 0x00))
        self.assertTrue(T._predicate(negative, 0x10))

        unknown = self.run_one(
            T.State(0x10, {astatx: T.Const(0), mode1: T.Const(0)}),
            insn("2c", short_pass, length=2),
        )
        self.assertIsInstance(unknown.uregs[astatx], T.Unknown)
        self.assertIsNone(T._predicate(unknown, 0x00))
        self.assertIsNone(T._predicate(unknown, 0x10))

    def test_type11c_rejects_rti_and_loop_reentry(self):
        for fields, reason in (
            ({"x": 1, "j": 0, "cond[4:0]": 0x1F, "lr": 0}, "unsupported Type11c RTI"),
            ({"x": 0, "j": 0, "cond[4:0]": 0x1F, "lr": 1}, "unsupported Type11c loop reentry"),
        ):
            with self.subTest(reason=reason):
                stopped = self.run_one(T.State(0x10), insn("11c", fields, length=2))
                self.assertEqual(stopped.stopped, reason)

    def test_type18a_mutates_documented_system_register_bits(self):
        mode1 = T.UREG_CODES["MODE1"]
        cases = (
            (0, 0x30, 0x0C, 0x3C, "set"),
            (1, 0x3F, 0x0C, 0x33, "clear"),
            (2, 0x30, 0x0C, 0x3C, "toggle"),
        )
        for bop, initial, mask, expected, operation in cases:
            with self.subTest(operation=operation):
                state = T.State(0x10, {mode1: T.Const(initial)})
                advanced = self.run_one(
                    state,
                    insn(
                        "18a",
                        {
                            "bop[2:0]": bop,
                            "sreg[3:0]": 2,
                            "data[31:16]": 0,
                            "data[15:0]": mask,
                        },
                        length=6,
                    ),
                )
                self.assertEqual(advanced.uregs[mode1], T.Const(expected))
                self.assertEqual(advanced.trace[-1]["action"], "system-bit-op")
                self.assertEqual(advanced.trace[-1]["operation"], operation)

    def test_type18a_bit_tests_drive_tf_predicates(self):
        mode1 = T.UREG_CODES["MODE1"]
        astatx = T.UREG_CODES["ASTATX"]
        astaty = T.UREG_CODES["ASTATY"]
        stkyx = T.UREG_CODES["STKYX"]
        stkyy = T.UREG_CODES["STKYY"]

        def bit_test(bop, mask, state):
            return self.run_one(
                state,
                insn(
                    "18a",
                    {
                        "bop[2:0]": bop,
                        "sreg[3:0]": 8,
                        "data[31:16]": mask >> 16,
                        "data[15:0]": mask & 0xFFFF,
                    },
                    length=6,
                ),
            )

        state = bit_test(
            4,
            4,
            T.State(
                0x10,
                {mode1: T.Const(0), stkyx: T.Const(4), astatx: T.Const(0)},
            ),
        )
        self.assertEqual(state.trace[-1]["action"], "system-bit-test")
        self.assertTrue(state.trace[-1]["result"])
        self.assertTrue(T._predicate(state, 0x0D))
        self.assertFalse(T._predicate(state, 0x1D))

        state = bit_test(4, 8, state)
        self.assertFalse(state.trace[-1]["result"])
        self.assertFalse(T._predicate(state, 0x0D))
        self.assertTrue(T._predicate(state, 0x1D))

        state = bit_test(5, 4, state)
        self.assertTrue(state.trace[-1]["result"])
        self.assertTrue(T._predicate(state, 0x0D))

        simd = bit_test(
            4,
            4,
            T.State(
                0x10,
                {
                    mode1: T.Const(1 << 21),
                    stkyx: T.Const(4),
                    stkyy: T.Const(0),
                    astatx: T.Const(0),
                    astaty: T.Const(0),
                },
            ),
        )
        self.assertEqual(simd.uregs[astatx], T.Const(1 << 18))
        self.assertEqual(simd.uregs[astaty], T.Const(0))

        unknown = bit_test(
            4,
            4,
            T.State(0x10, {mode1: T.Const(0), astatx: T.Const(0)}),
        )
        self.assertIsNone(T._predicate(unknown, 0x0D))

    def test_type20a_pushes_and_pops_status_registers(self):
        codes = {name: T.UREG_CODES[name] for name in ("ASTATX", "ASTATY", "MODE1", "MMASK", "STKYX")}
        state = T.State(
            0x10,
            {
                codes["ASTATX"]: T.Const(1),
                codes["ASTATY"]: T.Const(2),
                codes["MODE1"]: T.Const(0x3C),
                codes["MMASK"]: T.Const(0x0C),
                codes["STKYX"]: T.Const(1 << 24),
            },
        )
        push_fields = {
            "lpu": 0,
            "lpo": 0,
            "spu": 1,
            "spo": 0,
            "ppu": 0,
            "ppo": 0,
            "fc": 1,
            "llii": 0,
            "lldwb": 0,
            "lldi": 0,
            "llpwb": 0,
            "llpi": 0,
        }
        state = self.run_one(state, insn("20a", push_fields, length=6))
        self.assertEqual(state.uregs[codes["MODE1"]], T.Const(0x30))
        self.assertEqual(state.uregs[codes["STKYX"]], T.Const(0))
        self.assertEqual(len(state.status_stack), 1)
        self.assertTrue(state.trace[-1]["flush_cache"])

        state.uregs[codes["ASTATX"]] = T.Const(9)
        state.uregs[codes["ASTATY"]] = T.Const(10)
        pop_fields = dict(push_fields, spu=0, spo=1, fc=0)
        state = self.run_one(state, insn("20a", pop_fields, length=6))
        self.assertEqual(state.uregs[codes["ASTATX"]], T.Const(1))
        self.assertEqual(state.uregs[codes["ASTATY"]], T.Const(2))
        self.assertEqual(state.uregs[codes["MODE1"]], T.Const(0x3C))
        self.assertEqual(state.uregs[codes["STKYX"]], T.Const(1 << 24))
        self.assertEqual(state.status_stack, [])

        state.uregs[codes["STKYX"]] = T.Const(0)
        empty_pop_fields = dict(pop_fields, lpo=1, ppo=1)
        state = self.run_one(state, insn("20a", empty_pop_fields, length=6))
        self.assertEqual(
            state.uregs[codes["STKYX"]],
            T.Const((1 << 26) | (1 << 24) | (1 << 22)),
        )
        self.assertEqual(state.uregs[T.UREG_CODES["CURLCNTR"]], T.Const(0xFFFFFFFF))
        self.assertEqual(state.uregs[T.UREG_CODES["PCSTK"]], T.Const(0x7FFFFFFF))
        self.assertEqual(state.uregs[T.UREG_CODES["PCSTKP"]], T.Const(0))

        mixed = self.run_one(
            T.State(0x10),
            insn("20a", dict(push_fields, lpo=1), length=6),
        )
        self.assertEqual(mixed.stopped, "invalid Type20a mixed push and pop")

    def test_type12a_immediate_runs_a_counted_single_instruction_loop(self):
        state = T.State(0x10, {T.UREG_CODES["STKYX"]: T.Const(0)})
        setup = insn(
            "12a_imm",
            {
                "data[15:8]": 0,
                "data[7:0]": 4,
                "mode": 1,
                "reladdr[22:16]": 0,
                "reladdr[15:0]": 3,
            },
            length=6,
        )
        state = self.run_one(state, setup)
        self.assertEqual(state.pc_sw, 0x13)
        self.assertEqual(state.loops, [T.Loop(0x13, 0x13, 4, 1)])
        self.assertEqual(state.call_stack, [0x13])
        self.assertEqual(state.uregs[T.UREG_CODES["PCSTK"]], T.Const(0x13))
        self.assertEqual(state.uregs[T.UREG_CODES["LCNTR"]], T.Const(4))
        self.assertEqual(state.uregs[T.UREG_CODES["STKYX"]], T.Const(0))

        nop = insn("21a", {}, length=6)
        for remaining in (3, 2, 1):
            state = self.run_one(state, nop)
            self.assertEqual(state.pc_sw, 0x13)
            self.assertEqual(state.loops[-1].remaining, remaining)
            self.assertEqual(
                state.uregs[T.UREG_CODES["CURLCNTR"]], T.Const(remaining)
            )
        state = self.run_one(state, nop)
        self.assertEqual(state.pc_sw, 0x16)
        self.assertEqual(state.loops, [])
        self.assertEqual(
            state.uregs[T.UREG_CODES["CURLCNTR"]], T.Const(0xFFFFFFFF)
        )
        self.assertEqual(
            state.uregs[T.UREG_CODES["STKYX"]], T.Const((1 << 26) | (1 << 22))
        )
        self.assertEqual(state.call_stack, [])
        self.assertEqual(state.trace[-1]["action"], "loop-exit")

        zero = self.run_one(
            T.State(0x10),
            insn(
                "12a_imm",
                {
                    "data[15:8]": 0,
                    "data[7:0]": 0,
                    "mode": 0,
                    "reladdr[22:16]": 0,
                    "reladdr[15:0]": 3,
                },
                length=6,
            ),
        )
        self.assertEqual(zero.stopped, "unsupported zero-count Type12a loop")

        ureg_fields = {
            "ureg[6:0]": 4,
            "mode": 1,
            "reladdr[22:16]": 0,
            "reladdr[15:0]": 3,
        }
        ureg = self.run_one(
            T.State(0x10, {4: T.Const(23)}),
            insn("12a_ureg", ureg_fields, length=6),
        )
        self.assertEqual(ureg.loops, [T.Loop(0x13, 0x13, 23, 1)])
        unknown = self.run_one(
            T.State(0x10), insn("12a_ureg", ureg_fields, length=6)
        )
        self.assertEqual(unknown.stopped, "nonconcrete Type12a UREG loop count")

    def test_17_signed_and_assembled(self):
        s = self.run_one(
            T.State(10), insn("17b", {"ureg[6:0]": 2, "data[15:0]": 0xFFFF})
        )
        self.assertEqual(s.uregs[2], T.Const(0xFFFFFFFF))
        s = self.run_one(
            T.State(10),
            insn(
                "17a", {"ureg[6:0]": 2, "data[31:16]": 0x1234, "data[15:0]": 0x5678}, 6
            ),
        )
        self.assertEqual(s.uregs[2], T.Const(0x12345678))

    def test_type7a_modify_is_explicitly_unknown_and_type3a_moves_one_word(self):
        modified = self.run_one(
            T.State(1, {23: T.Const(0x100), 1: T.Const(4), 2: T.Const(5)}),
            insn(
                "7a",
                {
                    "g": 0,
                    "cond[4:0]": 31,
                    "is[2:2]": 1,
                    "is[1:0]": 3,
                    "breg": 1,
                    "toby": 1,
                    "idis[2:0]": 0,
                    "compute[22:16]": 0x28,
                    "compute[15:0]": 0x8310,
                },
                6,
            ),
        )
        self.assertEqual(modified.trace[0]["action"], "i-modify")
        self.assertEqual(modified.trace[0]["source"], "I7")
        self.assertIsInstance(modified.uregs[23], T.Unknown)
        self.assertEqual(modified.uregs[3], T.Const(29))

        memory = loader_memory(loader_block(1, 0x80, 4, payload=b"\0" * 4))
        moved = self.run_one(
            T.State(
                1,
                {16: T.Const(0x80), 32: T.Const(4), 2: T.Const(0xAABBCCDD)},
                concrete=memory,
                assume_nw32=True,
            ),
            insn(
                "3a",
                {
                    "u": 1,
                    "i": 0,
                    "m": 0,
                    "cond": 31,
                    "g": 0,
                    "d": 1,
                    "l": 0,
                    "ureg": 2,
                    "compute": 0,
                },
                6,
            ),
        )
        self.assertTrue(moved.trace[0]["concrete_write"])
        self.assertEqual(T._dm_read(moved, 0x80, 4), T.Const(0xAABBCCDD))
        self.assertEqual(moved.uregs[16], T.Const(0x84))

    def test_type14a_direct_load_and_store(self):
        fields = {
            "addr[31:16]": 0x310C,
            "addr[15:0]": 0x90C0,
            "g": 0,
            "d": 1,
            "l": 0,
            "ureg[6:0]": 16,
        }
        stored = self.run_one(
            T.State(10, {16: T.Const(0x3DEF7B9C)}),
            insn("14a", fields, 6),
        )
        self.assertEqual(
            stored.trace[0],
            {
                "pc_sw": 10,
                "form": "14a",
                "action": "store",
                "space": "DM",
                "ureg": "I0",
                "value": 0x3DEF7B9C,
                "address": 0x310C90C0,
                "expression": "0x310c90c0",
                "simd_companion_possible": True,
            },
        )

        loaded = self.run_one(
            T.State(10, {16: T.Const(7)}),
            insn("14a", {**fields, "g": 1, "d": 0}, 6),
        )
        self.assertEqual(
            (loaded.trace[0]["space"], loaded.trace[0]["simd_companion_possible"]),
            ("PM", True),
        )
        self.assertEqual(loaded.trace[0]["address"], 0x310C90C0)
        self.assertEqual(loaded.uregs[16], T.Unknown("memory-address 0x310c90c0"))

        long_word = self.run_one(
            T.State(10, {0: T.Const(1), 1: T.Const(2)}),
            insn("14a", {**fields, "ureg[6:0]": 0, "l": 1}, 6),
        )
        self.assertEqual(long_word.stopped, "unsupported Type14a long-word access")
        self.assertEqual(long_word.trace[0]["action"], "stop")

    def test_pm_normal_word_load_into_px_splits_loader_backed_48_bits(self):
        address = T.L1_BLOCK3_NW_BASE + 0x20
        byte_address = L.sw_to_byte(T.L1_BLOCK3_SW_BASE) + 6 * 0x20
        payload = struct.pack("<3H", 0x1234, 0x5678, 0x9ABC)
        memory = loader_memory(
            loader_block(1, byte_address, len(payload), payload=payload)
        )
        fields = {
            "addr[31:16]": address >> 16,
            "addr[15:0]": address & 0xFFFF,
            "g": 1,
            "d": 0,
            "l": 0,
            "ureg[6:0]": T.UREG_CODES["PX"],
        }
        loaded = self.run_one(
            T.State(10, concrete=memory), insn("14a", fields, 6)
        )
        self.assertEqual(
            loaded.uregs[T.UREG_CODES["PX1"]], T.Const(0x9ABC0000)
        )
        self.assertEqual(
            loaded.uregs[T.UREG_CODES["PX2"]], T.Const(0x12345678)
        )
        self.assertIsInstance(loaded.uregs[T.UREG_CODES["PX"]], T.Unknown)
        self.assertEqual(
            loaded.trace[-1]["concrete_value"],
            {"PX1": 0x9ABC0000, "PX2": 0x12345678},
        )

        missing = self.run_one(
            T.State(
                10,
                {
                    T.UREG_CODES["PX"]: T.Const(1),
                    T.UREG_CODES["PX1"]: T.Const(2),
                    T.UREG_CODES["PX2"]: T.Const(3),
                },
                concrete=memory,
            ),
            insn(
                "14a",
                {**fields, "addr[15:0]": (address + 1) & 0xFFFF},
                6,
            ),
        )
        self.assertIsInstance(missing.uregs[T.UREG_CODES["PX"]], T.Unknown)
        self.assertIsInstance(missing.uregs[T.UREG_CODES["PX1"]], T.Unknown)
        self.assertIsInstance(missing.uregs[T.UREG_CODES["PX2"]], T.Unknown)

        dm_loaded = self.run_one(
            T.State(10, concrete=memory),
            insn("14a", {**fields, "g": 0}, 6),
        )
        self.assertEqual(
            dm_loaded.uregs[T.UREG_CODES["PX1"]], T.Const(0x9ABC0000)
        )
        self.assertEqual(
            dm_loaded.uregs[T.UREG_CODES["PX2"]], T.Const(0x12345678)
        )

    def test_type3b_pm_px_load_uses_normal_word_alias_and_post_modifies(self):
        address = T.L1_BLOCK3_NW_BASE + 0x21
        byte_address = L.sw_to_byte(T.L1_BLOCK3_SW_BASE) + 6 * 0x21
        payload = struct.pack("<3H", 0xABCD, 0x0123, 0x4567)
        memory = loader_memory(
            loader_block(1, byte_address, len(payload), payload=payload)
        )
        fields = {
            "u": 1,
            "i[2:0]": 0,
            "m[2:0]": 6,
            "cond[4:0]": 31,
            "g": 1,
            "d": 0,
            "l": 0,
            "ureg[6:0]": T.UREG_CODES["PX"],
            "w": 1,
            "x": 1,
        }
        state = T.State(
            10,
            {24: T.Const(address), 46: T.Const(1)},
            concrete=memory,
        )
        loaded = self.run_one(state, insn("3b", fields))
        self.assertEqual(loaded.uregs[24], T.Const(address + 1))
        self.assertEqual(
            loaded.uregs[T.UREG_CODES["PX1"]], T.Const(0x45670000)
        )
        self.assertEqual(
            loaded.uregs[T.UREG_CODES["PX2"]], T.Const(0xABCD0123)
        )
        self.assertEqual(loaded.trace[-1]["access_width"], "normal-word")

    def test_type25_negative_pcrel_target_wraps_24bit_current_sw_address(self):
        call = insn(
            "25a_pcrel",
            {"reladdr[23:16]": 0x80, "reladdr[15:0]": 0},
            6,
        )
        state = self.run_one(T.State(0x100), call)
        state = self.run_one(state, insn("21c", {}, length=2))
        state = self.run_one(state, insn("21c", {}, length=2))
        self.assertEqual(state.stopped, "external-call")
        self.assertEqual(state.trace[-1]["target_sw"], 0x800100)

        dt2_116 = insn(
            "25a_pcrel",
            {"reladdr[23:16]": 0x9C, "reladdr[15:0]": 0x843D},
            6,
        )
        state = self.run_one(T.State(0x1C0FA5), dt2_116)
        state = self.run_one(state, insn("21c", {}, length=2))
        state = self.run_one(state, insn("21c", {}, length=2))
        self.assertEqual(state.trace[-1]["target_sw"], 0xB893E2)

    def test_ureg_copy_and_compute_rejection(self):
        f = {
            "srcureghigh[4:0]": 4,
            "srcureglow[1:1]": 1,
            "srcureglow[0:0]": 0,
            "dstureg[6:0]": 3,
            "cond[4:0]": 31,
        }
        s = self.run_one(T.State(1, {18: T.Const(9)}), insn("5b_move", f))
        self.assertEqual(s.uregs[3], T.Const(9))
        f.update({"compute[22:16]": 1, "compute[15:0]": 0})
        self.assertIn(
            "unsupported full compute",
            self.run_one(T.State(1), insn("5a_move", f, 6)).stopped,
        )

    def test_ureg_move_unknown_predicate_forks_copy_and_skip(self):
        fields = {
            "cond[4:0]": 1,
            "srcureghigh[4:0]": 0,
            "srcureglow[1:1]": 0,
            "srcureglow[0:0]": 1,
            "dstureg[6:0]": 2,
        }
        executed, skipped = T._execute(
            T.State(10, {1: T.Const(0x1234), 2: T.Const(7)}),
            insn("5b_move", fields),
        )
        self.assertEqual(executed.uregs[2], T.Const(0x1234))
        self.assertEqual(skipped.uregs[2], T.Const(7))
        self.assertEqual(executed.trace[-1]["predicate_assumption"], True)
        self.assertEqual(skipped.trace[-1]["predicate_assumption"], False)

    def test_computes_and_old_value_parallel_move(self):
        short = lambda opcode, rn, rx: {"compute[11:0]": (opcode << 8) | (rn << 4) | rx}
        s = self.run_one(T.State(1, {3: T.Const(9)}), insn("2c", short(2, 1, 3), 2))
        self.assertEqual(s.uregs[1], T.Const(9))
        full = lambda cu, op, rn, rx, ry: {
            "compute[22:16]": ((cu << 4) | (op >> 4)),
            "compute[15:0]": ((op & 15) << 12) | (rn << 8) | (rx << 4) | ry,
        }
        s = self.run_one(
            T.State(1, {1: T.Const(99), 4: T.Const(7)}),
            insn(
                "5a_move",
                {
                    "srcureghigh[4:0]": 0,
                    "srcureglow[1:1]": 0,
                    "srcureglow[0:0]": 1,
                    "dstureg[6:0]": 4,
                    "cond[4:0]": 31,
                    **full(0, 0x02, 3, 4, 4),
                },
                6,
            ),
        )
        self.assertEqual((s.uregs[3], s.uregs[4]), (T.Const(0), T.Const(99)))
        for opcode, expected, operation in (
            (0x40, 0x0A00, "and"),
            (0x41, 0xAFAF, "or"),
            (0x42, 0xA5AF, "xor"),
        ):
            s = self.run_one(
                T.State(1, {1: T.Const(0x0F0F), 2: T.Const(0xAAA0)}),
                insn("2a", {"cond[4:0]": 31, **full(0, opcode, 3, 1, 2)}, 6),
            )
            self.assertEqual(s.uregs[3], T.Const(expected))
            self.assertEqual(s.trace[-1]["operation"], operation)
        s = self.run_one(
            T.State(1, {5: T.Const(11)}),
            insn(
                "5a_move",
                {
                    "srcureghigh[4:0]": 0,
                    "srcureglow[1:1]": 0,
                    "srcureglow[0:0]": 0,
                    "dstureg[6:0]": 6,
                    "cond[4:0]": 31,
                    **full(0, 0x21, 6, 5, 0),
                },
                6,
            ),
        )
        self.assertEqual(s.uregs[6], T.Const(11))
        s = self.run_one(
            T.State(1, {1: T.Const(6), 2: T.Const(7)}),
            insn(
                "5a_move",
                {
                    "srcureghigh[4:0]": 0,
                    "srcureglow[1:1]": 0,
                    "srcureglow[0:0]": 0,
                    "dstureg[6:0]": 3,
                    "cond[4:0]": 31,
                    **full(1, 0x70, 2, 1, 2),
                },
                6,
            ),
        )
        self.assertEqual(s.uregs[2], T.Const(42))
        self.assertEqual(s.trace[0]["action"], "compute")

        s = self.run_one(
            T.State(
                1,
                {
                    0: T.Const(99),
                    2: T.Const(4),
                    12: T.Const(4),
                    T.UREG_CODES["ASTATX"]: T.Const(1),
                },
            ),
            insn(
                "5a_move",
                {
                    "srcureghigh[4:0]": 0,
                    "srcureglow[1:1]": 0,
                    "srcureglow[0:0]": 0,
                    "dstureg[6:0]": 3,
                    "cond[4:0]": 31,
                    **full(0, 0x0A, 0, 12, 2),
                },
                6,
            ),
        )
        self.assertEqual(s.uregs[0], T.Const(99))
        self.assertEqual(s.trace[0]["operation"], "compare")
        self.assertTrue(s.trace[0]["status_only"])
        self.assertIsInstance(s.uregs[T.UREG_CODES["ASTATX"]], T.Unknown)

        s = self.run_one(
            T.State(1, {0: T.Const(0x10), 2: T.Const(4)}),
            insn(
                "5a_move",
                {
                    "srcureghigh[4:0]": 0,
                    "srcureglow[1:1]": 0,
                    "srcureglow[0:0]": 0,
                    "dstureg[6:0]": 2,
                    "cond[4:0]": 31,
                    **full(2, 0xCC, 0, 0, 2),
                },
                6,
            ),
        )
        self.assertEqual(s.uregs[0], T.Const(0x10))
        self.assertEqual(s.uregs[2], T.Const(0x10))
        self.assertEqual(
            (s.trace[0]["operation"], s.trace[0]["status_only"]),
            ("bit-test", True),
        )

        s = self.run_one(
            T.State(1, {1: T.Const(0x10), 2: T.Const(4)}),
            insn(
                "5a_move",
                {
                    "srcureghigh[4:0]": 0,
                    "srcureglow[1:1]": 0,
                    "srcureglow[0:0]": 0,
                    "dstureg[6:0]": 3,
                    "cond[4:0]": 31,
                    **full(2, 0xC8, 0, 1, 2),
                },
                6,
            ),
        )
        self.assertEqual(s.uregs[0], T.Const(0))
        self.assertEqual(s.trace[0]["operation"], "bit-toggle")

        s = self.run_one(
            T.State(1, {1: T.Const(0x10), 2: T.Const(32)}),
            insn("2a", {"cond[4:0]": 31, **full(2, 0xC8, 0, 1, 2)}, 6),
        )
        self.assertEqual(s.uregs[0], T.Const(0x10))

        s = self.run_one(
            T.State(1, {1: T.Const(0x80000001), 2: T.Const(4)}),
            insn("2a", {"cond[4:0]": 31, **full(2, 0x00, 0, 1, 2)}, 6),
        )
        self.assertEqual(s.uregs[0], T.Const(0x10))
        self.assertEqual(s.trace[0]["operation"], "logical-shift")

        for opcode, expected, operation in (
            (0xC0, 0x80000001, "bit-set"),
            (0xC4, 0x00000001, "bit-clear"),
        ):
            s = self.run_one(
                T.State(1, {1: T.Const(0x80000001), 2: T.Const(31)}),
                insn("2a", {"cond[4:0]": 31, **full(2, opcode, 0, 1, 2)}, 6),
            )
            self.assertEqual(s.uregs[0], T.Const(expected))
            self.assertEqual(s.trace[-1]["operation"], operation)

        s = self.run_one(
            T.State(1, {1: T.Const(0x80000000), 2: T.Const(0xFFFFFFFC)}),
            insn("2a", {"cond[4:0]": 31, **full(2, 0x00, 0, 1, 2)}, 6),
        )
        self.assertEqual(s.uregs[0], T.Const(0x08000000))

    def test_compute_unknown_and_unsupported_do_not_mutate(self):
        s = self.run_one(T.State(1), insn("2c", {"compute[11:0]": 0x251}, 2))
        self.assertIsInstance(s.uregs[5], T.Unknown)
        s = self.run_one(
            T.State(1, {1: T.Const(2)}), insn("2c", {"compute[11:0]": 0xF12}, 2)
        )
        self.assertIn("unsupported short compute", s.stopped)
        self.assertEqual(s.uregs, {1: T.Const(2)})

    def test_type6a_shift_store_and_post_modify_use_old_values(self):
        address = 0x1000
        fields = {
            "cond[4:0]": 31,
            "g": 0,
            "i[2:0]": 5,
            "m[2:0]": 5,
            "d": 1,
            "dreg[3:0]": 9,
            "dataex[3:0]": 0,
            # R2 = BCLR R2 BY 11
            "shiftimm[22:16]": 0x31,
            "shiftimm[15:0]": 0x0B22,
        }
        state = T.State(
            1,
            {
                T.UREG_CODES["R2"]: T.Const(0xFFFF),
                T.UREG_CODES["R9"]: T.Const(0x12345678),
                T.UREG_CODES["I5"]: T.Const(address),
                T.UREG_CODES["M5"]: T.Const(4),
            },
        )
        state = self.run_one(state, insn("6a_mem", fields, 6))
        self.assertEqual(state.uregs[T.UREG_CODES["R2"]], T.Const(0xF7FF))
        self.assertEqual(state.uregs[T.UREG_CODES["I5"]], T.Const(address + 4))
        self.assertEqual(
            (state.trace[0]["action"], state.trace[0]["address"], state.trace[0]["value"]),
            ("store", address, 0x12345678),
        )
        self.assertEqual(state.trace[1]["operation"], "bit-clear-immediate")

        toggled = self.run_one(
            T.State(1, {T.UREG_CODES["R1"]: T.Const(1)}),
            insn(
                "6b_shiftimm",
                {
                    "cond[4:0]": 31,
                    "dataex[3:0]": 0,
                    "shiftimm[22:16]": 0x32,
                    "shiftimm[15:0]": 0x1F01,
                },
                6,
            ),
        )
        self.assertEqual(toggled.uregs[T.UREG_CODES["R0"]], T.Const(0x80000001))
        self.assertEqual(toggled.trace[-1]["operation"], "bit-toggle-immediate")

    def test_full_compute_register_to_mr_move_is_recorded(self):
        state = self.run_one(
            T.State(1, {T.UREG_CODES["R2"]: T.Const(0x1234)}),
            insn(
                "2a",
                {
                    "cond[4:0]": 31,
                    "compute[22:16]": 0x41,
                    "compute[15:0]": 0x0200,
                },
                6,
            ),
        )
        self.assertEqual(state.uregs[T.UREG_CODES["R2"]], T.Const(0x1234))
        self.assertEqual(
            (state.trace[-1]["operation"], state.trace[-1]["result_register"]),
            ("mr-data-move", "MR0F"),
        )
        state.uregs[T.UREG_CODES["R10"]] = T.Const(3)
        state = self.run_one(
            state,
            insn(
                "2a",
                {
                    "cond[4:0]": 31,
                    "compute[22:16]": 0x1B,
                    "compute[15:0]": 0x40A2,
                },
                6,
            ),
        )
        self.assertEqual(state.special["MRF"], T.Const(0x1234 + 3 * 0x1234))
        self.assertEqual(state.trace[-1]["operation"], "multiply-accumulate")
        state.uregs[T.UREG_CODES["R6"]] = T.Const(2)
        state.uregs[T.UREG_CODES["R11"]] = T.Const(4)
        state = self.run_one(
            state,
            insn(
                "2a",
                {
                    "cond[4:0]": 31,
                    "compute[22:16]": 0x1B,
                    "compute[15:0]": 0x07B6,
                },
                6,
            ),
        )
        self.assertEqual(state.uregs[T.UREG_CODES["R7"]], T.Const(0x48D8))
        self.assertEqual(state.trace[-1]["operation"], "multiply-add-mrf")

    def test_type2a_increment_unconditional_and_affine(self):
        def full(opcode, rn, rx, ry=0):
            return {
                "compute[22:16]": opcode >> 4,
                "compute[15:0]": ((opcode & 0xF) << 12) | (rn << 8) | (rx << 4) | ry,
            }

        concrete = self.run_one(
            T.State(10, {4: T.Const(0x41)}),
            insn("2a", {"cond[4:0]": 0x1F, **full(0x29, 3, 4)}, 6),
        )
        self.assertEqual((concrete.pc_sw, concrete.uregs[3]), (13, T.Const(0x42)))
        self.assertEqual(
            concrete.trace[-1],
            {
                "pc_sw": 10,
                "form": "2a",
                "action": "compute",
                "operation": "increment",
                "result_register": "R3",
                "condition": 0x1F,
                "predicate_assumption": True,
            },
        )
        affine = self.run_one(
            T.State(10, {4: T.symbol("counter")}),
            insn("2a", {"cond[4:0]": 0x1F, **full(0x29, 3, 4)}, 6),
        )
        self.assertEqual(affine.uregs[3], T.Affine(1, (("counter", 1),)))

    def test_type2a_decrement_unconditional_and_affine(self):
        def full(opcode, rn, rx, ry=0):
            return {
                "compute[22:16]": opcode >> 4,
                "compute[15:0]": ((opcode & 0xF) << 12) | (rn << 8) | (rx << 4) | ry,
            }

        concrete = self.run_one(
            T.State(10, {4: T.Const(0)}),
            insn("2a", {"cond[4:0]": 0x1F, **full(0x2A, 3, 4)}, 6),
        )
        self.assertEqual((concrete.pc_sw, concrete.uregs[3]), (13, T.Const(0xFFFFFFFF)))
        self.assertEqual(
            concrete.trace[-1],
            {
                "pc_sw": 10,
                "form": "2a",
                "action": "compute",
                "operation": "decrement",
                "result_register": "R3",
                "condition": 0x1F,
                "predicate_assumption": True,
            },
        )
        affine = self.run_one(
            T.State(10, {4: T.symbol("counter")}),
            insn("2a", {"cond[4:0]": 0x1F, **full(0x2A, 3, 4)}, 6),
        )
        self.assertEqual(affine.uregs[3], T.Affine(-1, (("counter", 1),)))

    def test_type2a_unknown_predicate_forks_execute_and_skip(self):
        fields = {
            "cond[4:0]": 1,
            "compute[22:16]": 2,
            "compute[15:0]": 0x9340,
        }
        executed, skipped = T._execute(
            T.State(10, {4: T.Const(7)}), insn("2a", fields, 6)
        )
        self.assertEqual((executed.pc_sw, skipped.pc_sw), (13, 13))
        self.assertEqual(executed.uregs[3], T.Const(8))
        self.assertNotIn(3, skipped.uregs)
        self.assertEqual(
            (
                executed.trace[-1]["condition"],
                executed.trace[-1]["predicate_assumption"],
            ),
            (1, True),
        )
        self.assertEqual(
            (
                skipped.trace[-1]["action"],
                skipped.trace[-1]["condition"],
                skipped.trace[-1]["predicate_assumption"],
            ),
            ("compute-skipped", 1, False),
        )
        executed.uregs[3] = T.Const(0)
        self.assertNotIn(3, skipped.uregs)

    def test_type2a_status_only_and_unsupported_do_not_write(self):
        compare = self.run_one(
            T.State(10, {0: T.Const(0x55), 2: T.Const(4), 12: T.Const(4)}),
            insn(
                "2a",
                {
                    "cond[4:0]": 0x1F,
                    "compute[22:16]": 0,
                    "compute[15:0]": 0xA0C2,
                },
                6,
            ),
        )
        self.assertEqual(compare.uregs[0], T.Const(0x55))
        self.assertEqual(
            (compare.trace[-1]["operation"], compare.trace[-1]["status_only"]),
            ("compare", True),
        )
        original = {1: T.Const(2)}
        unsupported = self.run_one(
            T.State(10, dict(original)),
            insn(
                "2a",
                {"cond[4:0]": 0x1F, "compute[22:16]": 0xF, "compute[15:0]": 0x1234},
                6,
            ),
        )
        self.assertIn("unsupported full compute", unsupported.stopped)
        self.assertEqual(unsupported.uregs, original)
        empty = self.run_one(
            T.State(10, dict(original)),
            insn(
                "2a",
                {"cond[4:0]": 0x1F, "compute[22:16]": 0, "compute[15:0]": 0},
                6,
            ),
        )
        self.assertEqual(empty.stopped, "empty full compute")
        self.assertEqual(empty.uregs, original)

    def test_type2a_second_call_delay_slot_forks_to_external_call(self):
        call = insn("25a_direct", {"addr[23:16]": 0, "addr[15:0]": 99}, 4)
        first_slot = insn("17b", {"ureg[6:0]": 0, "data[15:0]": 1}, 4)
        type2a = insn(
            "2a",
            {"cond[4:0]": 1, "compute[22:16]": 2, "compute[15:0]": 0x9340},
            6,
        )
        state = self.run_one(T.State(10, {4: T.Const(7)}), call)
        state = self.run_one(state, first_slot)
        executed, skipped = T._execute(state, type2a)
        for result, assumed in ((executed, True), (skipped, False)):
            self.assertEqual(result.stopped, "external-call")
            self.assertEqual(
                (result.trace[-1]["return_sw"], result.trace[-1]["target_sw"]), (17, 99)
            )
            self.assertEqual(result.trace[-2]["predicate_assumption"], assumed)
        self.assertEqual(executed.uregs[3], T.Const(8))
        self.assertNotIn(3, skipped.uregs)

    def test_type4a_pre_post_and_type3c(self):
        base = {
            "i[2:0]": 1,
            "g": 0,
            "d": 0,
            "cond[4:0]": 31,
            "data[5:5]": 1,
            "data[4:0]": 0x1F,
            "dreg[3:0]": 2,
            "compute[22:16]": 0,
            "compute[15:0]": 0,
        }
        s = self.run_one(
            T.State(1, {17: T.Const(0x100)}), insn("4a", {**base, "u": 0}, 6)
        )
        self.assertEqual(s.trace[0]["address"], 0xFF)
        self.assertEqual(s.uregs[17], T.Const(0x100))
        # The full compute reads R2 before this postmodify load overwrites it.
        computed = {"compute[22:16]": 0x02, "compute[15:0]": 0x1320}
        s = self.run_one(
            T.State(1, {17: T.Const(0x100), 2: T.Const(4)}),
            insn("4a", {**base, **computed, "u": 1}, 6),
        )
        self.assertEqual(s.uregs[3], T.Const(4))
        s = self.run_one(
            T.State(1, {17: T.Const(0x100), 2: T.Const(4)}),
            insn("4a", {**base, "u": 1, "d": 1}, 6),
        )
        self.assertEqual(s.trace[0]["address"], 0x100)
        self.assertEqual(s.trace[0]["value"], 4)
        self.assertEqual(s.uregs[17], T.Const(0xFF))
        self.assertEqual((T.UREG_CODES["I0"], T.UREG_CODES["M0"]), (16, 32))
        s = self.run_one(
            T.State(1, {16: T.Const(0x80), 32: T.Const(3)}),
            insn("3c", {"dmi[2:0]": 0, "dmm[2:0]": 0, "d": 0, "dreg[3:0]": 3}, 2),
        )
        self.assertEqual(
            (s.trace[0]["space"], s.trace[0]["address"], s.uregs[16]),
            ("DM", 0x80, T.Const(0x83)),
        )
        # The Type3c call-slot case selects DAG1 I7 and M7 directly.
        self.assertEqual((T.UREG_NAMES[23], T.UREG_NAMES[39]), ("I7", "M7"))
        s = self.run_one(
            T.State(1, {23: T.Const(0x90), 39: T.Const(4)}),
            insn("3c", {"dmi[2:0]": 7, "dmm[2:0]": 7, "d": 0, "dreg[3:0]": 3}, 2),
        )
        self.assertEqual((s.trace[0]["address"], s.uregs[23]), (0x90, T.Const(0x94)))

    def test_type16a_store_and_unknown_postmodify(self):
        f = {
            "i[2:0]": 2,
            "m[2:0]": 3,
            "g": 1,
            "sl": 0,
            "by": 0,
            "data[31:16]": 0x1234,
            "data[15:0]": 0x5678,
        }
        s = self.run_one(
            T.State(1, {26: T.Const(0x90), 43: T.Const(4)}), insn("16a", f, 6)
        )
        self.assertEqual(
            (s.trace[0]["space"], s.trace[0]["value"], s.uregs[26]),
            ("PM", 0x12345678, T.Const(0x94)),
        )
        s = self.run_one(T.State(1), insn("16a", f, 6))
        self.assertIsInstance(s.uregs[26], T.Unknown)

    def test_synthetic_prefix_forms(self):
        full_mul = {"compute[22:16]": 0x17, "compute[15:0]": 0x0212}
        move = {
            "srcureghigh[4:0]": 1,
            "srcureglow[1:1]": 0,
            "srcureglow[0:0]": 0,
            "dstureg[6:0]": 13,
            "cond[4:0]": 31,
            "compute[22:16]": 0,
            "compute[15:0]": 0,
        }
        records = [
            insn("5a_move", move, 6),
            insn(
                "15b",
                {"i[2:0]": 0, "g": 0, "d": 1, "l": 1, "ureg[6:0]": 4, "data[6:0]": 0},
            ),
            insn(
                "15b",
                {"i[2:0]": 0, "g": 0, "d": 0, "l": 1, "ureg[6:0]": 14, "data[6:0]": 0},
            ),
            insn("2c", {"compute[11:0]": 0x202}, 2),
            insn("17b", {"ureg[6:0]": 7, "data[15:0]": 1}),
            insn(
                "4a",
                {
                    "i[2:0]": 1,
                    "g": 0,
                    "d": 0,
                    "u": 0,
                    "cond[4:0]": 31,
                    "data[5:5]": 0,
                    "data[4:0]": 0,
                    "dreg[3:0]": 14,
                    "compute[22:16]": 0,
                    "compute[15:0]": 0,
                },
                6,
            ),
            insn(
                "4a",
                {
                    "i[2:0]": 1,
                    "g": 0,
                    "d": 0,
                    "u": 0,
                    "cond[4:0]": 31,
                    "data[5:5]": 0,
                    "data[4:0]": 0,
                    "dreg[3:0]": 4,
                    "compute[22:16]": 0,
                    "compute[15:0]": 0,
                },
                6,
            ),
            insn(
                "5a_move",
                {
                    **move,
                    "srcureghigh[4:0]": 3,
                    "srcureglow[1:1]": 1,
                    "srcureglow[0:0]": 0,
                    "dstureg[6:0]": 4,
                    **full_mul,
                },
                6,
            ),
        ]
        s = T.State(
            1,
            {
                4: T.Const(0x55),
                1: T.Const(6),
                2: T.Const(7),
                16: T.Const(0),
                17: T.Const(0),
            },
        )
        for record in records:
            s = self.run_one(s, record)
        self.assertEqual(s.uregs[13], T.Const(0x55))
        self.assertEqual(s.uregs[2], T.Const(42))
        self.assertIsInstance(s.uregs[14], T.Unknown)
        self.assertEqual(s.uregs[4], s.uregs[14])

    def test_15b_concrete_symbolic_load_and_store(self):
        f = {"i[2:0]": 1, "g": 0, "d": 0, "l": 1, "ureg[6:0]": 2, "data[6:0]": 0x7F}
        s = self.run_one(T.State(1, {17: T.Const(0x100)}), insn("15b", f))
        self.assertEqual(s.trace[0]["address"], 0xFF)
        self.assertIsInstance(s.uregs[2], T.Unknown)
        f["d"] = 1
        s = self.run_one(T.State(1, {2: T.Const(5)}), insn("15b", f))
        self.assertEqual(s.trace[0]["action"], "store")
        self.assertEqual(s.trace[0]["expression"], "I1 + -1")

    def test_normal_word_immediate_offsets_scale_only_when_opted_in(self):
        type4 = {
            "i[2:0]": 1,
            "g": 0,
            "d": 0,
            "cond[4:0]": 31,
            "data[5:5]": 0,
            "data[4:0]": 3,
            "dreg[3:0]": 2,
            "compute[22:16]": 0,
            "compute[15:0]": 0,
            "u": 0,
        }
        state = T.State(1, {17: T.Const(0x100)}, assume_nw32=True)
        s = self.run_one(state, insn("4a", type4, 6))
        self.assertEqual(s.trace[0]["address"], 0x10C)

        type15 = {
            "i[2:0]": 1,
            "g": 0,
            "d": 0,
            "l": 0,
            "ureg[6:0]": 2,
            "data[6:0]": 3,
        }
        state = T.State(1, {17: T.Const(0x100)}, assume_nw32=True)
        s = self.run_one(state, insn("15b", type15))
        self.assertEqual(s.trace[0]["address"], 0x10C)

    def test_type3b_dm_premodify_load_and_pm_postmodify_store(self):
        load = {
            "u": 0,
            "i[2:0]": 1,
            "m[2:0]": 2,
            "g": 0,
            "d": 0,
            "l": 0,
            "x": 1,
            "w": 1,
            "ureg[6:0]": 7,
            "cond[4:0]": 31,
        }
        s = self.run_one(
            T.State(1, {17: T.symbol("buffer"), 34: T.Const(4)}), insn("3b", load)
        )
        event = s.trace[0]
        self.assertEqual(
            (
                event["space"],
                event["expression"],
                event["addressing_mode"],
                event["access_width"],
            ),
            ("DM", "buffer + 0x4", "pre-modify", "normal-word"),
        )
        self.assertEqual(s.uregs[17], T.symbol("buffer"))
        self.assertEqual(s.uregs[7], T.Unknown("memory-address buffer + 0x4"))

        store = {
            **load,
            "u": 1,
            "i[2:0]": 2,
            "m[2:0]": 3,
            "g": 1,
            "d": 1,
            "ureg[6:0]": 4,
        }
        s = self.run_one(
            T.State(1, {26: T.Const(0x90), 43: T.Const(4), 4: T.Const(0x55)}),
            insn("3b", store),
        )
        event = s.trace[0]
        self.assertEqual(
            (
                event["space"],
                event["address"],
                event["value"],
                event["addressing_mode"],
            ),
            ("PM", 0x90, 0x55, "post-modify"),
        )
        self.assertEqual(s.uregs[26], T.Const(0x94))

    def test_type3b_widths_and_rejections_do_not_mutate(self):
        base = {
            "u": 0,
            "i[2:0]": 0,
            "m[2:0]": 0,
            "g": 0,
            "d": 0,
            "ureg[6:0]": 2,
            "cond[4:0]": 31,
        }
        expected = {
            (0, 1, 1): ("normal-word", 0x83),
            (0, 0, 0): ("byte", 0x83),
            (0, 1, 0): ("byte-sign-extended", 0x83),
            (1, 0, 0): ("short-word", 0x86),
            (1, 1, 0): ("short-word-sign-extended", 0x86),
            (1, 1, 1): ("long-word", 0x98),
        }
        for (l, x, w), (access_width, address) in expected.items():
            event = self.run_one(
                T.State(1, {16: T.Const(0x80), 32: T.Const(3)}),
                insn("3b", {**base, "l": l, "x": x, "w": w}),
            ).trace[0]
            self.assertEqual(event["access_width"], access_width)
            self.assertEqual(event["address"], address)

        for fields, reason in (
            ({"l": 0, "x": 0, "w": 1}, "unsupported Type3b access width"),
            (
                {"d": 1, "l": 0, "x": 1, "w": 0},
                "unsupported Type3b sign-extended store",
            ),
        ):
            state = self.run_one(
                T.State(1, {16: T.Const(0x80), 32: T.Const(3), 2: T.Const(9)}),
                insn("3b", {**base, **fields}),
            )
            self.assertEqual(state.stopped, reason)
            self.assertEqual(
                state.uregs, {16: T.Const(0x80), 32: T.Const(3), 2: T.Const(9)}
            )

        invalid = T._execute(
            T.State(1, {16: T.Const(0x80), 32: T.Const(3), 2: T.Const(9)}),
            insn("3b", {**base, "cond[4:0]": 1, "l": 0, "x": 0, "w": 1}),
        )
        self.assertEqual(len(invalid), 1)
        self.assertEqual(invalid[0].stopped, "unsupported Type3b access width")
        self.assertEqual(
            invalid[0].uregs, {16: T.Const(0x80), 32: T.Const(3), 2: T.Const(9)}
        )

    def test_type3b_unknown_predicate_forks_premodify_load_and_postmodify_store(self):
        load = {
            "u": 0,
            "i[2:0]": 1,
            "m[2:0]": 2,
            "g": 0,
            "d": 0,
            "l": 0,
            "x": 1,
            "w": 1,
            "ureg[6:0]": 7,
            "cond[4:0]": 1,
        }
        executed, skipped = T._execute(
            T.State(10, {17: T.symbol("buffer"), 34: T.Const(4)}),
            insn("3b", load),
        )
        self.assertEqual((executed.pc_sw, skipped.pc_sw), (12, 12))
        self.assertEqual(executed.uregs[7], T.Unknown("memory-address buffer + 0x4"))
        self.assertNotIn(7, skipped.uregs)
        self.assertEqual(executed.uregs[17], T.symbol("buffer"))
        self.assertEqual(skipped.uregs[17], T.symbol("buffer"))
        self.assertEqual(
            (
                executed.trace[-1]["condition"],
                executed.trace[-1]["predicate_assumption"],
            ),
            (1, True),
        )
        self.assertEqual(
            skipped.trace[-1],
            {
                "pc_sw": 10,
                "form": "3b",
                "action": "memory-access-skipped",
                "space": "DM",
                "ureg": "R7",
                "addressing_mode": "pre-modify",
                "access_width": "normal-word",
                "condition": 1,
                "predicate_assumption": False,
            },
        )

        store = {**load, "u": 1, "d": 1, "ureg[6:0]": 4}
        executed, skipped = T._execute(
            T.State(10, {17: T.Const(0x80), 34: T.Const(4), 4: T.Const(7)}),
            insn("3b", store),
        )
        self.assertEqual(executed.uregs[17], T.Const(0x84))
        self.assertEqual(skipped.uregs[17], T.Const(0x80))
        self.assertEqual(executed.trace[-1]["value"], 7)
        self.assertEqual(skipped.trace[-1]["addressing_mode"], "post-modify")
        executed.uregs[4] = T.Const(99)
        executed.uregs[17] = T.Const(0)
        self.assertEqual(
            (skipped.uregs[4], skipped.uregs[17]), (T.Const(7), T.Const(0x80))
        )

    def test_type3b_dm_postmodify_and_pm_premodify(self):
        store = {
            "i[2:0]": 1,
            "m[2:0]": 2,
            "d": 1,
            "l": 0,
            "x": 1,
            "w": 1,
            "ureg[6:0]": 4,
            "cond[4:0]": 31,
        }
        dm = self.run_one(
            T.State(1, {17: T.symbol("dm"), 34: T.Const(4), 4: T.Const(7)}),
            insn("3b", {**store, "u": 1, "g": 0}),
        )
        self.assertEqual(dm.trace[0]["expression"], "dm")
        self.assertEqual(dm.uregs[17], T.Affine(4, (("dm", 1),)))

        pm = self.run_one(
            T.State(1, {25: T.symbol("pm"), 42: T.Const(4), 4: T.Const(7)}),
            insn("3b", {**store, "u": 0, "g": 1}),
        )
        self.assertEqual(pm.trace[0]["expression"], "pm + 0x4")
        self.assertEqual(pm.uregs[25], T.symbol("pm"))

    def test_type4b_immediate_width_and_postmodify(self):
        memory = loader_memory(
            loader_block(1, L.SW_ALIAS_BASE + 0x80, 4, payload=b"\x80\x7f\0\0")
        )
        fields = {
            "i[2:0]": 1,
            "g": 0,
            "d": 0,
            "u": 1,
            "cond[4:0]": 31,
            "data[5:5]": 0,
            "data[4:0]": 2,
            "dreg[3:0]": 3,
            "l": 0,
            "x": 1,
            "w": 0,
        }
        state = self.run_one(
            T.State(1, {17: T.Const(0x80)}, concrete=memory),
            insn("4b", fields, 4),
        )
        self.assertEqual(state.uregs[3], T.Const(0xFFFFFF80))
        self.assertEqual(state.uregs[17], T.Const(0x82))
        self.assertEqual(state.trace[0]["access_width"], "byte-sign-extended")

        short = self.run_one(
            T.State(1, {17: T.Const(0x80)}),
            insn("4b", {**fields, "u": 0, "l": 1, "x": 1, "w": 0}, 4),
        )
        self.assertEqual(short.trace[0]["address"], 0x84)
        self.assertEqual(short.trace[0]["access_width"], "short-word-sign-extended")

    def test_type3b_unknown_predicate_second_call_delay_slot_preserves_call_target(
        self,
    ):
        call = insn("25a_direct", {"addr[23:16]": 0, "addr[15:0]": 99}, 4)
        type3b = insn(
            "3b",
            {
                "u": 1,
                "i[2:0]": 0,
                "m[2:0]": 0,
                "g": 0,
                "d": 0,
                "l": 0,
                "x": 1,
                "w": 1,
                "ureg[6:0]": 2,
                "cond[4:0]": 1,
            },
        )
        s = self.run_one(T.State(10, {16: T.Const(0x80), 32: T.Const(4)}), call)
        s = self.run_one(s, insn("17b", {"ureg[6:0]": 0, "data[15:0]": 1}, 4))
        executed, skipped = T._execute(s, type3b)
        for result, assumed in ((executed, True), (skipped, False)):
            self.assertEqual(result.stopped, "external-call")
            self.assertEqual(
                (result.trace[-1]["return_sw"], result.trace[-1]["target_sw"]), (17, 99)
            )
            self.assertEqual(result.trace[-2]["predicate_assumption"], assumed)
        self.assertIn(2, executed.uregs)
        self.assertNotIn(2, skipped.uregs)

    def test_19a_constant_and_unknown(self):
        f = {
            "g": 1,
            "idis[2:0]": 2,
            "is[2:0]": 1,
            "data[31:16]": 0xFFFF,
            "data[15:0]": 0xFFFE,
        }
        self.assertEqual(
            self.run_one(T.State(1, {25: T.Const(7)}), insn("19a", f, 6)).uregs[27],
            T.Const(5),
        )
        self.assertIsInstance(
            self.run_one(T.State(1), insn("19a", f, 6)).uregs[27], T.Unknown
        )

    def test_delay_slots_variable_width_and_target(self):
        branch = insn(
            "8a_abs",
            {"b": 0, "j": 1, "cond[4:0]": 31, "addr[23:16]": 0, "addr[15:0]": 99},
            6,
        )
        s = self.run_one(T.State(10), branch)
        s = self.run_one(s, insn("17b", {"ureg[6:0]": 0, "data[15:0]": 1}, 4))
        s = self.run_one(
            s, insn("17a", {"ureg[6:0]": 1, "data[31:16]": 0, "data[15:0]": 2}, 6)
        )
        self.assertEqual(s.pc_sw, 99)
        self.assertEqual([e["pc_sw"] for e in s.trace], [10, 13, 15])

    def test_conditional_forks_have_independent_two_slot_delays(self):
        branch = insn(
            "8a_abs",
            {"b": 0, "j": 1, "cond[4:0]": 1, "addr[23:16]": 0, "addr[15:0]": 30},
            6,
        )
        taken, not_taken = T._execute(T.State(10), branch)
        self.assertEqual(taken.trace[-1]["action"], "branch")
        self.assertEqual(not_taken.trace[-1]["action"], "branch-not-taken")
        not_taken.trace[-1]["action"] = "changed-not-taken"
        self.assertEqual(taken.trace[-1]["action"], "branch")

        # The not-taken state retains its delay marker and rejects transfers
        # in both delay slots.
        self.assertEqual(
            self.run_one(not_taken, branch).stopped, "nested delayed transfer"
        )
        _, not_taken = T._execute(T.State(10), branch)
        not_taken = self.run_one(
            not_taken, insn("17b", {"ureg[6:0]": 0, "data[15:0]": 1}, 4)
        )
        self.assertEqual(
            self.run_one(not_taken, branch).stopped, "nested delayed transfer"
        )

        taken, not_taken = T._execute(T.State(10), branch)
        slot32 = insn("17b", {"ureg[6:0]": 0, "data[15:0]": 1}, 4)
        slot48 = insn("17a", {"ureg[6:0]": 1, "data[31:16]": 0, "data[15:0]": 2}, 6)
        taken = self.run_one(self.run_one(taken, slot32), slot48)
        not_taken = self.run_one(self.run_one(not_taken, slot32), slot48)
        self.assertEqual(taken.pc_sw, 30)
        self.assertEqual(not_taken.pc_sw, 18)
        self.assertEqual([e["pc_sw"] for e in taken.trace], [10, 13, 15])
        self.assertEqual([e["pc_sw"] for e in not_taken.trace], [10, 13, 15])

    def test_type8_without_db_transfers_immediately(self):
        branch = insn(
            "8a_abs",
            {"b": 0, "j": 0, "cond[4:0]": 31, "addr[23:16]": 0, "addr[15:0]": 30},
            6,
        )
        state = self.run_one(T.State(10), branch)
        self.assertEqual(state.pc_sw, 30)
        self.assertIsNone(state.pending)
        self.assertEqual(state.steps, 1)

        conditional = insn(
            "8a_abs",
            {"b": 0, "j": 0, "cond[4:0]": 1, "addr[23:16]": 0, "addr[15:0]": 30},
            6,
        )
        taken, not_taken = T._execute(T.State(10), conditional)
        self.assertEqual(taken.pc_sw, 30)
        self.assertEqual(not_taken.pc_sw, 13)
        self.assertEqual(not_taken.trace[-1]["action"], "branch-not-taken")

    def test_type8_call_without_db_uses_immediate_return_address(self):
        call = insn(
            "8a_abs",
            {"b": 1, "j": 0, "cond[4:0]": 31, "addr[23:16]": 0, "addr[15:0]": 99},
            6,
        )
        taken = self.run_one(T.State(10), call)
        self.assertEqual(taken.stopped, "external-call")
        self.assertEqual(
            (taken.trace[-1]["target_sw"], taken.trace[-1]["return_sw"]), (99, 13)
        )

        conditional = insn(
            "8a_abs",
            {"b": 1, "j": 0, "cond[4:0]": 1, "addr[23:16]": 0, "addr[15:0]": 99},
            6,
        )
        taken, not_taken = T._execute(T.State(10), conditional)
        self.assertEqual(taken.stopped, "external-call")
        self.assertEqual(taken.trace[-1]["return_sw"], 13)
        self.assertEqual(not_taken.pc_sw, 13)
        self.assertIsNone(not_taken.stopped)
        self.assertEqual(not_taken.trace[-1]["action"], "branch-not-taken")

        negative = insn(
            "8a_rel",
            {
                "b": 1,
                "j": 0,
                "cond[4:0]": 31,
                "reladdr[23:16]": 0x80,
                "reladdr[15:0]": 0,
            },
            6,
        )
        guarded = self.run_one(
            T.State(
                0,
                concrete=loader_memory(loader_block(0, 0, 4, payload=b"\0" * 4)),
                follow_loaded_calls=True,
            ),
            negative,
        )
        self.assertEqual(guarded.stopped, "external-call")
        self.assertEqual(guarded.trace[-1]["target_sw"], 0x800000)

    def test_delayed_call_returns_after_variable_width_slots(self):
        call = insn("25a_direct", {"addr[23:16]": 0, "addr[15:0]": 99}, 4)
        s = self.run_one(T.State(10), call)
        s = self.run_one(s, insn("17b", {"ureg[6:0]": 0, "data[15:0]": 1}, 4))
        s = self.run_one(
            s, insn("17a", {"ureg[6:0]": 1, "data[31:16]": 0, "data[15:0]": 2}, 6)
        )
        self.assertEqual(s.stopped, "external-call")
        self.assertEqual(s.trace[-1]["return_sw"], 17)
        self.assertEqual(s.trace[-1]["target_sw"], 99)
        self.assertEqual([e["pc_sw"] for e in s.trace[:-1]], [10, 12, 14])

    def test_provisional_stop(self):
        self.assertIn(
            "uncertain",
            self.run_one(T.State(1), insn("19p", {}, kind="uncertain")).stopped,
        )

    def test_affine_canonicalization_and_arithmetic(self):
        value = T.Affine(0x1_0000_0001, (("z", 2), ("a", 1), ("z", -2), ("a", -1)))
        self.assertEqual((value.constant, value.terms), (1, ()))
        self.assertEqual(T._affine(3, (("z", 1),)), T.Affine(3, (("z", 1),)))
        self.assertEqual(T._affine(3, ()), T.Const(3))
        receive = T.symbol("receive_buffer")
        self.assertEqual(
            T._subtract(T._add(receive, T.Const(4), "ignored"), T.Const(5), "ignored"),
            T.Affine(0xFFFFFFFF, (("receive_buffer", 1),)),
        )
        self.assertEqual(
            T._multiply(T.Const(2), T.symbol("track_index"), "ignored"),
            T.Affine(0, (("track_index", 2),)),
        )
        rejected = T._multiply(
            receive, T.symbol("track_index"), "receive_buffer * track_index"
        )
        self.assertIsInstance(rejected, T.Unknown)
        self.assertIn("non-affine", rejected.reason)
        with self.assertRaises(ValueError):
            T.symbol("not-valid")

    def test_affine_compute_and_memory_events(self):
        short = lambda opcode, rn, rx: {"compute[11:0]": (opcode << 8) | (rn << 4) | rx}
        state = T.State(1, {1: T.symbol("receive_buffer"), 2: T.Const(0x94)})
        state = self.run_one(state, insn("2c", short(0, 1, 2), 2))
        self.assertEqual(state.uregs[1], T.Affine(0x94, (("receive_buffer", 1),)))
        self.assertEqual(T._render(state.uregs[1]), "receive_buffer + 0x94")
        state.uregs[3] = T.symbol("track_index")
        state.uregs[4] = T.Const(2)
        full = {"compute[22:16]": 0x17, "compute[15:0]": 0x0534}
        state.uregs[5] = T._compute(full, False, state.uregs)[1]
        state = self.run_one(state, insn("2c", short(0, 1, 5), 2))
        self.assertEqual(
            T._render(state.uregs[1]),
            "receive_buffer + 2*track_index + 0x94",
        )
        store = {"i[2:0]": 1, "g": 0, "d": 1, "l": 1, "ureg[6:0]": 2, "data[6:0]": 0x14}
        event = self.run_one(
            T.State(1, {17: state.uregs[1], 2: T.Const(5)}), insn("15b", store)
        ).trace[0]
        self.assertEqual(event["expression"], "receive_buffer + 2*track_index + 0xa8")
        self.assertEqual(
            event["address"],
            {
                "affine": {
                    "constant": 0xA8,
                    "terms": [["receive_buffer", 1], ["track_index", 2]],
                }
            },
        )
        self.assertEqual(json.loads(json.dumps(event))["address"], event["address"])

    def test_affine_type19_and_seed_handling(self):
        f = {"g": 0, "idis[2:0]": 2, "is[2:0]": 1, "data[31:16]": 0, "data[15:0]": 0x94}
        state = self.run_one(
            T.State(1, {17: T.symbol("receive_buffer")}), insn("19a", f, 6)
        )
        self.assertEqual(T._render(state.uregs[19]), "receive_buffer + 0x94")
        seeded = T.trace(b"", 0, 0, {"R1": 7}, max_steps=1)[0]
        self.assertEqual(seeded.uregs[1], T.Const(7))
        symbolic = T.trace(b"", 0, 0, {"R1": "@receive_buffer"}, max_steps=1)[0]
        self.assertEqual(symbolic.uregs[1], T.symbol("receive_buffer"))
        with self.assertRaises(ValueError):
            T.trace(b"", 0, 0, {"R1": "@"}, max_steps=1)

    def test_scaled_type19_normal_word_modify_and_circular_wrap(self):
        fields = {
            "w": 1,
            "g": 0,
            "idis[2:0]": 0,
            "is[2:0]": 7,
            "data[31:16]": 0xFFFF,
            "data[15:0]": 0xFFFE,
        }
        i7 = T.UREG_CODES["I7"]
        b7 = T.UREG_CODES["B7"]
        l7 = T.UREG_CODES["L7"]

        byte_space = self.run_one(
            T.State(
                0xB893E2,
                {
                    i7: T.Const(0x26F7EE),
                    b7: T.Const(0x26F000),
                    l7: T.Const(0x1FD),
                },
                assume_nw32=True,
            ),
            insn("19a_scaled", fields, length=6),
        )
        self.assertEqual(byte_space.uregs[i7], T.Const(0x26F7E6))
        self.assertEqual(byte_space.uregs[b7], T.Const(0x26F000))
        self.assertEqual(byte_space.uregs[l7], T.Const(0x1FD))
        self.assertEqual(byte_space.trace[-1]["offset"], -8)

        normal_space = self.run_one(
            T.State(
                0x10,
                {i7: T.Const(0x100), b7: T.Const(0), l7: T.Const(0)},
            ),
            insn("19a_scaled", fields, length=6),
        )
        self.assertEqual(normal_space.uregs[i7], T.Const(0xFE))

        wrapped = self.run_one(
            T.State(
                0x10,
                {i7: T.Const(0x104), b7: T.Const(0x100), l7: T.Const(4)},
                assume_nw32=True,
            ),
            insn("19a_scaled", fields, length=6),
        )
        self.assertEqual(wrapped.uregs[i7], T.Const(0x10C))
        self.assertTrue(wrapped.trace[-1]["circular"])

    def test_cli_symbolic_seed(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            path = f.name
        try:
            valid = subprocess.run(
                [
                    sys.executable,
                    "tools/sharc_trace.py",
                    path,
                    "--base-sw",
                    "0",
                    "--start",
                    "0",
                    "--set",
                    "R1=@receive_buffer",
                    "--json",
                ],
                capture_output=True,
            )
            invalid = subprocess.run(
                [
                    sys.executable,
                    "tools/sharc_trace.py",
                    path,
                    "--base-sw",
                    "0",
                    "--start",
                    "0",
                    "--set",
                    "R1=@not-valid",
                ],
                capture_output=True,
            )
            invalid_register = subprocess.run(
                [
                    sys.executable,
                    "tools/sharc_trace.py",
                    path,
                    "--base-sw",
                    "0",
                    "--start",
                    "0",
                    "--set",
                    "BOGUS=1",
                ],
                capture_output=True,
            )
            self.assertEqual(valid.returncode, 0, valid.stderr.decode())
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("NAME=@symbol", invalid.stderr.decode())
            self.assertNotEqual(invalid_register.returncode, 0)
            self.assertNotIn("Traceback", invalid_register.stderr.decode())
        finally:
            os.unlink(path)

    def test_blob_backed_exact_pc_decode(self):
        pc = 0x20
        address = L.sw_to_byte(pc)
        rframe = bytes.fromhex("0119")
        full = bytes.fromhex("000f00000000")  # Confident 48-bit Type 17a.

        # The established flat-image API remains unchanged.
        self.assertEqual(T.decode_at(rframe, pc, pc).type_name, "25c_rframe")
        self.assertEqual(
            T.decode_at(
                loader_memory(loader_block(0, address, 6, payload=full)), None, pc
            ).type_name,
            "17a",
        )
        # Adjacent loader blocks are one contiguous decode window.
        self.assertEqual(
            T.decode_at(
                loader_memory(
                    loader_block(0, address, 4, payload=full[:4]),
                    loader_block(0, address + 4, 2, payload=full[4:]),
                ),
                None,
                pc,
            ).type_name,
            "17a",
        )
        # Trying smaller windows permits a valid 16-bit form at range end.
        self.assertEqual(
            T.decode_at(
                loader_memory(loader_block(0, address, 2, payload=rframe)), None, pc
            ).type_name,
            "25c_rframe",
        )

    def test_blob_backed_gap_truncation_and_overlap(self):
        pc = 0x30
        address = L.sw_to_byte(pc)
        truncated = T.decode_at(
            loader_memory(
                loader_block(0, address, 4, payload=bytes.fromhex("000f0000"))
            ),
            None,
            pc,
        )
        self.assertEqual(truncated.kind, "unknown")
        self.assertIn("17a (48 bits) but only 4 bytes remain", truncated.note)
        unmapped = T.decode_at(
            loader_memory(
                loader_block(0, address + 2, 2, payload=bytes.fromhex("0119"))
            ),
            None,
            pc,
        )
        self.assertEqual(unmapped.note, "PC unmapped in loader memory")
        # LoadedMemory's stream-order last-write rule is visible to decoding.
        overwritten = loader_memory(
            loader_block(0, address, 2, payload=bytes.fromhex("0119")),
            loader_block(0, address, 2, payload=bytes.fromhex("800a")),
        )
        self.assertEqual(T.decode_at(overwritten, None, pc).type_name, "11c")

    def test_blob_cli_validation_and_json(self):
        pc = 0x40
        address = L.sw_to_byte(pc)
        with tempfile.NamedTemporaryFile("wb", delete=False) as stream:
            stream.write(loader_block(0, address, 2, payload=bytes.fromhex("0119")))
            stream.write(loader_block(1 << L.BFLAGS["FINAL"], 0, 0))
            stream_path = stream.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as empty:
            empty.write(loader_block(1 << L.BFLAGS["FINAL"], 0, 0))
            empty_path = empty.name
        with tempfile.NamedTemporaryFile("w", delete=False) as trace_file:
            trace_path = trace_file.name
        try:
            command = [sys.executable, "tools/sharc_trace.py"]
            missing_base = subprocess.run(
                command + [stream_path, "--start", hex(pc)], capture_output=True
            )
            ambiguous = subprocess.run(
                command + [stream_path, "--blob", "--base-sw", "0", "--start", hex(pc)],
                capture_output=True,
            )
            no_ranges = subprocess.run(
                command + [empty_path, "--blob", "--start", hex(pc)],
                capture_output=True,
            )
            valid = subprocess.run(
                command + [stream_path, "--blob", "--start", hex(pc), "--json"],
                capture_output=True,
            )
            concrete = subprocess.run(
                command
                + [
                    stream_path,
                    "--blob",
                    "--start",
                    hex(pc),
                    "--concrete-memory",
                    "--dossier-bytes",
                    "4",
                    "--json",
                ],
                capture_output=True,
            )
            summary = subprocess.run(
                command
                + [
                    stream_path,
                    "--blob",
                    "--start",
                    hex(pc),
                    "--summary",
                    "--trace-json",
                    trace_path,
                ],
                capture_output=True,
            )
            unsafe = subprocess.run(
                command
                + [
                    stream_path,
                    "--base-sw",
                    "0",
                    "--start",
                    hex(pc),
                    "--concrete-memory",
                ],
                capture_output=True,
            )
            self.assertNotEqual(missing_base.returncode, 0)
            self.assertIn("--base-sw is required", missing_base.stderr.decode())
            self.assertNotEqual(ambiguous.returncode, 0)
            self.assertIn("ambiguous", ambiguous.stderr.decode())
            self.assertNotEqual(no_ranges.returncode, 0)
            self.assertIn("no loaded ranges", no_ranges.stderr.decode())
            self.assertEqual(valid.returncode, 0, valid.stderr.decode())
            self.assertEqual(concrete.returncode, 0, concrete.stderr.decode())
            self.assertEqual(summary.returncode, 0, summary.stderr.decode())
            self.assertNotEqual(unsafe.returncode, 0)
            self.assertIn("requires --blob", unsafe.stderr.decode())
            self.assertNotIn("Traceback", valid.stderr.decode())
            self.assertNotIn("raw", valid.stdout.decode())
            json.loads(valid.stdout)
            summary_result = json.loads(summary.stdout)
            self.assertEqual(summary_result["start_sw"], pc)
            self.assertEqual(len(summary_result["states"]), 1)
            with open(trace_path) as trace_input:
                self.assertEqual(len(json.load(trace_input)), 1)
        finally:
            os.unlink(stream_path)
            os.unlink(empty_path)
            os.unlink(trace_path)

    def test_concrete_loader_reads_and_forked_write_overlays(self):
        # Loader memory is keyed at the alias, while application DM code uses
        # the unaliased address.  Later overlapping loader data still wins.
        address = L.SW_ALIAS_BASE + 0x100
        memory = loader_memory(
            loader_block(1, address, 4, payload=b"\x11\x22\x33\x44"),
            loader_block(1, address + 2, 2, payload=b"\xaa\xbb"),
        )
        self.assertIsNone(T._dm_read(T.State(1, concrete=memory), 0x100, 4))
        self.assertEqual(
            T._dm_read(T.State(1, concrete=memory), 0x100, 1), T.Const(0x11)
        )
        state = T.State(1, {0: T.Const(0x100)}, concrete=memory, assume_nw32=True)
        load = insn(
            "14a",
            {
                "l": 0,
                "addr[31:16]": 0,
                "addr[15:0]": 0x100,
                "ureg[6:0]": 1,
                "g": 0,
                "d": 0,
            },
            6,
        )
        loaded = self.run_one(state, load)
        self.assertEqual(loaded.uregs[1], T.Const(0xBBAA2211))
        left, right = T._copy(loaded), T._copy(loaded)
        self.assertTrue(T._dm_write(left, 0x100, 4, T.Const(0x01020304)))
        self.assertEqual(T._dm_read(left, 0x100, 4), T.Const(0x01020304))
        self.assertEqual(T._dm_read(right, 0x100, 4), T.Const(0xBBAA2211))
        self.assertTrue(T._dm_write(left, 0x200, 4, T.Const(0x55667788)))
        self.assertEqual(T._dm_read(left, 0x200, 4), T.Const(0x55667788))
        self.assertTrue(T._dm_write(left, 0x310CA300, 4, T.Const(0x11223344)))
        self.assertEqual(T._dm_read(left, 0x310CA300, 4), T.Const(0x11223344))

    def test_trace_real_return_idiom_and_external_dossier_modes(self):
        # The return is real decoder-backed firmware syntax: Type9b_abs raw
        # 0x083f343f, a normal delay slot, then Type25c_rframe raw 0x1901.
        start, target = 0x100, 0x110
        call = encode("25a_direct", target)
        # Two 16-bit slots end at start+5, while delayed CALL must return to
        # the architectural start+7 rather than to the byte after slot two.
        slot = bytes.fromhex("f29f")
        return_branch = struct.pack("<HH", 0x083F, 0x343F)
        rframe = struct.pack("<H", 0x1901)
        payload = bytearray((target - start + 5) * 2)
        payload[: len(call)] = call
        payload[len(call) : len(call) + len(slot)] = slot
        payload[len(call) + len(slot) : len(call) + 2 * len(slot)] = slot
        offset = (target - start) * 2
        payload[offset : offset + 4] = return_branch
        payload[offset + 4 : offset + 4 + len(slot)] = slot
        payload[offset + 4 + len(slot) : offset + 4 + len(slot) + 2] = rframe
        memory = loader_memory(
            loader_block(1, L.sw_to_byte(start), len(payload), payload=bytes(payload)),
            loader_block(1, L.SW_ALIAS_BASE + 0x300, 4, payload=b"\0" * 4),
        )
        self.assertEqual(T.decode_at(memory, None, target).type_name, "9b_abs")
        self.assertEqual(T.decode_at(memory, None, target + 3).type_name, "25c_rframe")
        returned = T.trace(
            memory,
            None,
            start,
            max_steps=6,
            concrete_memory=True,
            follow_loaded_calls=True,
        )[0]
        actions = [event["action"] for event in returned.trace]
        self.assertIn("loaded-call-enter", actions)
        self.assertIn("return-branch", actions)
        self.assertIn("loaded-call-return", actions)
        self.assertEqual(returned.pc_sw, start + 7)

        stopped = T.trace(
            memory,
            None,
            start,
            {"I0": 0x300},
            max_steps=10,
            concrete_memory=True,
            dossier_bytes=4,
        )[0]
        continued = T.trace(
            memory,
            None,
            start,
            {"I0": 0x300},
            max_steps=10,
            concrete_memory=True,
            continue_external_calls=True,
            dossier_bytes=4,
        )[0]
        self.assertEqual(stopped.stopped, "external-call")
        self.assertEqual(stopped.trace[-1]["objects"][0]["bytes"], [0, 0, 0, 0])
        self.assertIn(
            "opaque-external-call", [event["action"] for event in continued.trace]
        )
        self.assertIsInstance(continued.uregs[0], T.Unknown)

    def test_trace_executes_scaled_type19_loaded_entry(self):
        start = 0x10
        payload = bytes.fromhex("8715fffffeff")
        memory = loader_memory(
            loader_block(1, L.sw_to_byte(start), len(payload), payload=payload)
        )
        state = T.trace(
            memory,
            None,
            start,
            {"I7": 0x26F7EE, "B7": 0x26F000, "L7": 0x1FD},
            max_steps=1,
            concrete_memory=True,
            assume_nw32=True,
        )[0]
        self.assertEqual(state.uregs[T.UREG_CODES["I7"]], T.Const(0x26F7E6))
        self.assertEqual(state.trace[-2]["action"], "i-add")

    def test_trace_can_seed_documented_core_reset_state(self):
        start = 0x10
        memory = loader_memory(
            loader_block(1, L.sw_to_byte(start), 2, payload=bytes.fromhex("f29f"))
        )
        state = T.trace(
            memory,
            None,
            start,
            {"MODE1": 5},
            max_steps=0,
            concrete_memory=True,
            core_reset_state=True,
        )[0]
        self.assertEqual(state.uregs[T.UREG_CODES["MODE1"]], T.Const(5))
        self.assertEqual(state.uregs[T.UREG_CODES["MMASK"]], T.Const(0))
        self.assertEqual(T._dm_read(state, T.Const(0x31400), 4), T.Const(0))
        self.assertTrue(state.core_reset_state)

    def test_event_values_are_json_safe(self):
        type3c = {"dmi[2:0]": 0, "dmm[2:0]": 0, "d": 1, "dreg[3:0]": 3}
        s = self.run_one(
            T.State(1, {16: T.Const(0x80), 32: T.Const(3)}), insn("3c", type3c, 2)
        )
        self.assertEqual(s.trace[0]["value"], {"unknown": "uninitialized R3"})
        encoded = json.dumps(s.trace)
        self.assertIn('"unknown": "uninitialized R3"', encoded)
        self.assertNotIn("b'", encoded)

    def test_runtime_summary_keeps_only_named_peripheral_accesses(self):
        state = T.State(0x20, steps=7, stopped="test-stop")
        state.trace = [
            {
                "pc_sw": 0x10,
                "form": "14a",
                "action": "store",
                "address": 0x100,
                "value": 1,
            },
            {
                "pc_sw": 0x13,
                "form": "12a_imm",
                "action": "loop-setup",
                "start_sw": 0x16,
                "end_sw": 0x16,
                "count": 4,
                "mode": 1,
            },
            {
                "pc_sw": 0x16,
                "form": "14a",
                "action": "store",
                "address": 0x310CA300,
                "value": 0x1234,
                "access_width": "normal-word",
            },
            {
                "pc_sw": 0x19,
                "form": "test_form",
                "action": "stop",
                "reason": "test-stop",
            },
        ]
        summary = T.summarize([state], 0x10)
        item = summary["states"][0]
        self.assertEqual(summary["start_sw"], 0x10)
        self.assertEqual(item["stop_pc_sw"], 0x19)
        self.assertEqual(item["stop_form"], "test_form")
        self.assertEqual(item["loop_setups"][0]["count"], 4)
        self.assertEqual(
            item["peripheral_accesses"],
            [
                {
                    "pc_sw": 0x16,
                    "action": "store",
                    "address": 0x310CA300,
                    "peripheral": "PCG0_CTLC0",
                    "value": 0x1234,
                    "access_width": "normal-word",
                }
            ],
        )

    def test_bounds_and_json_has_no_raw_bytes(self):
        data = b"\x00\x00"
        self.assertEqual(T.trace(data, 0, 0, max_steps=0)[0].stopped, "max-steps")
        with self.assertRaisesRegex(ValueError, "max_states must be between"):
            T.trace(data, 0, 0, max_states=0)
        branch = insn(
            "8a_abs",
            {"b": 0, "j": 0, "cond[4:0]": 1, "addr[23:16]": 0, "addr[15:0]": 20},
            6,
        )
        with patch("sharc_trace.decode_at", return_value=branch):
            self.assertIn(
                "max-states", [s.stopped for s in T.trace(b"", 0, 0, max_states=1)]
            )
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            out = subprocess.check_output(
                [
                    sys.executable,
                    "tools/sharc_trace.py",
                    path,
                    "--base-sw",
                    "0",
                    "--start",
                    "0",
                    "--json",
                ]
            )
            self.assertNotIn("raw", out.decode())
            json.loads(out)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
