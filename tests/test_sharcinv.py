"""tools/sharcinv.py: boundaries, feature vectors and labels on synthetic code.

No real firmware is used (it is Elektron's copyright and is not committed);
words are built directly from tools/sharc_visa_tables.py, the same way
tests/test_sharcflow.py builds calls and returns.
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

import sharc_visa_tables as T  # noqa: E402
import sharcflow  # noqa: E402
import sharcinv  # noqa: E402
from test_sharc_disasm import encode  # noqa: E402
from test_sharcflow import cjump, load, push3c, store, words  # noqa: E402


def compute23(name, field23):
    """A `name` instruction (2a/2a_short/... ) with its 23-bit compute field
    (bits 22:0 of compute[22:16]/compute[15:0]) set to `field23`, the fixed
    bits from the opcode table otherwise -- put() in test_sharcflow.py can't
    place a value that's split across two field chunks, so this does it by
    hand from each chunk's (hi, lo)."""
    t = T.get_type(name)
    insn = t['opcode_value']
    for label, (hi, lo) in t['fields'].items():
        if label.split('[')[0] != 'compute':
            continue
        chi, clo = label[label.index('[') + 1:-1].split(':')
        chunk = (field23 >> int(clo)) & ((1 << (int(chi) - int(clo) + 1)) - 1)
        insn |= chunk << lo
    nwords = t['bits'] // 16
    ws = [(insn >> (t['bits'] - 16 * (i + 1))) & 0xFFFF for i in range(nwords)]
    return struct.pack('<%dH' % nwords, *ws)


def rframe():
    return encode('25c_rframe')


def ret():
    """9b_abs return jump (raw 0x083F343F), split into its two 16-bit words."""
    return words(sharcinv.RETURN_JUMP >> 16, sharcinv.RETURN_JUMP & 0xFFFF)


DUAL_ADD_SUB_FIXED = (0x7 << 16) | (0xA << 12) | (0x1 << 8) | (0x2 << 4) | 0x3
# cu=0 (bits 22:20 = 000), opcode[19:16]=0111 (dual add/sub, fixed),
# opcode[15:12]=Rs=0xA, Ra(rn)=1, Rx=2, Ry=3 -- PRM Table 18-10.


class BoundariesTest(unittest.TestCase):
    def _block(self, data, base_sw, min_depth=1):
        sites = sharcflow.find_sites(data, base_sw, min_depth)
        insns = sharcflow.aligned(data, min_depth)
        block = {'base_sw': base_sw, 'sites': sites, 'insns': insns}
        block['_insn_sw'] = [base_sw + off // 2 for off, _ in insns]
        return block

    def test_two_functions_split_at_the_return(self):
        # fn A: a call, then a return with its delay slots
        # fn B: one dual add/subtract compute op, then a return
        data = (cjump(0x2000) + push3c() + store(0x1007)
                + ret() + load(0, 0) + rframe()
                + compute23('2a_short', DUAL_ADD_SUB_FIXED) + ret() + load(0, 0) + rframe())
        block = self._block(data, 0x1000)
        spans = sharcinv.function_bounds(block)
        self.assertEqual(len(spans), 2)
        (a_entry, a_exit), (b_entry, b_exit) = spans
        self.assertEqual(a_entry, 0x1000)
        self.assertEqual(b_entry, a_exit)

        b_insns = sharcinv.instructions_in(block, b_entry, b_exit)
        v = sharcinv.compute_vector(b_insns, {}, {})
        self.assertEqual(v['dual_add_sub'], 1)
        self.assertEqual(v['int_alu'], 0)
        self.assertEqual(v['float_alu'], 0)

        fv = sharcinv.finalize_vector(v)
        label, conf, reasons = sharcinv.label_function(fv, len(b_insns), 0, 0, True)
        self.assertEqual(label, 'FFT-like (dual add/subtract)')
        self.assertTrue(reasons)

    def test_call_target_inside_a_span_splits_it(self):
        # One return-delimited span containing two calls: one to an address
        # inside itself (should split it), one further out (should not).
        inner_target = 0x1006  # lands right after the two calls below
        outer_target = 0x9000
        data = (cjump(inner_target) + push3c() + store(0x1007)
                + cjump(outer_target) + push3c() + store(0x100A)
                + load(0, 0) + ret() + load(0, 0) + rframe())
        block = self._block(data, 0x1000)
        spans = sharcinv.function_bounds(block)
        entries = [e for e, _ in spans]
        self.assertIn(inner_target, entries)


class ComputeClassifyTest(unittest.TestCase):
    def test_plain_integer_add(self):
        field = (0 << 20) | (0x01 << 12) | (1 << 8) | (2 << 4) | 3  # RN=RX+RY
        cu, d = sharcinv.classify_compute(field)
        self.assertEqual(cu, 'ALU')
        self.assertFalse(d['is_float'])
        self.assertNotIn('is_dual_addsub', d)

    def test_float_add(self):
        field = (0 << 20) | (0x81 << 12)  # FN = FX + FY
        cu, d = sharcinv.classify_compute(field)
        self.assertEqual(cu, 'ALU')
        self.assertTrue(d['is_float'])

    def test_dual_add_subtract_fixed(self):
        cu, d = sharcinv.classify_compute(DUAL_ADD_SUB_FIXED)
        self.assertEqual(cu, 'ALU')
        self.assertTrue(d['is_dual_addsub'])
        self.assertFalse(d['is_float'])

    def test_dual_add_subtract_float(self):
        field = (0xF << 16) | (0xA << 12) | (1 << 8) | (2 << 4) | 3
        cu, d = sharcinv.classify_compute(field)
        self.assertEqual(cu, 'ALU')
        self.assertTrue(d['is_dual_addsub'])
        self.assertTrue(d['is_float'])

    def test_mac_accumulate(self):
        # cu=1 (MULT), top2=2 ("acc + RX*RY"), signed/int -> a MAC
        opcode = (2 << 6) | (0 << 3) | 0  # top2=10, F=0
        field = (1 << 20) | (opcode << 12)
        cu, d = sharcinv.classify_compute(field)
        self.assertEqual(cu, 'MULT')
        self.assertTrue(d['is_mac'])

    def test_multifunction_mul_dual_addsub(self):
        field = (6 << 20)  # bits[22:20]=110: MUL + dual add/subtract, fixed
        cu, d = sharcinv.classify_compute(field)
        self.assertEqual(cu, 'MULTIFN')
        self.assertTrue(d['is_mac'])
        self.assertTrue(d['is_dual_addsub'])
        self.assertFalse(d['is_float'])

    def test_zero_field_is_no_compute(self):
        self.assertEqual(sharcinv.classify_compute(0), (None, {}))


class FieldMergeTest(unittest.TestCase):
    def test_merges_split_fields(self):
        merged = sharcinv.merge_fields({'data[31:16]': 0x1234, 'data[15:0]': 0x5678, 'g': 1})
        self.assertEqual(merged, {'data': 0x12345678, 'g': 1})

    def test_float32_bit_pattern(self):
        self.assertAlmostEqual(sharcinv.float32(0x3F800000), 1.0)


class LiteralRegionTest(unittest.TestCase):
    def test_named_table(self):
        self.assertEqual(sharcinv.classify_literal(0x8055C440), 'named:cosine_a')

    def test_param_frame(self):
        self.assertEqual(sharcinv.classify_literal(0x2559000), 'other')  # out of range on purpose
        self.assertEqual(sharcinv.classify_literal(0x255900), 'param_frame')

    def test_audio_ring(self):
        self.assertEqual(sharcinv.classify_literal(0x262138), 'audio_ring')

    def test_external_table_space(self):
        self.assertEqual(sharcinv.classify_literal(0x80123456), 'external_0x80xxxxxx')

    def test_generic_dm(self):
        self.assertEqual(sharcinv.classify_literal(0x210000), 'dm_0x2xxxxx')


class SwBaseTest(unittest.TestCase):
    def test_alias_window(self):
        self.assertEqual(sharcinv.sw_base_for_target(0x282403F0), 0x1201F8)

    def test_l2_window(self):
        self.assertEqual(sharcinv.sw_base_for_target(0x20000000), sharcinv.L2_SW_BASE)

    def test_outside_any_window(self):
        self.assertIsNone(sharcinv.sw_base_for_target(0x10000000))


if __name__ == '__main__':
    unittest.main()
