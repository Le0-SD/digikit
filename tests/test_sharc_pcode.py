"""The p-code of the generated SHARC+ language, and tools/sharcpcode.py.

Generates the language from decode_table.json in a temporary directory,
compiles it with the sleigh compiler bundled with pypcode, and lifts
hand-encoded instructions. Needs no firmware and no Ghidra."""

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

import sharc_disasm  # noqa: E402
import sharc_visa_tables as T  # noqa: E402
import sharcpcode  # noqa: E402
from test_sharc_disasm import encode  # noqa: E402

TARGET_SW = 0x1C1400
COND_EQ = 0x00


def have_pypcode():
    try:
        import pypcode  # noqa: F401
    except ImportError:
        return False
    return True


def field(name, label, value):
    """-> the bits that put value into field `label` of form `name`."""
    hi, lo = T.get_type(name)['fields'][label]
    return (value & ((1 << (hi - lo + 1)) - 1)) << lo


def branch(name, cond=None, b=None, target=None):
    """-> bytes of a form-`name` branch with the given cond, b bit and absolute target."""
    extra = 0
    if cond is not None:
        extra |= field(name, 'cond[4:0]', cond)
    if b is not None:
        extra |= field(name, 'b', b)
    if target is not None:
        extra |= field(name, 'addr[23:16]', target >> 16) | field(name, 'addr[15:0]', target)
    return encode(name, extra)


@unittest.skipUnless(have_pypcode(), 'needs pypcode (pyproject.toml)')
class GeneratedLanguage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='sharcpcode-')
        spec = os.path.join(cls.tmp, 'sharcspec')
        shutil.copytree(os.path.join(sharcpcode.TOOLS, 'sharcspec'), spec,
                        ignore=shutil.ignore_patterns('SHARC_VISA', '__pycache__'))
        subprocess.run([sys.executable, os.path.join(spec, 'ghidra', 'gen_sleigh.py')],
                       check=True, capture_output=True)
        src = os.path.join(spec, 'ghidra', 'SHARC_VISA', 'data', 'languages')
        cls.lint, ldefs = sharcpcode.build_language(
            src, os.path.join(cls.tmp, 'lang'), sharcpcode.find_sleigh(prefer_ghidra=False))
        cls.ctx = sharcpcode.load_context(ldefs) if cls.lint['compile']['returncode'] == 0 else None

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        if self.ctx is None:
            self.fail('the generated language does not compile: %s' % self.lint)

    def lift(self, buf, sw=0x1000):
        length, ops = sharcpcode.lift_one(self.ctx, buf, 2 * sw)
        self.assertIsNotNone(length, 'the language does not decode %s' % buf.hex())
        return [op.opcode.name for op in ops], ops

    def test_compiles_without_bad_pcode(self):
        """No errors, pattern conflicts, unnecessary extensions, dead or colliding temporaries."""
        self.assertEqual(self.lint['returncode'], 0, self.lint)
        bad = {k: v for k, v in self.lint['counts'].items() if k in sharcpcode.REGRESSING_LINT}
        self.assertEqual(bad, {}, self.lint['examples'])

    def test_every_form_has_our_decoders_length(self):
        """Each form, encoded with only its fixed bits, has the length tools/sharc_disasm.py gives it.
        Branch forms change here on purpose once delay slots join the branch (handover stage 3)."""
        missing, wrong = [], []
        for name in sorted(t['name'] for t in T.TYPES):
            buf = encode(name)
            ours = next(iter(sharc_disasm.disassemble(buf, count=1)), None)
            if ours is None or ours.type_name != name:
                continue
            length, _ = sharcpcode.lift_one(self.ctx, buf, 0x2000)
            if length is None:
                missing.append(name)
            elif length != ours.length_bytes:
                wrong.append((name, length, ours.length_bytes))
        self.assertEqual(wrong, [])
        self.assertEqual(missing, [])

    def test_unconditional_jump_and_call(self):
        for name, b, opname in (('8a_abs', 0, 'BRANCH'), ('8a_abs', 1, 'CALL')):
            with self.subTest(name=name, b=b):
                names, ops = self.lift(branch(name, cond=sharcpcode.COND_TRUE, b=b, target=TARGET_SW))
                self.assertIn(opname, names)
                self.assertEqual(ops[names.index(opname)].inputs[0].offset, 2 * TARGET_SW)
        names, ops = self.lift(branch('25a_direct', target=TARGET_SW))
        self.assertEqual(names, ['CALL'])
        self.assertEqual(ops[0].inputs[0].offset, 2 * TARGET_SW)

    def test_conditional_flow_falls_through(self):
        """A jump, call or return whose condition is not TRUE keeps a fall-through."""
        cases = {
            '8a_abs jump': branch('8a_abs', cond=COND_EQ, b=0, target=TARGET_SW),
            '8a_abs call': branch('8a_abs', cond=COND_EQ, b=1, target=TARGET_SW),
            '8a_rel jump': branch('8a_rel', cond=COND_EQ, b=0),
            '9b_abs jump': branch('9b_abs', cond=COND_EQ, b=0),
            '11a return': branch('11a', cond=COND_EQ),
            '11c return': branch('11c', cond=COND_EQ),
        }
        for label, buf in cases.items():
            with self.subTest(label):
                names, _ = self.lift(buf)
                self.assertIn('CALLOTHER', names)
                self.assertIn('CBRANCH', names)
                self.assertFalse(sharcpcode.lifts_without_fallthrough(names))

    def test_conditional_jump_branches_to_its_target(self):
        names, ops = self.lift(branch('8a_abs', cond=COND_EQ, b=0, target=TARGET_SW))
        self.assertNotIn('BRANCH', names)
        self.assertEqual(ops[names.index('CBRANCH')].inputs[0].offset, 2 * TARGET_SW)

    def test_true_condition_stays_unconditional(self):
        """With cond TRUE there is no condition and no fall-through."""
        cases = {
            '8a_abs jump': branch('8a_abs', cond=sharcpcode.COND_TRUE, b=0, target=TARGET_SW),
            '8a_rel jump': branch('8a_rel', cond=sharcpcode.COND_TRUE, b=0),
            '9b_abs jump': branch('9b_abs', cond=sharcpcode.COND_TRUE, b=0),
            '11a return': branch('11a', cond=sharcpcode.COND_TRUE),
            '11c return': branch('11c', cond=sharcpcode.COND_TRUE),
        }
        for label, buf in cases.items():
            with self.subTest(label):
                names, _ = self.lift(buf)
                self.assertNotIn('CALLOTHER', names)
                self.assertTrue(sharcpcode.lifts_without_fallthrough(names))

    def test_lift_region_counts(self):
        jump_eq = branch('8a_abs', cond=COND_EQ, b=0, target=TARGET_SW)
        call = branch('8a_abs', cond=sharcpcode.COND_TRUE, b=1, target=TARGET_SW)
        data = encode('17b') + jump_eq + call + encode('17b')
        r = sharcpcode.lift_region(self.ctx, data, 0x1000, min_depth=1)
        self.assertEqual((r['aligned'], r['decoded']), (4, 4))
        self.assertEqual(r['length_mismatch'], {})
        self.assertEqual(r['forms']['8a_abs']['n'], 2)
        self.assertEqual(r['forms']['17b']['n'], 2)
        expected = int(sharcpcode.lifts_without_fallthrough(self.lift(jump_eq)[0]))
        self.assertEqual(sharcpcode._total(r['conditional_without_fallthrough']), expected)


def image_record(**lift):
    rec = {'region_sha256': 'a', 'lift': {
        'aligned': 10, 'decoded': 10, 'undecoded': {}, 'length_mismatch': {},
        'conditional_without_fallthrough': {}, 'forms': {}, 'ops_total': 0,
        'instructions_per_second': 1000}}
    rec['lift'].update(lift)
    return rec


class Compare(unittest.TestCase):

    def test_same_run_has_no_regression(self):
        self.assertEqual(sharcpcode.compare_image(image_record(), image_record(), 0.25)[0], [])

    def test_fewer_decoded_instructions(self):
        reg, _ = sharcpcode.compare_image(image_record(), image_record(decoded=9), 0.25)
        self.assertEqual(len(reg), 1)

    def test_new_conditional_flow_without_fallthrough(self):
        new = image_record(conditional_without_fallthrough={'11c': {'count': 2, 'examples': []}})
        reg, _ = sharcpcode.compare_image(image_record(), new, 0.25)
        self.assertEqual(len(reg), 1)

    def test_slower_lifting_beyond_tolerance(self):
        reg, _ = sharcpcode.compare_image(image_record(), image_record(instructions_per_second=700), 0.25)
        self.assertEqual(len(reg), 1)
        reg, notes = sharcpcode.compare_image(image_record(), image_record(instructions_per_second=900), 0.25)
        self.assertEqual(reg, [])

    def test_different_image_counts_are_notes(self):
        new = image_record(decoded=5)
        new['region_sha256'] = 'b'
        self.assertEqual(sharcpcode.compare_image(image_record(), new, 0.25)[0], [])

    def test_probe_that_stops_passing(self):
        g = {'probes': [{'name': 'p', 'ok': True, 'instructions': 3}], 'decompile_failed': {}}
        old, new = image_record(), image_record()
        old['ghidra'] = g
        new['ghidra'] = dict(g, probes=[{'name': 'p', 'ok': False, 'instructions': 3}])
        reg, _ = sharcpcode.compare_image(old, new, 0.25)
        self.assertEqual(reg, ['probe "p" stopped passing'])

    def test_lint_regressions(self):
        old = {'compiler': 'pypcode', 'returncode': 0, 'compile': {'returncode': 0},
               'counts': {'nop': 47}, 'slaspec_sha256': 'x'}
        new = dict(old, counts={'nop': 40, 'dead_temp': 1}, slaspec_sha256='y')
        reg, notes = sharcpcode.compare_lint(old, new, 0.25)
        self.assertEqual(reg, ['dead_temp 0 -> 1'])
        self.assertIn('nop 47 -> 40', notes)


class Dump(unittest.TestCase):

    def test_field_value_assembles_and_sign_extends(self):
        self.assertEqual(sharcpcode.field_value({'addr[23:16]': 0x1c, 'addr[15:0]': 0x1400}, 'addr'), 0x1C1400)
        self.assertEqual(sharcpcode.field_value({'reladdr[5:5]': 1, 'reladdr[4:0]': 0x1f}, 'reladdr', signed=True), -1)
        self.assertEqual(sharcpcode.field_value({'cond[4:0]': 8}, 'cond'), 8)
        self.assertIsNone(sharcpcode.field_value({'b': 1}, 'addr'))

    def test_decoder_rows(self):
        data = encode('17b') + branch('8a_abs', cond=sharcpcode.COND_TRUE, b=0, target=0x1002) + encode('17b')
        db = sqlite3.connect(':memory:')
        db.executescript(sharcpcode.SCHEMA)
        sharcpcode.write_decoder(db, None, data, 0x1000, min_depth=1)
        rows = dict(db.execute('SELECT sw, form FROM decoder WHERE aligned = 1'))
        self.assertEqual(rows, {0x1000: '17b', 0x1002: '8a_abs', 0x1005: '17b'})
        target, target_aligned, cond = db.execute(
            'SELECT target_sw, target_aligned, cond FROM decoder WHERE sw = 0x1002').fetchone()
        self.assertEqual((target, target_aligned, cond), (0x1002, 1, sharcpcode.COND_TRUE))


if __name__ == '__main__':
    unittest.main()
