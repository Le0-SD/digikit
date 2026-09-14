"""Pure decoding helpers of emu/uitrace.py (no emulator needed)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from emu import uitrace


class DescribeFlags(unittest.TestCase):
    def test_known_bits(self):
        self.assertEqual(uitrace.describe_flags(0x01), 'press')
        self.assertEqual(uitrace.describe_flags(0x03), 'press|chord')
        self.assertEqual(uitrace.describe_flags(0x0b), 'press|chord|repeat')
        self.assertEqual(uitrace.describe_flags(0x12), 'chord|release')

    def test_unknown_bits_and_zero(self):
        self.assertEqual(uitrace.describe_flags(0x2b),
                         'press|chord|repeat|+0x20')
        self.assertEqual(uitrace.describe_flags(0x00), '-')


class ItaniumName(unittest.TestCase):
    def test_length_prefixed(self):
        self.assertEqual(uitrace.itanium_name('20MachineSelectionView'),
                         'MachineSelectionView')
        self.assertEqual(uitrace.itanium_name('8KeyEvent'), 'KeyEvent')

    def test_other_forms_unchanged(self):
        self.assertEqual(uitrace.itanium_name('N3elk4ViewE'), 'N3elk4ViewE')
        self.assertEqual(uitrace.itanium_name('123'), '123')
        self.assertEqual(uitrace.itanium_name(''), '')


class DescribeItem(unittest.TestCase):
    def test_key_record(self):
        record = bytes.fromhex('00000000' '00000002' '00000003' '0000abcd')
        self.assertEqual(uitrace.describe_item(record, lambda code: 'SRC'),
                         'SRC(2) 0x03 press|chord ts=0xabcd')
        self.assertEqual(uitrace.describe_item(record),
                         'code(2) 0x03 press|chord ts=0xabcd')

    def test_other_record_and_unreadable(self):
        record = bytes.fromhex('05466e63' '00000000' '00000000' '00000000')
        self.assertEqual(uitrace.describe_item(record),
                         'type=5 05466e63000000000000000000000000')
        self.assertEqual(uitrace.describe_item(None), 'unreadable')


if __name__ == '__main__':
    unittest.main()
