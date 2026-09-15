"""tools/sharcframe.py frame comparison (capture needs a snapshot)."""

import argparse
import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

import sharcframe  # noqa: E402


class RangesTest(unittest.TestCase):
    def test_differing_ranges(self):
        self.assertEqual(list(sharcframe.ranges(b'abcdef', b'abXdYf')), [(2, 3), (4, 5)])

    def test_length_difference(self):
        self.assertEqual(list(sharcframe.ranges(b'ab', b'abcd')), [(2, 4)])

    def test_parse_poke(self):
        self.assertEqual(sharcframe.parse_poke('0x4094e4f4=0'), (0x4094e4f4, bytes(4)))
        self.assertEqual(sharcframe.parse_poke('0x10=0x12345678'), (0x10, bytes.fromhex('12345678')))

    def test_parse_poke_needs_a_value(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            sharcframe.parse_poke('0x4094e4f4')


if __name__ == '__main__':
    unittest.main()
