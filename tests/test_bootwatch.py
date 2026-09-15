"""tools/bootwatch.py argument parsing (the watch needs a cold boot)."""

import argparse
import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

import bootwatch  # noqa: E402


class ParseWatchTest(unittest.TestCase):
    def test_full(self):
        self.assertEqual(bootwatch.parse_watch('0x409664f4:4=gate'), (0x409664f4, 4, 'gate'))

    def test_defaults(self):
        self.assertEqual(bootwatch.parse_watch('0x409664f4'), (0x409664f4, 4, '0x409664f4'))

    def test_bad(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            bootwatch.parse_watch('gate')


if __name__ == '__main__':
    unittest.main()
