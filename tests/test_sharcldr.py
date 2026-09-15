"""tools/sharcldr.py main_program() on a hand-built boot stream."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

import sharcldr  # noqa: E402


def block(code, addr, count, arg=0, payload=b''):
    """-> a 16-byte header whose bytes XOR to zero, then the payload."""
    hdr = bytearray(struct.pack('<IIII', code, addr, count, arg))
    hdr[3] = 0
    x = 0
    for b in hdr:
        x ^= b
    hdr[3] = x
    return bytes(hdr) + payload


class MainProgramTest(unittest.TestCase):
    def test_contiguous_run_with_fill(self):
        first = 1 << sharcldr.BFLAGS['FIRST']
        fill = 1 << sharcldr.FILL_BIT
        base = sharcldr.sw_to_byte(0x100)
        data = (block(first, 0x100, 0)
                + block(0, base, 4, payload=b'\x01\x02\x03\x04')
                + block(fill, base + 4, 6, arg=0x11223344)
                + block(0, base + 10, 2, payload=b'\xaa\xbb')
                + block(0, base + 100, 2, payload=b'\xcc\xdd'))
        blocks = sharcldr.parse_blocks(data)
        self.assertEqual(len(blocks), 5)
        addr, code, used = sharcldr.main_program(data, blocks)
        self.assertEqual(addr, base)
        self.assertEqual(code, bytes.fromhex('01020304' '443322114433' 'aabb'))
        self.assertEqual(used, [1, 2, 3])

    def test_no_entry(self):
        data = block(0, 0x28000000, 2, payload=b'\x00\x00')
        self.assertEqual(sharcldr.main_program(data, sharcldr.parse_blocks(data)), (None, b'', []))


if __name__ == '__main__':
    unittest.main()
