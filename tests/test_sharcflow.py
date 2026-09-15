"""tools/sharcflow.py call and return recognition (the Ghidra pass needs a project)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

import sharcflow  # noqa: E402
from test_sharc_disasm import encode  # noqa: E402
from test_sharcimm import put  # noqa: E402


def words(*ws):
    return struct.pack('<%dH' % len(ws), *ws)


def store(value):
    return encode('16a', put('16a', **{'i[2:0]': 7, 'm[2:0]': 7, 'data[31:16]': value >> 16,
                                       'data[15:0]': value & 0xFFFF}))


def load(ureg, value):
    return encode('17b', put('17b', **{'ureg[6:0]': ureg, 'data[15:0]': value}))


def goto(target):
    return encode('25a_direct', put('25a_direct', **{'addr[23:16]': target >> 16,
                                                     'addr[15:0]': target & 0xFFFF}))


class SitesTest(unittest.TestCase):
    def test_calls_gotos_returns(self):
        base = 0x1000
        # SW 0x1000 push, 0x1001 store, 0x1004 goto: a strict triple
        # SW 0x1007 push, 0x1008 store, 0x100b load R4, 0x100d goto: argument between
        # SW 0x1010 goto without a store; SW 0x1013 return jump, 0x1015 rframe
        data = (words(0x9FF2) + store(0x1003) + goto(0x2000)
                + words(0x9FF2) + store(0x100A) + load(4, 0xABC) + goto(0x3000)
                + goto(0x4000)
                + words(0x083F, 0x343F) + words(0x1901))
        sites = sharcflow.find_sites(data, base, lookback=3, min_depth=1)
        self.assertEqual([(c['sw'], c['target'], c['store_sw'], c['delta'], c['between'], c['strict'])
                          for c in sites['calls']],
                         [(0x1004, 0x2000, 0x1001, 1, 0, True),
                          (0x100D, 0x3000, 0x1008, 3, 1, False)])
        self.assertTrue(sites['calls'][1]['push'])
        self.assertEqual(sites['gotos'], [{'sw': 0x1010, 'target': 0x4000}])
        self.assertEqual(sites['returns'], [{'sw': 0x1013, 'rframe_sw': 0x1015}])

    def test_store_must_hold_its_address_plus_2(self):
        # SW 0x1000 stores a constant, not 0x1002: the goto is not a call
        data = store(0xBF800000) + goto(0x2000)
        sites = sharcflow.find_sites(data, 0x1000, lookback=3, min_depth=1)
        self.assertEqual(sites['calls'], [])
        self.assertEqual(sites['gotos'], [{'sw': 0x1003, 'target': 0x2000}])
        self.assertEqual(sites['aligned'], [(0x1000, 6), (0x1003, 6)])

    def test_lookback_stops_at_a_transfer(self):
        data = store(0x1002) + goto(0x2000) + goto(0x3000)
        sites = sharcflow.find_sites(data, 0x1000, lookback=3, min_depth=1)
        self.assertEqual([c['target'] for c in sites['calls']], [0x2000])
        self.assertEqual([g['target'] for g in sites['gotos']], [0x3000])


if __name__ == '__main__':
    unittest.main()
