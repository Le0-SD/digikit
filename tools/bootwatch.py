"""Watch guest memory writes during a cold boot.

    uv run python tools/bootwatch.py --limit N [--syx SYX]
        [--watch ADDR[:LEN][=NAME]]... [--frame-gate] [--dump DIR]
        [--max-hits N] [--json OUT]

Boots the MAIN OS image from reset with emu.dspboot.run, the path that
`python -m emu.checkpoint make` builds the snapshot ladder on, so instruction
counts compare with the ladder's rungs. A write hook over each watched range
records the instruction count, the PC Unicorn reports, the address, size and
value, and the four longs at the stack pointer. --frame-gate watches the stop
flag, countdown, gate and mode of the image's tools/framelink.py profile.
--dump names the function holding each PC from a tools/ghidradump.py output.
The firmware and image come from emu/config.py (DT2_SYX, DT2_MAIN_IMG,
DT2_SECTIONS), as for the ladder; the tool never saves snapshots.
"""

import argparse
import json
import os
import sqlite3
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import framelink  # noqa: E402
from vtcheck import containing  # noqa: E402

GATE_VARIABLES = ('stop', 'countdown', 'gate', 'mode')


def parse_watch(text):
    """'0x409664f4:4=gate' -> (0x409664f4, 4, 'gate'); LEN defaults to 4."""
    spec, _, name = text.partition('=')
    addr, _, length = spec.partition(':')
    try:
        addr = int(addr, 0)
        length = int(length, 0) if length else 4
    except ValueError:
        raise argparse.ArgumentTypeError('want ADDR[:LEN][=NAME], got %r' % text)
    return addr, length, name or '0x%08x' % addr


def function_names(dump):
    """-> (names, ranges) from a tools/ghidradump.py output."""
    db = sqlite3.connect(os.path.join(dump, 'xrefs.sqlite'))
    try:
        names = dict(db.execute('SELECT entry, name FROM functions'))
        ranges = sorted(db.execute('SELECT lo, hi, func FROM function_ranges'))
    finally:
        db.close()
    return names, ranges


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--limit', type=lambda s: int(s, 0), required=True,
                   help='instructions to run from reset')
    p.add_argument('--syx')
    p.add_argument('--watch', action='append', default=[], type=parse_watch,
                   metavar='ADDR[:LEN][=NAME]', help='repeatable')
    p.add_argument('--frame-gate', action='store_true',
                   help="watch the profile's stop, countdown, gate and mode")
    p.add_argument('--dump', help='tools/ghidradump.py output of the same image')
    p.add_argument('--max-hits', type=int, default=1000, help='stop recording after N writes')
    p.add_argument('--json')
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    from emu import config
    from emu import dspboot
    from unicorn import UC_HOOK_MEM_WRITE
    from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC

    syx = config.firmware(args.syx)
    image_path = config.main_image()
    with open(image_path, 'rb') as f:
        img = f.read()
    image_sha256 = framelink.sha256_file(image_path)
    watches = list(args.watch)
    profile = None
    if args.frame_gate:
        _, prof = framelink.profile_for(image_path)
        profile = prof['name']
        watches += [(prof[name], 4, name) for name in GATE_VARIABLES]
    if not watches:
        raise SystemExit('nothing to watch: give --watch or --frame-gate')
    names, ranges = function_names(args.dump) if args.dump else ({}, [])
    print('%s (%s)%s' % (image_path, image_sha256[:12], ', ' + profile if profile else ''))
    for addr, length, name in watches:
        print('watch %s 0x%08x+%d' % (name, addr, length))

    box, hits = {}, []

    def make_hook(name):
        def hook(uc, access, address, size, value, user):
            if len(hits) >= args.max_hits:
                return
            pc = uc.reg_read(UC_M68K_REG_PC)
            sp = uc.reg_read(UC_M68K_REG_A7)
            try:
                stack = ['0x%08x' % v for v in struct.unpack('>4I', bytes(uc.mem_read(sp, 16)))]
            except Exception:
                stack = []
            func = containing(ranges, pc) if ranges else None
            hit = {'n': box['st']['n'], 'watch': name, 'addr': '0x%08x' % address,
                   'size': size, 'value': '0x%x' % (value & 0xffffffff), 'pc': '0x%08x' % pc,
                   'function': names.get(func) if func is not None else None, 'stack': stack}
            hits.append(hit)
            print('[%d] %s 0x%08x size %d value %s pc %s %s  sp: %s'
                  % (hit['n'], name, address, size, hit['value'], hit['pc'],
                     hit['function'] or '', ' '.join(stack)), flush=True)
        return hook

    def pre_start(m):
        for addr, length, name in watches:
            m.uc.hook_add(UC_HOOK_MEM_WRITE, make_hook(name), begin=addr, end=addr + length - 1)

    m, st, stop = dspboot.run(syx, img, limit=args.limit, machine_out=box, pre_start=pre_start)
    final = {name: bytes(m.uc.mem_read(addr, length)).hex() for addr, length, name in watches}
    print('stop: %s after %d instructions; %d writes recorded' % (stop, st['n'], len(hits)))
    for name, value in final.items():
        print('  %s = %s' % (name, value))
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, 'w') as f:
            json.dump({'tool': 'tools/bootwatch.py', 'syx': syx, 'image': image_path,
                       'image_sha256': image_sha256, 'profile': profile, 'limit': args.limit,
                       'stop': stop, 'n': st['n'],
                       'watches': [{'name': name, 'addr': '0x%08x' % addr, 'len': length}
                                   for addr, length, name in watches],
                       'final': final, 'hits': hits}, f, indent=1)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
