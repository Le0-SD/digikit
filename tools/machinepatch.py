#!/usr/bin/env python3
"""Relocate the UI's source machine-list table into the MAIN OS cave, live.

Milestone A of adding an eighth machine. `docs/FINDINGS.md`'s "The ColdFire
machine dispatch" section established that the UI's *source* machine list is
seven big-endian u32 at rodata `0x401e1958`-`0x401e1974` (`{0,1,2,3,6,4,5}`),
copied into a `std::vector<int>` by `FUN_40051fbc` via two `pea` bounds at
`0x40052000` (END) and `0x4005200a` (START). This tool patches a resumed
snapshot, before `FUN_40051fbc` runs, so that:

  - a new 8-entry table `{0,1,2,3,6,4,5,7}` is written into the MAIN OS cave
    at `0x402f9c14` (58,188 zero bytes in the static image, confirmed clear
    of the one runtime-written byte at `0x402fa193`);
  - the two `pea` operands are repointed at the cave copy instead of the
    original rodata table.

It then proves the firmware actually reads the relocated copy -- and not the
original -- by installing `mmiotrace.py`'s `CountingSink` over both the cave
range and the original table's rodata range, and reporting which one saw
read traffic.

Index 7 has no eighth descriptor entry, so it falls back to descriptor entry
6 (the existing "MANUAL SLICE" collapses index 6 and would-be index 7 to the
same descriptor). Expect the new row to render as a second MANUAL SLICE.
That is the correct, unsurprising result for Milestone A: this proves the
list-relocation plumbing works, not that a new machine type exists yet.

This tool patches **guest memory on a resumed snapshot only**. It does not
modify any file, does not touch the firmware image on disk, and produces
nothing flashable -- the patch evaporates when the emulator process exits.

Modelled on `tools/memdump.py` (resume/build, intro-handover spin loop,
argparse/JSON conventions) and `tools/mmiotrace.py` (`CountingSink`,
`install_mmio_trace`). As in both, `reg_read(UC_M68K_REG_SR)` is never
called between `emu_start` calls -- it clobbers condition codes on this
patched Unicorn build.

Usage:
    uv run python tools/machinepatch.py --syx Digitakt_II_OS1.15C.syx \\
        --snapshot snapshots/boot400M.snap --json out/machinepatch.json

    uv run python tools/machinepatch.py --syx Digitakt_II_OS1.15C.syx \\
        --snapshot snapshots/boot400M.snap --no-patch --json out/control.json
"""
import argparse
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from addrtrace import load_main_image
from mmiotrace import CountingSink

from emu import symbols
from emu.dtim import Dtims, Timers
from emu.longrun import build, spin
from emu.pit import Pits, intro_running

END_SITE = 0x40052000
START_SITE = 0x4005200a
END_WANT = bytes.fromhex('4879401e1974')
START_WANT = bytes.fromhex('4879401e1958')
TABLE_D_LO, TABLE_D_HI = 0x401e1958, 0x401e1973
ORIGINAL_TABLE = (0, 1, 2, 3, 6, 4, 5)
NEW_TABLE = ORIGINAL_TABLE + (7,)
DEFAULT_CAVE = 0x402f9c14


def patch(m, cave_addr):
    lines = []
    for site, want in ((END_SITE, END_WANT), (START_SITE, START_WANT)):
        cur = bytes(m.uc.mem_read(site, 6))
        if cur != want:
            raise SystemExit(
                'machinepatch: %#010x holds %s, expected %s'
                % (site, cur.hex(), want.hex()))

    m.ensure(cave_addr)
    new_bytes = struct.pack('>8I', *NEW_TABLE)
    old_cave = bytes(m.uc.mem_read(cave_addr, len(new_bytes)))
    m.uc.mem_write(cave_addr, new_bytes)
    lines.append('%#010x  %s -> %s' % (cave_addr, old_cave.hex(), new_bytes.hex()))

    for site, new_ptr in ((START_SITE, cave_addr), (END_SITE, cave_addr + 32)):
        old = bytes(m.uc.mem_read(site + 2, 4))
        new = struct.pack('>I', new_ptr)
        m.uc.mem_write(site + 2, new)
        lines.append('%#010x  %s -> %s' % (site + 2, old.hex(), new.hex()))

    return lines


def run(args):
    main_img, _ = load_main_image(args.syx)
    profile = symbols.resolve(main_img)

    m, ev, st, pc, inq, at = build(
        args.snapshot, syx=args.syx, unblock=True, softfloat=True,
        bitmap=True, dsp=True, slc=args.slc,
        sdgate=args.sdgate, esdhc=args.esdhc)

    patch_lines = []
    if not args.no_patch:
        patch_lines = patch(m, args.cave)

    sink = CountingSink()
    ranges = ((args.cave, args.cave + 31), (TABLE_D_LO, TABLE_D_HI))
    m.install_mmio_trace(sink, ranges=ranges, owned=False)

    intro = intro_running(m, profile.intro_pit3_isr)
    pits = Timers(Pits(m, hold=intro), Dtims(m, channels=(3,), hold=intro))
    phase = {'post_intro': not intro}

    if intro and profile.intro_done is not None:
        def handover(uc, a, size, data):
            pits.release()
            phase['post_intro'] = True
        at(profile.intro_done, handover)

    done, pc_, stop = 0, pc, 'limit'
    t0 = time.time()
    target = args.instrs
    while True:
        pc_, executed, stop = spin(m, pc_, max(target - done, args.chunk),
                                    pits=pits)
        done += executed
        if stop != 'limit':
            break
        if done >= target and phase['post_intro']:
            break
        if done >= target and not phase['post_intro']:
            if done >= args.max_instrs:
                break
            target = min(target + args.chunk, args.max_instrs)

    raw = bytes(m.uc.mem_read(args.cave, 32))
    table = list(struct.unpack('>8I', raw))

    def range_report(lo, hi):
        keys = [k for k in sink.first_pc if lo <= k[0] <= hi and k[1] == 'read']
        addrs = sorted(set(k[0] for k in keys))
        events = sum(v for k, v in _counts(sink, lo, hi))
        return {
            'range': '0x%08x-0x%08x' % (lo, hi),
            'events': events,
            'distinct_addrs': len(addrs),
            'first_pc': {'0x%08x' % a: '0x%08x' % sink.first_pc[(a, 'read')]
                         for a in addrs},
        }

    cave_report = range_report(args.cave, args.cave + 31)
    tabled_report = range_report(TABLE_D_LO, TABLE_D_HI)

    mode = 'control' if args.no_patch else 'patched'
    if mode == 'patched':
        cave_ok = cave_report['events'] > 0
        tabled_ok = tabled_report['events'] == 0
        if cave_ok and tabled_ok:
            verdict = 'PASS: relocated table read, original table D untouched'
        else:
            fails = []
            if not cave_ok:
                fails.append('relocated range saw zero reads')
            if not tabled_ok:
                fails.append('original table D range still saw reads')
            verdict = 'FAIL: ' + '; '.join(fails)
    else:
        verdict = ('control: original table D events=%d, cave events=%d'
                   % (tabled_report['events'], cave_report['events']))

    return {
        'syx': args.syx,
        'snapshot': args.snapshot,
        'mode': mode,
        'cave': '0x%08x' % args.cave,
        'patch_lines': patch_lines,
        'cave_range': cave_report,
        'table_d_range': tabled_report,
        'readback_table': ['0x%08x' % v for v in table],
        'reached_post_intro': phase['post_intro'],
        'instrs': done,
        'stop': stop,
        'elapsed_s': round(time.time() - t0, 1),
        'verdict': verdict,
    }


def _counts(sink, lo, hi):
    keys = [k for k in sink.first_pc if lo <= k[0] <= hi and k[1] == 'read']
    for key in keys:
        total = sum(bucket.get(key, 0) for bucket in sink.buckets)
        total += sink.cur.get(key, 0)
        yield key, total


def print_report(report):
    print(json.dumps(report, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--syx', required=True)
    ap.add_argument('--snapshot', required=True)
    ap.add_argument('--cave', type=lambda s: int(s, 0), default=DEFAULT_CAVE,
                     help='MAIN OS cave address to write the relocated table '
                          'into (default: 0x402f9c14)')
    ap.add_argument('--no-patch', action='store_true',
                     help='skip the patch, for a control run')
    ap.add_argument('--instrs', type=lambda s: int(s, 0), default=90_000_000,
                     help='instruction budget to run forward before '
                          'observing (default: 90M, enough for post-intro '
                          'handover from snapshots/boot400M.snap)')
    ap.add_argument('--max-instrs', type=lambda s: int(s, 0),
                     default=400_000_000,
                     help='hard ceiling; if handover has not happened by '
                          '--instrs, keep spinning in --chunk steps up to '
                          'this many instructions total')
    ap.add_argument('--chunk', type=lambda s: int(s, 0), default=5_000_000,
                     help='spin() chunk size for the extra post-budget '
                          'search for handover')
    ap.add_argument('--slc', action='store_true', default=True)
    ap.add_argument('--sdgate', dest='sdgate', action='store_true', default=True)
    ap.add_argument('--no-sdgate', dest='sdgate', action='store_false')
    ap.add_argument('--esdhc', dest='esdhc', action='store_true', default=True)
    ap.add_argument('--no-esdhc', dest='esdhc', action='store_false')
    ap.add_argument('--json', help='write the full report here')
    args = ap.parse_args(argv)

    report = run(args)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)) or '.',
                     exist_ok=True)
        with open(args.json, 'w') as fh:
            json.dump(report, fh, indent=2)
    print_report(report)
    if report['mode'] == 'control':
        return 0
    return 0 if report['verdict'].startswith('PASS') else 1


if __name__ == '__main__':
    sys.exit(main())
