#!/usr/bin/env python3
"""Search mapped guest memory for a byte pattern, on a resumed snapshot.

Some data (the machine-select display names, for instance) is neither in the
static image nor in the bss descriptor table -- it appears to be built only
at runtime, as heap-allocated `std::string` character data with no fixed
address Ghidra's static view can show. `tools/memdump.py` answers "what is
at this address"; this tool answers "where, if anywhere, does this byte
pattern live" by scanning every page Unicorn has actually mapped.

Modelled directly on `tools/memdump.py`: same `emu.longrun.build`/`spin`,
the same post-intro handover dance via `emu.pit.intro_running` and
`emu.dtim.Dtims`/`Timers`, the same per-syx cached image loading via
`tools/addrtrace.py`'s `load_main_image`, and the same argparse/JSON
conventions. It never reads the m68k SR register between `emu_start` calls
(a documented gotcha on this patched Unicorn build -- it clobbers condition
codes) and installs no hooks beyond what `build()` sets up for a faithful
resume, for the same reason `memdump.py` does not: a global code/block hook
is known to change emulation outcomes on this project.

Mapped memory (`emu.harness.Machine.mapped`) is a set of `PAGE`-aligned
(0x100000) base addresses, populated lazily as the guest touches pages --
it is not one contiguous span. This tool groups mapped pages into
contiguous runs and reads + searches each run as one block, so a hit
straddling a page boundary inside one run is still found; a "hit" spanning
a gap between two non-adjacent runs cannot exist and is not looked for.

Usage:
    uv run python tools/memfind.py --syx Digitakt_II_OS1.15C.syx \\
        --snapshot snapshots/boot400M.snap \\
        --pattern ONESHOT --json out/oneshot-hits.json

    uv run python tools/memfind.py --syx Digitakt_II_OS1.15C.syx \\
        --snapshot snapshots/boot400M.snap \\
        --hex 44f25c7c --range 0x40000000-0x50000000

    # find pointers to a hit address (4-byte big-endian pointer value)
    uv run python tools/memfind.py --syx Digitakt_II_OS1.15C.syx \\
        --snapshot snapshots/boot400M.snap --hex 44f25c7c
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from addrtrace import load_main_image

from emu import symbols
from emu.dtim import Dtims, Timers
from emu.harness import PAGE
from emu.longrun import build, spin
from emu.pit import Pits, intro_running


def parse_range(spec):
    lo, _, hi = spec.partition('-')
    if not hi:
        raise argparse.ArgumentTypeError(
            'range must be LO-HI, e.g. 0x40000000-0x50000000')
    lo, hi = int(lo, 0), int(hi, 0)
    if hi <= lo:
        raise argparse.ArgumentTypeError('range HI must be > LO')
    return (lo, hi)


def parse_pattern(args):
    if bool(args.pattern) == bool(args.hex):
        raise argparse.ArgumentTypeError(
            'exactly one of --pattern or --hex is required')
    if args.pattern:
        return args.pattern.encode('latin-1')
    hexstr = ''.join(args.hex.split())
    if len(hexstr) % 2:
        raise argparse.ArgumentTypeError('--hex must have an even number '
                                          'of digits')
    return bytes.fromhex(hexstr)


def contiguous_runs(bases, bound=None):
    """Group sorted page-aligned addresses into (lo, hi) contiguous runs,
    optionally clipped to `bound=(lo, hi)`."""
    bases = sorted(bases)
    if bound:
        blo, bhi = bound
        bases = [b for b in bases if b + PAGE > blo and b < bhi]
    runs = []
    for base in bases:
        if runs and runs[-1][1] == base:
            runs[-1] = (runs[-1][0], base + PAGE)
        else:
            runs.append((base, base + PAGE))
    if bound:
        blo, bhi = bound
        runs = [(max(lo, blo), min(hi, bhi)) for lo, hi in runs]
    return runs


def find_all(haystack, needle):
    """-> list of offsets of every (possibly overlapping) occurrence."""
    hits = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            break
        hits.append(idx)
        start = idx + 1
    return hits


def run(args):
    main_img, _ = load_main_image(args.syx)
    profile = symbols.resolve(main_img)
    pattern = parse_pattern(args)

    m, ev, st, pc, inq, at = build(
        args.snapshot, syx=args.syx, unblock=True, softfloat=True,
        bitmap=True, dsp=True, slc=args.slc,
        sdgate=args.sdgate, esdhc=args.esdhc)

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
    # As in memdump.py: never stop mid-intro, and keep spinning in further
    # chunks up to --max-instrs if handover hasn't happened by --instrs, so
    # a caller who only raised --instrs still gets a post-handover search.
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

    runs = contiguous_runs(m.mapped, bound=args.range)

    hits = []
    bytes_scanned = 0
    for lo, hi in runs:
        blob = bytes(m.uc.mem_read(lo, hi - lo))
        bytes_scanned += len(blob)
        for off in find_all(blob, pattern):
            hits.append('0x%08x' % (lo + off))

    return {
        'syx': args.syx,
        'snapshot': args.snapshot,
        'pattern_hex': pattern.hex(),
        'pattern_len': len(pattern),
        'pattern_repr': (args.pattern if args.pattern
                          else '(hex) ' + args.hex),
        'range': ('0x%08x-0x%08x' % args.range) if args.range else None,
        'instrs': done,
        'intro_live_at_restore': bool(intro),
        'reached_post_intro': phase['post_intro'],
        'stop': stop,
        'elapsed_s': round(time.time() - t0, 1),
        'mapped_pages': len(m.mapped),
        'contiguous_runs': [['0x%08x' % lo, '0x%08x' % hi]
                             for lo, hi in runs],
        'bytes_scanned': bytes_scanned,
        'hit_count': len(hits),
        'hits': hits,
    }


def print_report(report, show_hits):
    meta = {k: v for k, v in report.items() if k != 'hits'}
    print(json.dumps(meta, indent=2))
    if not report['reached_post_intro']:
        print('\n*** the intro never handed over -- search may be over an '
              'unpopulated heap; raise --instrs / --max-instrs ***')
    print('\n--- hits (%d total) ---' % report['hit_count'])
    for addr in report['hits'][:show_hits]:
        print(addr)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--syx', required=True)
    ap.add_argument('--snapshot', required=True)
    ap.add_argument('--pattern', help='literal string to search for '
                     '(encoded latin-1, one byte per char)')
    ap.add_argument('--hex', help='hex byte pattern to search for, e.g. '
                     '4f4e455348 (spaces allowed); use this for a raw '
                     'big-endian pointer value too')
    ap.add_argument('--range', type=parse_range, default=None,
                     help='LO-HI guest address range to narrow the search '
                          'to (default: every mapped page)')
    ap.add_argument('--instrs', type=lambda s: int(s, 0), default=90_000_000,
                     help='instruction budget to run forward before '
                          'searching (default: 90M, enough for post-intro '
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
    ap.add_argument('--top', type=int, default=200,
                     help='max hit addresses to print (all are in --json)')
    ap.add_argument('--json', help='write the full report here')
    args = ap.parse_args(argv)

    if bool(args.pattern) == bool(args.hex):
        ap.error('exactly one of --pattern or --hex is required')

    report = run(args)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)) or '.',
                     exist_ok=True)
        with open(args.json, 'w') as fh:
            json.dump(report, fh, indent=2)
    print_report(report, args.top)
    return 0 if report['reached_post_intro'] else 1


if __name__ == '__main__':
    sys.exit(main())
