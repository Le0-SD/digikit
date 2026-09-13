#!/usr/bin/env python3
"""Dump a guest memory range from a resumed, spun-forward snapshot.

Some data structures do not exist until runtime -- an uninitialised bss
region that a static initialiser fills in during startup, for instance. For
those, Ghidra's static image throws `MemoryAccessException` and the emulator
is the only way to see real values. This tool is the minimal, reusable
counterpart to that need: resume a snapshot, run forward a caller-chosen
instruction budget (waiting for post-intro handover the way `mmiotrace.py`
does, since bss tables of interest are typically populated by that point),
and dump a memory range as both hex bytes and big-endian longwords.

Modelled directly on `tools/mmiotrace.py` (`emu.longrun.build`/`spin`, the
`emu.pit.intro_running` + `emu.dtim.Dtims`/`Timers` post-intro handover
dance) and `tools/addrtrace.py`'s `load_main_image` (per-syx cached
extraction, never touching the shared `sections/` directory).

No hooks are installed on the dumped range itself -- this is a pure `Machine
build + spin + mem_read`, on purpose. `tools/addrtrace.py`'s docstring notes
that `UC_HOOK_BLOCK`/global `UC_HOOK_CODE` hooks are known to change
emulation outcomes (see `bootcheck.py --profile`); range-scoped MMIO trace
hooks are fine for peripheral windows but add needless risk for a plain RAM
read, so this tool installs none at all beyond what `build()` always sets up
for a faithful resume.

Also known and deliberately avoided: `reg_read(UC_M68K_REG_SR)` between
`emu_start` calls clobbers condition codes on this patched Unicorn build.
This tool never reads SR.

Usage:
    uv run python tools/memdump.py --syx Digitakt_II_OS1.15C.syx \\
        --snapshot snapshots/boot400M.snap \\
        --range 0x42923540-0x429237f8 --json out/machine-table.json

    uv run python tools/memdump.py --syx Digitakt_II_OS1.15C.syx \\
        --snapshot snapshots/boot400M.snap \\
        --range 0x42923644-0x42923670 --instrs 200000000 --stride 44
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
from emu.longrun import build, spin
from emu.pit import Pits, intro_running


def parse_range(spec):
    lo, _, hi = spec.partition('-')
    if not hi:
        raise argparse.ArgumentTypeError(
            'range must be LO-HI, e.g. 0x42923540-0x429237f8')
    lo, hi = int(lo, 0), int(hi, 0)
    if hi <= lo:
        raise argparse.ArgumentTypeError('range HI must be > LO')
    return (lo, hi)


def run(args):
    main_img, _ = load_main_image(args.syx)
    profile = symbols.resolve(main_img)

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
    # Run to the instruction budget, but never stop mid-intro: if the budget
    # is exhausted before handover, keep going in further chunks up to
    # --max-instrs so a caller who only raised --instrs still gets a
    # post-handover dump rather than a premature, unpopulated one.
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

    lo, hi = args.range
    size = hi - lo
    raw = bytes(m.uc.mem_read(lo, size))

    words = []
    stride = args.stride
    for off in range(0, size - (size % stride if stride else 0), stride):
        chunk = raw[off:off + stride]
        longwords = []
        for i in range(0, len(chunk) - (len(chunk) % 4), 4):
            longwords.append(int.from_bytes(chunk[i:i + 4], 'big'))
        words.append({
            'address': '0x%08x' % (lo + off),
            'offset': off,
            'hex': chunk.hex(),
            'longwords': ['0x%08x' % w for w in longwords],
        })

    return {
        'syx': args.syx,
        'snapshot': args.snapshot,
        'range': '0x%08x-0x%08x' % (lo, hi),
        'size': size,
        'stride': stride,
        'instrs': done,
        'intro_live_at_restore': bool(intro),
        'reached_post_intro': phase['post_intro'],
        'stop': stop,
        'elapsed_s': round(time.time() - t0, 1),
        'hex': raw.hex(),
        'records': words,
    }


def print_report(report, show_words):
    meta = {k: v for k, v in report.items()
            if k not in ('hex', 'records')}
    print(json.dumps(meta, indent=2))
    if not report['reached_post_intro']:
        print('\n*** the intro never handed over -- dump may be from an '
              'unpopulated table; raise --instrs / --max-instrs ***')
    print('\n--- records (stride=%d) ---' % report['stride'])
    for rec in report['records'][:show_words]:
        print('%-12s  %-40s  %s' % (
            rec['address'], rec['hex'], ' '.join(rec['longwords'])))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--syx', required=True)
    ap.add_argument('--snapshot', required=True)
    ap.add_argument('--range', type=parse_range, required=True,
                     help='LO-HI guest address range to dump, e.g. '
                          '0x42923540-0x429237f8')
    ap.add_argument('--instrs', type=lambda s: int(s, 0), default=90_000_000,
                     help='instruction budget to run forward before '
                          'dumping (default: 90M, enough for post-intro '
                          'handover from snapshots/boot400M.snap)')
    ap.add_argument('--max-instrs', type=lambda s: int(s, 0),
                     default=400_000_000,
                     help='hard ceiling; if handover has not happened by '
                          '--instrs, keep spinning in --chunk steps up to '
                          'this many instructions total')
    ap.add_argument('--chunk', type=lambda s: int(s, 0), default=5_000_000,
                     help='spin() chunk size for the extra post-budget '
                          'search for handover')
    ap.add_argument('--stride', type=int, default=4,
                     help='bytes per record row (default: 4, one '
                          'longword; use 44/0x2c for the descriptor table)')
    ap.add_argument('--slc', action='store_true', default=True)
    ap.add_argument('--sdgate', dest='sdgate', action='store_true', default=True)
    ap.add_argument('--no-sdgate', dest='sdgate', action='store_false')
    ap.add_argument('--esdhc', dest='esdhc', action='store_true', default=True)
    ap.add_argument('--no-esdhc', dest='esdhc', action='store_false')
    ap.add_argument('--top', type=int, default=200,
                     help='max record rows to print (all are in --json)')
    ap.add_argument('--json', help='write the full report here')
    args = ap.parse_args(argv)

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
