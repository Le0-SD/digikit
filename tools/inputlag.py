# pyright: reportMissingImports=false
# fmt: off
"""Measure how long the firmware takes to react to a panel button.

INCOMPLETE: the harness works, the OBSERVATION DOES NOT. Read this first.

This times the press by latching the panel framebuffer at `panel_diff` and
thresholding how many bytes changed. That signal does not work. Run against
both builds on 2026-09-13 it reported "no page change in 300M instructions"
for Digitakt too -- a build that visibly responds to the same button in the
GUI within a frame or two. The measurement is at fault, not the firmware.

The reason is in its own output: at idle, 365-402 of the panel buffer's 1024
bytes differ between CONSECUTIVE latched frames, on both builds. A third of
the screen changes frame to frame with nothing happening, so no threshold
separates a page switch from the churn. `emu/panel.py` documents `panel_diff`
as the one moment [FRONT] is a complete frame; this says it is not, which is
worth chasing on its own -- `emu/gui.py` latches at the same place.

What to fix: replace the frame comparison with a hook on the firmware's own
output. `queue_recv` and `main_queue` both resolve on both builds, and the
16-byte event record the firmware emits is what actually says "the button
arrived". That technique mapped the whole panel in 85 seconds where framebuffer
diffing took hours and produced two contradictory maps.

What is reusable as-is: warming past the intro, settling until the UI is up,
resolving a button by the firmware's OWN name table, and injecting a press and
release through `panelin.feed`. Only the last step -- deciding that the
firmware reacted -- needs replacing.

A click in `emu/gui.py` reaches the guest almost immediately -- `_drain_input`
runs once per `spin` pass and `panelin.feed` writes the whole byte stream into
the DMA ring and raises the RX vector in one go, with no baud model and no
per-call byte budget. So when a button feels slow, the delay is the FIRMWARE's,
and the question is how many instructions it spends before the screen changes.

This answers that without a window and without a human hand: warm past the
intro, settle until the UI is up, latch the panel framebuffer at `panel_diff`
(the one moment emu/panel.py documents it as a complete frame), press a
button, and count instructions until a latched frame differs from the one
before the press.

    uv run python tools/inputlag.py SNAP --syx FW.syx --button FLTR

To measure a build whose sections are not the ones in `sections/`, point
DT2_SECTIONS at its directory rather than re-extracting -- that way this can
run beside a GUI session on the other build without disturbing it:

    DT2_SECTIONS=/tmp/dn-sections uv run python tools/inputlag.py ...
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn.m68k_const import UC_M68K_REG_PC

from emu import config, device as devices, panel, panelin, symbols
from emu.dtim import Dtims, Timers
from emu.longrun import build, spin
from emu.pit import INSTR_PER_SEC, Pits, intro_running

CHUNK = 2_000_000         # instructions between frame comparisons


def _differ(a, b):
    """-> how many bytes of two frames differ."""
    return sum(1 for x, y in zip(a, b) if x != y)


class Watcher:
    """Latches the panel framebuffer at each `panel_diff`, with a clock.

    `panel_diff` is the only moment [FRONT] is a complete, just-rendered
    frame: mid-flush it is torn on a page boundary, and once the diff has
    swapped, [FRONT] is the buffer being rendered INTO rather than the one on
    the panel. emu/panel.py documents this; emu/gui.py latches at the same
    place for the same reason.
    """

    def __init__(self, m, profile):
        self.m = m
        self.profile = profile
        self.frame = None
        self.frames = 0
        self.churn = 0                  # biggest idle frame-to-frame change
        self.at = 0
        self.clock = lambda: 0          # replaced once spinning starts

    def latch(self, uc, addr, size, data):
        buf = panel.read(self.m, self.profile.fb_front)
        if buf is None:
            return
        frame = bytes(buf)
        if self.frame is not None:
            # Background churn: a blinking cursor, a level meter, the
            # playhead. A page change is not "some pixels differ" -- this
            # screen is never still -- it is a redraw far larger than
            # whatever the idle screen does on its own.
            self.churn = max(self.churn, _differ(self.frame, frame))
        self.frame = frame
        self.frames += 1
        self.at = self.clock()


def settle(m, pc, pits, instrs, label, fast, note=None):
    """Spin `instrs` instructions, reporting as it goes. -> (pc, done)."""
    done, t0 = 0, time.time()
    while done < instrs:
        pc, ran, stop = spin(m, pc, min(20_000_000, instrs - done), pits=pits,
                             fast=fast)
        done += ran
        if stop != 'limit':
            print('%s halted: %s at %#010x after %dM'
                  % (label, stop, pc, done // 1_000_000), flush=True)
            return pc, done
        print('  %s %4dM  %.0fs%s'
              % (label, done // 1_000_000, time.time() - t0,
                 '  ' + note() if note else ''), flush=True)
    return pc, done


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('snapshot')
    ap.add_argument('--syx')
    ap.add_argument('--button', default='FLTR',
                    help='panel button to press, by name (default FLTR)')
    ap.add_argument('--settle', type=int, default=1_000_000_000,
                    help='instructions to run after the intro hands over, so '
                         'the UI is actually up before pressing anything')
    ap.add_argument('--hold', type=int, default=2_000_000,
                    help='instructions to hold the button down')
    ap.add_argument('--window', type=int, default=300_000_000,
                    help='how long to wait for the screen to change')
    ap.add_argument('--exact', action='store_true',
                    help='count= stepping instead of the GUI default')
    ap.add_argument('--slc', action='store_true')
    args = ap.parse_args(argv)
    fast = not args.exact

    syx = config.firmware(args.syx) if args.syx else None
    m, ev, st, pc, inq, at = build(args.snapshot, unblock=True, softfloat=True,
                                   bitmap=True, dsp=True, slc=args.slc,
                                   **({'syx': syx} if syx else {}))
    # pi-lens-ignore: ast-grep:unchecked-throwing-call-python
    profile = symbols.resolve(open(config.main_image(), 'rb').read())
    if profile.panel_diff is None or profile.fb_front is None:
        raise SystemExit('panel_diff/fb_front did not resolve for this image; '
                         'there is no defined moment to read a whole frame.')
    if not syx:
        raise SystemExit('Pass --syx: button names have no codes without '
                         'knowing which product this is.')
    dev, fw = devices.identify(syx)
    # The firmware names its own controls; nothing here writes the panel
    # down. gui.py labels the same way, and strips a common prefix per group
    # ("PAGE TRIG", "PAGE SRC" -> "TRIG", "SRC"), so match on the last word
    # too or --button FLTR would miss.
    names = panelin.control_names(m, profile, 'button')
    want = args.button.upper()
    code = None
    for c, name in names.items():
        if want in (name.upper(), name.upper().rsplit(' ', 1)[-1]):
            code = c
            break
    if code is None:
        raise SystemExit('%s has no button %r. It has:\n  %s'
                         % (dev.name, args.button,
                            '\n  '.join('%-4s %s' % (c, n)
                                        for c, n in sorted(names.items()))))

    intro = intro_running(m, profile.intro_pit3_isr)
    pits = Timers(Pits(m, hold=intro), Dtims(m, channels=(3,), hold=intro))
    if pits.held and profile.intro_done is not None:
        at(profile.intro_done, lambda uc, a, s, d: pits.release())
    marks = {'mainloop': 0}
    if profile.mainloop is not None:
        at(profile.mainloop, lambda uc, a, s, d: marks.__setitem__(
            'mainloop', marks['mainloop'] + 1))

    watch = Watcher(m, profile)
    at(profile.panel_diff, watch.latch)

    print('%s   %s   button %s (code %s)   %s stepping'
          % (dev.name, args.snapshot, names[code], code,
             'exact' if args.exact else 'fast'),
          flush=True)

    total = [0]
    watch.clock = lambda: total[0]
    t0 = time.time()
    while pits.held:
        pc, ran, stop = spin(m, pc, 4_000_000, pits=pits, fast=fast)
        total[0] += ran
        if stop != 'limit':
            raise SystemExit('halted during intro: %s' % stop)
    print('intro handed over after %dM, %.0fs'
          % (total[0] // 1_000_000, time.time() - t0), flush=True)

    def note():
        return 'mainloop %d  frames %d' % (marks['mainloop'], watch.frames)
    pc, ran = settle(m, pc, pits, args.settle, 'settle', fast, note)
    total[0] += ran
    if watch.frame is None:
        raise SystemExit('No complete frame was ever latched, so there is '
                         'nothing to compare against. Settle for longer.')

    before, at_press = watch.frame, total[0]
    print('\npressing %s at %dM instructions (%d frames latched, mainloop %d)'
          % (names[code], total[0] // 1_000_000, watch.frames,
             marks['mainloop']),
          flush=True)

    held = panelin.Held(dev)
    pos = held.press(code)
    pc = panelin.feed(m, profile, panelin.encode_buttons(*pos))

    # A page switch redraws most of the panel, so demand a change several
    # times larger than anything the idle screen managed on its own, and
    # never less than a twentieth of it.
    floor = max(watch.churn * 4, len(before) // 20)
    print('idle churn was at most %d bytes a frame, so calling it a page '
          'change at %d of %d' % (watch.churn, floor, len(before)), flush=True)

    released, changed, peak = False, None, 0
    while total[0] - at_press < args.window and changed is None:
        pc, ran, stop = spin(m, pc, CHUNK, pits=pits, fast=fast)
        total[0] += ran
        if stop != 'limit':
            print('halted while waiting: %s' % stop, flush=True)
            break
        if not released and total[0] - at_press >= args.hold:
            for p in held.release_all():
                pc = panelin.feed(m, profile, panelin.encode_buttons(*p))
            released = True
        if watch.frame is None:
            continue
        d = _differ(before, watch.frame)
        if d > peak:
            peak = d
            print('  +%-9d %5d bytes differ%s'
                  % (total[0] - at_press, d, '  (released)' if released else ''),
                  flush=True)
        if d >= floor:
            changed = watch.at

    print()
    if changed is None:
        print('NO PAGE CHANGE in %dM instructions (%.1f emulated seconds). '
              'Biggest difference seen was %d bytes, under the %d it would '
              'have taken. %d frames latched.'
              % (args.window // 1_000_000, args.window / INSTR_PER_SEC,
                 peak, floor, watch.frames), flush=True)
        return 1
    delta = changed - at_press
    print('screen changed %d instructions after the press '
          '-- %.2f emulated seconds at %.2fM instr/sec'
          % (delta, delta / INSTR_PER_SEC, INSTR_PER_SEC / 1e6), flush=True)
    print('  mainloop passes now %d, frames latched %d, pc %#010x'
          % (marks['mainloop'], watch.frames, m.uc.reg_read(UC_M68K_REG_PC)),
          flush=True)
    fired = pits.fired
    print('  PIT0 %d  PIT2 %d  PIT3 %d  DTIM3 %d'
          % (fired.get('PIT0', 0), fired.get('PIT2', 0), fired.get('PIT3', 0),
             fired.get('DTIM3', 0)), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
