"""The panel the firmware actually draws on.

Read this before trusting any statement about what is on screen.

There are two different "screens" in this project and they are not the same
thing. `emu.frame` and `longrun.build(bitmap=True, on_pixel=...)` observe
`Bitmap::setPixel`, a high-level intercept of one drawing primitive. That is
the right instrument for the *intro*, which draws through it. It is the wrong
instrument for the main OS, which composes text and widgets straight into a
framebuffer and never calls the intercepted primitive -- so `setPixel` counts
near zero while a complete user interface sits in RAM unobserved. Believing
`setPixel` cost a session: HANDOVER used to say the panel "still shows the
last intro frame" when in fact the main OS had been rendering for millions of
instructions.

The real thing is a pair of 1024-byte buffers whose pointers live at
0x4029f650 and 0x4029f654. `0x40126332` diffs them page by page, flushes the
changed runs through `0x40126264`, and then swaps the two pointers
(0x401263b0..0x401263c6). So:

  * at diff *entry*, [FRONT] is a complete, just-rendered frame -- this is the
    only moment guaranteed untorn, and `Capture` grabs it there;
  * after the diff has swapped, [BACK] is what the panel is showing and
    [FRONT] is the buffer being rendered into next.

Layout, read off the diff's own indexing (P + 0x40*k + 8*j over P=0..7,
k=0..15, j=0..7) and confirmed against the flush, which sends `0x10|page`,
then the column, then eight bytes:

    byte index = page + 8 * column      page 0..7, column 0..127
    bit n of that byte = row 8 * (7 - page) + n,  least significant bit first

An ordinary SSD1306-style page layout for a 128x64 mono panel, except that
**the page order is inverted**: page 0 is the BOTTOM eight rows, not the top.
That is a remapped COM scan direction (SSD1306 COMSCANDEC and equivalents), a
routine panel-wiring option, and columns are NOT reversed with it.

Do not take the page order on trust -- it was got wrong first, and the failure
mode is subtle rather than obvious. With the pages the natural way round the
screen still shows crisp, readable text in several bands, which looks like
success; what gives it away is that circles come out as hourglasses and the
value rows overlap, because each eight-row band is mirrored in place. The
mapping below is the one where knobs are round, boxes are rectangles, and the
error dialog reads `MMC NOT IN SLC MODE` -- a string that is verbatim in the
firmware image at file offset 0x2245bd, which is what settles it.

`read` is a plain memory read and installs no hook, so it costs nothing and
cannot perturb a run -- HANDOVER warning 2. `Capture` does add one hook and
therefore does change the run it observes; use it when you want a frame
sequence and are not also measuring totals.

    python -m emu.panel <snapshot> [instrs] [channels] [out.png]
"""
import os
import struct
import sys

W, H = 128, 64
# Digitakt II 1.15C reference values, kept as defaults for callers that have
# no resolved Profile (a REPL, a script against a known-Digitakt Machine).
# Anything that knows which image is loaded should resolve one via
# emu.symbols and pass fb_front/fb_back/panel_diff explicitly -- see
# emu.gui.Emulator and main() below, both of which do.
FRONT = 0x4029f650      # -> the buffer just rendered (at diff entry)
BACK = 0x4029f654       # -> the buffer on the panel (after the diff's swap)
DIFF = 0x40126332       # the double-buffer diff; swaps FRONT/BACK on the way out
SIZE = W * H // 8       # 1024


def _uc(m):
    return getattr(m, 'uc', m)


def read(m, ptr_addr=FRONT):
    """-> the 1024 raw bytes behind `ptr_addr`, or None if it is not a buffer.

    `ptr_addr` is fb_front (or fb_back) from a resolved emu.symbols Profile;
    it defaults to the Digitakt address for back-compat. None (an unresolved
    OPTIONAL symbol -- see emu/symbols.py) is a valid input and reads as "no
    buffer", same as any other address that turns out not to hold one.

    Installs no hook. Called after a run has stopped this is the frame in
    memory; called at an arbitrary moment it may be torn on a page boundary,
    because the flush walks pages 0..7. Use `Capture` if that matters.
    """
    if ptr_addr is None:
        return None
    uc = _uc(m)
    try:
        ptr = struct.unpack('>I', bytes(uc.mem_read(ptr_addr, 4)))[0]
    except Exception:
        return None
    if not 0x40000000 <= ptr < 0x50000000:
        return None
    try:
        return bytes(uc.mem_read(ptr, SIZE))
    except Exception:
        return None


def lit(buf):
    """-> the set of (x, y) pixels that are on, y=0 at the top of the panel.

    `7 - (y // 8)` is the inverted page order described above.
    """
    return {(x, y)
            for x in range(W) for y in range(H)
            if (buf[(7 - (y // 8)) + 8 * x] >> (y % 8)) & 1}


def ascii_art(buf, on='#', off='.'):
    """-> the frame as H strings of W characters."""
    px = lit(buf)
    return [''.join(on if (x, y) in px else off for x in range(W))
            for y in range(H)]


def png_bytes(buf, scale=6):
    """-> a scaled 8-bit greyscale PNG of the frame.

    Nearest-neighbour and integer, so no pixel is invented; 128x64 is
    unreadable at 1:1 in any viewer.
    """
    from emu.screen import png
    s = max(1, scale)
    out = bytearray(W * s * H * s)
    for x, y in lit(buf):
        for dy in range(s):
            row = (y * s + dy) * W * s + x * s
            for dx in range(s):
                out[row + dx] = 255
    return png(out, W * s, H * s)


def write_png(buf, path, scale=6):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'wb') as fh:
        fh.write(png_bytes(buf, scale))
    return path


class Capture:
    """Collect untorn frames by hooking the diff's entry.

    This adds a hook and so changes the run -- keep it out of anything whose
    totals are being compared (HANDOVER warning 2).

        cap = Capture(at)          # `at` from longrun.build
        ...spin...
        cap.frames                 # every frame, in order
        cap.distinct()             # consecutive duplicates collapsed

    `diff_addr`/`front_addr` default to the Digitakt reference addresses;
    pass the resolved profile's `panel_diff`/`fb_front` for any other image.
    `diff_addr=None` (panel_diff unresolved -- an OPTIONAL symbol, see
    emu/symbols.py) degrades gracefully: no hook is installed and `frames`
    just stays empty, rather than crashing.
    """

    def __init__(self, at, limit=4096, diff_addr=DIFF, front_addr=FRONT):
        self.frames = []
        self.limit = limit
        if diff_addr is None:
            return

        def grab(uc, addr, size, data):
            if len(self.frames) < self.limit:
                buf = read(uc, front_addr)
                if buf is not None:
                    self.frames.append(buf)

        at(diff_addr, grab)

    def distinct(self):
        out = []
        for f in self.frames:
            if not out or f != out[-1]:
                out.append(f)
        return out

    @property
    def last(self):
        return self.frames[-1] if self.frames else None


def main(snapshot, instrs, channels, out):
    from emu import config, symbols
    from emu.dtim import Dtims, Timers
    from emu.longrun import build, spin
    from emu.pit import Pits, intro_running

    # Resolve fb_front/panel_diff for whichever image is actually loaded --
    # build() below resolves the identical profile itself (cached by image
    # SHA-256, see emu/symbols.py), so this costs nothing extra. Both are
    # OPTIONAL symbols: unresolved, Capture and read() just produce nothing
    # rather than crash or silently read the wrong build's addresses.
    main_img = open(config.main_image(), 'rb').read()
    profile = symbols.resolve(main_img)
    if profile.panel_diff is None or profile.fb_front is None:
        print('warning: panel_diff/fb_front unresolved for this image -- '
              'no frames will be captured\n%s' % profile.report())

    m, ev, st, pc, inq, at = build(snapshot, unblock=True, softfloat=True,
                                   bitmap=True, dsp=True)
    cap = Capture(at, diff_addr=profile.panel_diff, front_addr=profile.fb_front)
    # One call, one answer: both timer sources must agree on whether the
    # intro still owns PIT3, and the handler to compare against is this
    # build's own -- see emu/symbols.py:intro_pit3_isr.
    intro = intro_running(m, profile.intro_pit3_isr)
    src = [Pits(m, hold=intro)]
    if channels:
        src.append(Dtims(m, channels=channels, hold=intro))
    timers = Timers(*src)
    if timers.held:
        if profile.intro_done is None:
            print('warning: intro_done unresolved for this image -- the '
                  'timers will stay held for the whole run')
        else:
            at(profile.intro_done, lambda u, a, s, d: timers.release())

    pc, done, stop = spin(m, pc, instrs, pits=timers)
    frames = cap.distinct()
    print('%s  channels=%s  %s instrs  stop=%s'
          % (snapshot, channels, format(done, ','), stop))
    print('frames flushed=%d distinct=%d' % (len(cap.frames), len(frames)))
    buf = cap.last if cap.last is not None else read(m, profile.fb_front)
    if buf is None:
        print('no panel buffer'); return
    print('lit=%d of %d' % (len(lit(buf)), W * H))
    for row in ascii_art(buf):
        print('  ' + row)
    print('wrote %s' % write_png(buf, out))


if __name__ == '__main__':
    snap = sys.argv[1] if len(sys.argv) > 1 else 'snapshots/postintro.snap'
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 60_000_000
    ch = (tuple(int(c) for c in sys.argv[3].split(','))
          if len(sys.argv) > 3 else (3,))
    out = sys.argv[4] if len(sys.argv) > 4 else 'out/panel.png'
    main(snap, n, ch, out)
