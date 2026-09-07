"""Capture a real rendered panel frame from a running boot.

Every task other than the idle task blocks in sem_pend waiting on a device
event that never happens under emulation -- no DSP, no panel controller, no
MIDI. dspboot already force-satisfies one specific semaphore (the DSP
transport completion sem) to get past exactly this; this generalises that to
any pend whose count is <= 0, i.e. "the awaited event has always just
happened". With that, the draw task runs and Bitmap::setPixel executes for
the first time.

Usage: python -m emu.frame [snapshot] [instrs] [out.png]
"""
import struct, sys, os, time, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn.m68k_const import UC_M68K_REG_A7
from emu.longrun import build, spin
from emu.screen import png

SET_PIXEL = 0x40104eb4                    # setPixel(Bitmap*, x, y, value)
W, H = 128, 64


def ascii_art(fb, w=W, h=H):
    rows = []
    for y in range(h):
        rows.append(''.join('#' if fb.get((x, y)) else '.' for x in range(w)))
    return '\n'.join(rows)


def main(snapshot, instrs, out='out/frame.png'):
    m, ev, st, pc, inq, at = build(snapshot, unblock=True)
    stats = collections.Counter()

    fb = {}
    frames = []
    bitmaps = collections.Counter()

    def on_setpixel(uc, a, s, d):
        sp = uc.reg_read(UC_M68K_REG_A7)
        ret, this, x, y, val = struct.unpack('>IIIII', uc.mem_read(sp, 20))
        bitmaps[this] += 1
        stats['px'] += 1
        if x < W and y < H:
            if (x, y) in fb and len(fb) > W * H // 2:
                frames.append(dict(fb))      # coordinate repeat -> new frame
                fb.clear()
            fb[(x, y)] = val & 0xFF
    at(SET_PIXEL, on_setpixel)

    t0 = time.time()
    pc, done, stop = spin(m, pc, instrs)
    dt = time.time() - t0

    print('=== %d instrs in %.0fs (%.2fM/s) stop=%s ===' % (done, dt, done/dt/1e6, stop))
    print('pends satisfied : %d' % ev['satisfied'])
    print('setPixel calls  : %d   complete frames: %d' % (stats['px'], len(frames)))
    print('Bitmap objects  : %s' % ['0x%08x x%d' % (b, c) for b, c in bitmaps.most_common(4)])
    print('prints          : %r' % ev['prints'][:20])

    shot = frames[-1] if frames else fb
    if not shot:
        print('no pixels captured'); return
    lit = sum(1 for v in shot.values() if v)
    print('frame           : %d pixels set, %d lit' % (len(shot), lit))
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    px = bytearray(W * H)
    for (x, y), v in shot.items():
        px[y * W + x] = 255 if v else 0
    open(out, 'wb').write(png(px, W, H))
    print('wrote %s' % out)
    print()
    print(ascii_art(shot))


if __name__ == '__main__':
    snap = sys.argv[1] if len(sys.argv) > 1 else 'snapshots/boot400M.snap'
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 60_000_000
    out = sys.argv[3] if len(sys.argv) > 3 else 'out/frame.png'
    main(snap, n, out)
