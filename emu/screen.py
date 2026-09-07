"""Render firmware graphics by calling the device's own drawing code.

The panel is 128x64, 1 bit per pixel. Layout recovered from Bitmap::setPixel
(0x40104eb4), which is called as setPixel(Bitmap*, x, y, value):

    Bitmap     +0x04 width
               +0x08 height
               +0x0C stride -- 32-bit words per COLUMN
               +0x10 pixel data pointer
    PixelData  +0x00 width  +0x04 height  +0x08 8bpp row-major source buffer

Pixels are column-major, 1bpp, 32 rows packed per big-endian 32-bit word,
MSB = lowest y:  word_index = x * stride + (y >> 5);  bit = 0x80000000 >> (y & 31)

Two ways to get pixels out, both supported:
  * intercept setPixel and record the calls (format-agnostic)
  * give the firmware a real backing store and decode it afterwards

`px_copy_to_bitmap(PixelData&, Bitmap&)` (0x400d315e) asserts the two agree on
dimensions, so a Bitmap must be built to match its source.
"""
import struct, sys, os, zlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC, UC_M68K_REG_D0
from emu.harness import Machine, call

MAIN_LOAD = 0x40000400
PX_COPY_TO_BITMAP = 0x400d315e
BMP_ADDR  = 0x30000000       # scratch, away from anything the firmware uses
BMP_DATA  = 0x30020000       # backing store for the Bitmap we hand the firmware
STUB      = 0x30010000       # unused-slot sentinel (kept for renderers that
                             # dispatch through a function pointer)
SET_PIXEL = 0x40104eb4       # the real Bitmap::setPixel(Bitmap*, x, y, value);
                             # px_copy_to_bitmap calls this directly via a4,
                             # NOT through the +0x0C pointer. Intercept both.


def png(pixels, w, h):
    """8-bit greyscale PNG."""
    raw = b''.join(b'\x00' + bytes(pixels[y*w:(y+1)*w]) for y in range(h))
    def chunk(tag, data):
        c = tag + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c))
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 0, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9))
            + chunk(b'IEND', b''))


class Screen:
    def __init__(self, main_img, intercept=True):
        """intercept=True  capture setPixel calls (fast, format-agnostic)
           intercept=False let the real setPixel run and decode the store,
                          which independently checks the decoded layout."""
        self.img = main_img
        self.intercept = intercept
        self.m = Machine()
        self.fb = {}
        self.calls = 0

        def on_code(uc, addr, size):
            if addr in (STUB, SET_PIXEL) and self.intercept:
                sp = uc.reg_read(UC_M68K_REG_A7)
                ret, _this, x, y, val = struct.unpack('>IIIII', uc.mem_read(sp, 20))
                self.fb[(x, y)] = val & 0xFF
                self.calls += 1
                uc.reg_write(UC_M68K_REG_D0, 0)
                uc.reg_write(UC_M68K_REG_A7, sp + 4)   # caller pops args
                uc.reg_write(UC_M68K_REG_PC, ret)

        self.m.install_isa_patches(extra_code_hook=on_code)
        self.m.install_exceptions()
        self.m.load(main_img, MAIN_LOAD)
        self.m.ensure(STUB)
        self.m.uc.mem_write(STUB, b'\x4e\x71' * 8)     # nops; never actually run

    def make_bitmap(self, w, h):
        """A real Bitmap with backing store, so renderers that read pixels
        back (or that dispatch through +0x0C) behave."""
        stride = (h + 31) // 32
        self.m.ensure(BMP_ADDR); self.m.ensure(BMP_DATA)
        self.m.uc.mem_write(BMP_DATA, b'\x00' * (w * stride * 4))
        self.m.uc.mem_write(BMP_ADDR,
                            struct.pack('>IIIII', 0, w, h, stride, BMP_DATA))
        self.bmp = (w, h, stride)
        return BMP_ADDR

    def read_bitmap(self):
        """Decode the Bitmap's backing store -> {(x, y): 1}."""
        w, h, stride = self.bmp
        raw = bytes(self.m.uc.mem_read(BMP_DATA, w * stride * 4))
        out = {}
        for x in range(w):
            for y in range(h):
                word = struct.unpack_from('>I', raw, (x * stride + (y >> 5)) * 4)[0]
                if word & (0x80000000 >> (y & 31)):
                    out[(x, y)] = 1
        return out

    def copy_pixeldata(self, pd_addr, w, h):
        """Run px_copy_to_bitmap on a PixelData already present in the image."""
        self.fb = {}; self.calls = 0
        bmp = self.make_bitmap(w, h)
        call(self.m, PX_COPY_TO_BITMAP, [pd_addr, bmp])
        return self.render(w, h)

    def render(self, w, h, scale=True):
        """Renderers threshold to 0/1, so scale to 0/255 for viewing."""
        out = bytearray(w * h)
        vals = set(self.fb.values())
        mul = 255 if scale and vals and max(vals) <= 1 else 1
        for (x, y), v in self.fb.items():
            if 0 <= x < w and 0 <= y < h:
                out[y * w + x] = min(255, v * mul)
        return bytes(out)

    def ascii(self, w, h):
        rows = []
        for y in range(h):
            rows.append(''.join('#' if self.fb.get((x, y)) else '.' for x in range(w)))
        return '\n'.join(rows)


def selftest(img):
    """Drive the firmware's own copy routine with a known source and check the
    captured pixels match exactly. Guards against 'it ran' being mistaken for
    'it worked' -- a false-positive PixelData renders as plausible dither."""
    W, H = 40, 16
    src = bytearray(W * H)
    def put(x, y):
        if 0 <= x < W and 0 <= y < H:
            src[y * W + x] = 0xFF
    for x in range(W):
        put(x, 0); put(x, H - 1)
    for y in range(H):
        put(0, y); put(W - 1, y)
    for i in range(1, H - 1):
        put(i + 1, i)
    s = Screen(img)
    SRC, PD = 0x31000000, 0x31100000
    s.m.ensure(SRC); s.m.ensure(PD)
    s.m.uc.mem_write(SRC, bytes(src))
    s.m.uc.mem_write(PD, struct.pack('>III', W, H, SRC))
    s.copy_pixeldata(PD, W, H)
    expect = {(x, y) for y in range(H) for x in range(W) if src[y * W + x] > 0x80}
    got = {k for k, v in s.fb.items() if v}
    ok = (expect == got) and s.calls == W * H
    print('selftest: %d setPixel calls (expected %d), pixels match: %s'
          % (s.calls, W * H, expect == got))
    return ok


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'selftest':
        sys.exit(0 if selftest(open('sections/section_3_MAIN_OS.bin', 'rb').read()) else 1)

    img = open('sections/section_3_MAIN_OS.bin', 'rb').read()
    base = MAIN_LOAD
    pd = int(sys.argv[1], 16)
    w, h = struct.unpack_from('>II', img, pd - base)
    print('PixelData@0x%08x  %dx%d' % (pd, w, h))
    s = Screen(img)
    px = s.copy_pixeldata(pd, w, h)
    print('setPixel calls: %d  non-zero pixels: %d' % (s.calls, sum(1 for b in px if b)))
    out = sys.argv[2] if len(sys.argv) > 2 else 'out/render.png'
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, 'wb').write(png(px, w, h))
    print('wrote', out)
    if w <= 140:
        print(s.ascii(w, h))


if __name__ == '__main__':
    main()
