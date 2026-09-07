"""Native soft-float, because 93% of emulated instructions were soft-float.

This ColdFire build has no hardware FPU, so every float operation in the
firmware is a libgcc-style routine. Profiling the intro animation found that
**93.2% of all executed instructions** live in 0x40174000-0x40176000 -- the
particle simulation is float-heavy and each multiply costs hundreds of
emulated instructions.

Emulating them is pure waste: the operations are IEEE-754 binary32, which the
host does in one machine instruction. Intercepting each routine at its entry
and returning the host's answer removes ~90% of the work.

Correctness note: computing in float64 and rounding once to float32 gives
exactly the correctly-rounded float32 result for +, -, * and /, because
float64 carries 53 bits and 2*24+2 = 50 <= 53. So for normal values this is
not an approximation of the firmware's arithmetic -- it is the same answer.

The firmware's routines are NOT IEEE-754 at the edges, though: `subsf3` is
`bchg.b #$1f,$8(a7)` (flip arg2's sign) falling into `addsf3`, and that add
returns -0.0 on exact cancellation where IEEE says +0.0, and gets infinity
signs wrong. Rather than replicate quirks, the HLE **only intercepts the fast
path** -- finite arguments producing a finite, normal, non-zero result -- and
otherwise falls through to the real routine, which then defines the answer by
construction. This mirrors how the sem_pend patch takes the primitive's own
fast path instead of reimplementing it.

Entry points were found by watching which addresses execution actually enters
the region at, then identified by calling each one and comparing against known
arithmetic -- not by guessing at libgcc names.

    uv run python -m emu.softfloat        # verify against the real routines
"""
import math
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_D0, UC_M68K_REG_PC

INF, NINF = 0x7F800000, 0xFF800000
QNAN = 0x7FC00000


def b2f(bits):
    return struct.unpack('>f', struct.pack('>I', bits & 0xFFFFFFFF))[0]


def f2b(x):
    """float -> binary32 bits, saturating to infinity on overflow."""
    try:
        return struct.unpack('>I', struct.pack('>f', x))[0]
    except (OverflowError, ValueError):
        if x != x:
            return QNAN
        return INF if x > 0 else NINF


TINY = 2.0 ** -126          # smallest normal binary32


def _fast(x):
    return -3.4028235e38 <= x <= 3.4028235e38 and (x == 0.0 or abs(x) >= TINY)


def _div(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        if a != a or a == 0.0:
            return float('nan')          # 0/0 and nan/0
        return math.copysign(float('inf'), a) * math.copysign(1.0, b)


def _fix(a):
    """C float->int, truncating toward zero.

    Out-of-range is undefined behaviour in C and the firmware's routine
    returns 0xFFFFFFFF for it, so decline those (None = defer) rather than
    invent a saturating answer it does not give.
    """
    if not (-2147483648.0 <= a < 2147483648.0):
        return None
    return int(a) & 0xFFFFFFFF


def _cmp(a, b):
    if a != a or b != b:
        return 1                          # unordered
    return ((a > b) - (a < b)) & 0xFFFFFFFF


# addr -> (name, arity, fn, returns_float)
ROUTINES = {
    0x40175204: ('mulsf3',  2, lambda a, b: a * b, True),
    0x40174f1c: ('subsf3',  2, lambda a, b: a - b, True),
    0x40174f22: ('addsf3',  2, lambda a, b: a + b, True),
    0x40175346: ('divsf3',  2, _div,               True),
    0x40174134: ('abssf2',  1, abs,                True),
    0x40175a94: ('fixsfsi', 1, _fix,               False),
    0x40175834: ('cmpsf2',  2, _cmp,               False),
}


# Precompiled codecs. The stack already holds IEEE-754 binary32, so unpacking
# the arguments directly as '>f' skips the bits->float step entirely; b2f/f2b
# each cost a pack AND an unpack, and these handlers run tens of thousands of
# times per frame.
_ARGS = {1: struct.Struct('>If'), 2: struct.Struct('>I2f')}
_PACK_F = struct.Struct('>f')
_TO_BITS = struct.Struct('>I')


def install(at, stats=None):
    """Register HLE hooks. `at(addr, fn)` is longrun.build's hook registrar.

    Each handler pops only the return address, leaving the arguments for the
    caller to clean -- the same convention the real routines use, and the same
    one dspboot's flash-read HLE follows.
    """
    def make(arity, fn, is_float, name):
        codec = _ARGS[arity]
        size = codec.size
        unpack = codec.unpack
        pack_f = _PACK_F.pack
        to_bits = _TO_BITS.unpack
        fast = _fast

        def h(uc, addr, sz, data):
            sp = uc.reg_read(UC_M68K_REG_A7)
            vals = unpack(uc.mem_read(sp, size))
            args = vals[1:]
            for a in args:
                if not fast(a):
                    if stats is not None:
                        stats['deferred'] += 1
                    return                  # let the real routine run
            out = fn(*args)
            if is_float:
                if out is None or not (fast(out) and out != 0.0):
                    if stats is not None:
                        stats['deferred'] += 1
                    return                  # signed zero / overflow: firmware decides
                out = to_bits(pack_f(out))[0]
            elif out is None:
                if stats is not None:
                    stats['deferred'] += 1
                return
            uc.reg_write(UC_M68K_REG_D0, out & 0xFFFFFFFF)
            uc.reg_write(UC_M68K_REG_A7, sp + 4)
            uc.reg_write(UC_M68K_REG_PC, vals[0])
            if stats is not None:
                stats[name] += 1
        return h

    for addr, (name, arity, fn, is_float) in ROUTINES.items():
        at(addr, make(arity, fn, is_float, name))
    return len(ROUTINES)


def selftest(verbose=True):
    """Compare every HLE routine against the firmware's own implementation."""
    from emu.harness import Machine, call
    import emu.dspboot as db
    img = open('sections/section_3_MAIN_OS.bin', 'rb').read()

    def fresh():
        m = Machine()
        m.install_isa_patches_scoped(img, db.MAIN_LOAD)
        m.install_exceptions()
        m.load(img, db.MAIN_LOAD)
        return m

    vals = [0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 3.75, -2.5, 17.0, 1234.5,
            1e-8, -1e-8, 1e12, -1e12, 3.4e38, -3.4e38, 1.4e-45, 7.9,
            float('inf'), float('-inf'), float('nan'), 0.1, 65504.0, 12.0]
    machine = fresh()
    bad = total = deferred = 0
    per = {}
    for addr, (name, arity, fn, is_float) in sorted(ROUTINES.items()):
        pairs = ([(a, b) for a in vals for b in vals] if arity == 2
                 else [(a,) for a in vals])
        for args in pairs:
            if not all(_fast(x) for x in args):
                deferred += 1
                continue                    # HLE would not intercept these
            total += 1
            bits = [f2b(x) for x in args]
            try:
                real = call(machine, addr, bits, limit=400_000) & 0xFFFFFFFF
            except Exception as exc:                      # noqa: BLE001
                print('  %-8s %s -> firmware raised %s' % (name, args, exc))
                bad += 1
                machine = fresh()
                continue
            out = fn(*[b2f(b) for b in bits])
            if out is None or is_float and not (_fast(out) and out != 0.0):
                deferred += 1
                total -= 1
                continue                    # HLE would not intercept these either
            got = f2b(out) if is_float else out & 0xFFFFFFFF
            same = got == real
            if not same:
                bad += 1
                per[name] = per.get(name, 0) + 1
                if bad <= 12:
                    print('  MISMATCH %-8s%s  hle=0x%08x (%r)  firmware=0x%08x (%r)'
                          % (name, args, got, b2f(got) if is_float else got,
                             real, b2f(real) if is_float else real))
    if verbose:
        print('softfloat selftest: %d intercepted cases checked against the '
              'firmware, %d mismatches' % (total, bad))
        print('  %d edge cases deferred to the real routine (inf/nan/zero/'
              'denormal/overflow)' % deferred)
        if per:
            print('  mismatches by routine: %s' % per)
    return bad == 0


if __name__ == '__main__':
    raise SystemExit(0 if selftest() else 1)
