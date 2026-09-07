"""The four programmable interval timers, gated on their own enable bits.

After the intro the system is correctly idle: every task blocks and nothing
delivers the interrupts that would wake them. The one that matters is PIT2.
Its ISR (vector 207, `0x40002a18`) does nothing but ack the timer and post
semaphore `0x47d9ade0`, which is the tick of the RTOS software-timer wheel.
The wheel task at `0x40002a46` then walks a callback list at `0x4094cdb8`,
firing each entry whose mask matches a rolling counter -- mask 1 every tick,
mask 4 every fourth, mask 0x80 every 128th. Seven callbacks are registered and
all seven point at real code, including `0x4012651e` in the display module.
That list is the OS heartbeat, and without PIT2 nothing turns it.

Rates come from the firmware's own registers rather than being hardcoded:

    prescaler = 1 << (((PCSR >> 8) & 0xF) + 1)
    period    = prescaler * (PMR + 1) bus cycles, at 132 MHz

which reproduces all three known rates exactly -- PIT0 20.0000 ms (50 Hz),
PIT2 16.6672 ms (59.998 Hz), PIT3 66.6686 ms (14.9996 Hz). Three independent
timers landing on round numbers is what validates the 132 MHz bus clock.

**PIT0 matters as much as PIT2, for a different reason.** It is the RTOS's
time-slice timer: the context switcher at `0x40000410` re-arms it on every
switch (`move.w #$53f,$fc080000`) and unmasks its INTC source (`and.l
#$ffffdfff,$fc050014` clears IMRL bit 13, source 13 = vector 205), and vector
205's handler *is* the switcher. Delivering PIT2 without PIT0 gives the RTOS
timer-wheel ticks while denying it preemption, and the result is not merely
slower -- it is unstable. Measured over 60M instructions from
`postintro.snap`, PIT2 alone crashed or aborted at five of six chunk sizes
tried; adding PIT0 removed every abort and every spurious exception, and left
faults at only two. So both are on by default.

Delivery is gated on PCSR bit 0 (enable) and bit 3 (interrupt enable), so the
intro switching PIT3 off with its own `move.w d0,$fc08c000` stops frame
delivery without the emulator being told, and the display module switching
PIT3 back on at `0x40126004` starts it again. It is gated on the interrupt
controller too -- the source's ICR level, and its mask bit, both of which the
context switcher manipulates. And it is gated on the CPU's IPL: an interrupt
whose level is not above the current IPL cannot be taken. A tick the hardware
could not have taken is counted as missed, never forced.

Levels come from the INTC, not from us: vector 205 is INTC2 source 13, and
`0xFC050040 + source` reads 1 for PIT0, 3 for PIT2 and 3 for PIT3.

Pacing is an instruction count, not real time. `INSTR_PER_SEC` is 4.68M, from
the measured 312k instructions per intro frame at 15 fps. It is a proxy, and
only as good as the assumption that instruction rate tracks wall clock --
which it does not while a task spins. Good enough to turn the RTOS over; not
cycle accuracy, and it should not be described as such.

**Deliver from a chunk boundary, and re-read PC afterwards.** `raise_vector`
moves PC, so a caller that captured PC before servicing must refresh it, or
emulation resumes at the interrupted address with an exception frame stranded
on the stack. The next `rts` then pops that frame as a return address and
jumps to nowhere -- observed as a jump to `0x033C2004` and a vector-4 fault
exactly one tick after the first. `emu/longrun.py:spin` does this correctly;
a hand-rolled loop is where it goes wrong.
"""
import collections
import struct

from unicorn.m68k_const import UC_M68K_REG_SR

BASES   = (0xFC080000, 0xFC084000, 0xFC088000, 0xFC08C000)
VECTORS = (205, 206, 207, 208)
EN, PIE = 0x01, 0x08                  # PCSR bit 0 and bit 3
F_BUS = 132_000_000
INSTR_PER_SEC = 4_680_000             # 312k instructions per frame at 15 fps

# Each interrupt controller owns 64 vectors: INTC0 64-127, INTC1 128-191,
# INTC2 192-255. Per source there is an ICR byte at +0x40+source whose low
# three bits are the level, and a mask bit in IMRH/IMRL at +0x08/+0x0C.
INTC = ((0xFC048000, 64), (0xFC04C000, 128), (0xFC050000, 192))
ICR_BASE, IMR_BASE = 0x40, 0x08


class Pits:
    """Deliver PIT interrupts on an instruction-count clock.

    `channels` defaults to PIT0 and PIT2: the time slice and the timer-wheel
    tick. Delivering only one of them is measurably worse than delivering
    both -- see the module docstring.
    """

    def __init__(self, m, channels=(0, 2), instr_per_sec=INSTR_PER_SEC):
        self.m = m
        self.channels = tuple(channels)
        self.ips = instr_per_sec
        self.next = [None] * 4
        self.fired = collections.Counter()
        self.missed = collections.Counter()

    def period(self, ch):
        """-> instructions between interrupts, or None while the timer is off."""
        pcsr, pmr = struct.unpack('>HH', self.m.uc.mem_read(BASES[ch], 4))
        if not (pcsr & EN) or not (pcsr & PIE):
            return None
        prescale = 1 << (((pcsr >> 8) & 0xF) + 1)
        return prescale * (pmr + 1) / F_BUS * self.ips

    def level(self, vec):
        """-> the source's interrupt level, or None if masked or disabled.

        Read from the INTC rather than assumed, because the RTOS changes it:
        the context switcher unmasks PIT0's source on every switch.
        """
        for base, first in INTC:
            if first <= vec < first + 64:
                src = vec - first
                break
        else:
            return None
        icr = self.m.uc.mem_read(base + ICR_BASE + src, 1)[0] & 0x07
        if not icr:                       # level 0 means the source is off
            return None
        imrh, imrl = struct.unpack('>II', self.m.uc.mem_read(base + IMR_BASE, 8))
        masked = (imrl >> src) & 1 if src < 32 else (imrh >> (src - 32)) & 1
        return None if masked else icr

    def service(self, done):
        """Call at a chunk boundary with the instruction count so far.

        The caller MUST re-read PC afterwards -- see the module docstring.
        """
        for ch in self.channels:
            p = self.period(ch)
            if p is None:
                self.next[ch] = None       # off; restart the clock if it returns
                continue
            if self.next[ch] is None:
                self.next[ch] = done + p
                continue
            if done < self.next[ch]:
                continue
            self.next[ch] += p
            vec = VECTORS[ch]
            lvl = self.level(vec)
            sr = self.m.uc.reg_read(UC_M68K_REG_SR)
            if lvl is None or ((sr >> 8) & 0x07) >= lvl:
                self.missed[ch] += 1       # the hardware could not take it either
            elif self.m.raise_vector(vec):
                # Taking an interrupt raises the mask to its own level, so the
                # handler cannot be re-entered by the same source.
                self.m.uc.reg_write(UC_M68K_REG_SR,
                                    (sr & ~0x0700) | (lvl << 8) | 0x2000)
                self.fired[ch] += 1
