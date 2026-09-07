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

Delivery is gated on PCSR bit 0 (enable) and bit 3 (interrupt enable), so the
intro switching PIT3 off with its own `move.w d0,$fc08c000` stops frame
delivery without the emulator being told, and the display module switching
PIT3 back on at `0x40126004` starts it again. Delivery is also gated on the
CPU's IPL: an interrupt cannot be taken at IPL 7, and a large fraction of
chunk boundaries sit there, so a missed tick is normal. Missed ticks are
counted, not forced -- forcing one is not something the hardware could do.

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


class Pits:
    """Deliver PIT interrupts on an instruction-count clock.

    `channels` defaults to PIT2 alone, because that is the one the OS heartbeat
    hangs off and because PIT0's vector is the context switcher -- injecting
    that forces a reschedule inside arbitrary code, which has its own history
    of breaking resumed runs.
    """

    def __init__(self, m, channels=(2,), instr_per_sec=INSTR_PER_SEC):
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
            if (self.m.uc.reg_read(UC_M68K_REG_SR) & 0x0700) == 0x0700:
                self.missed[ch] += 1       # IPL 7; the hardware could not either
            elif self.m.raise_vector(VECTORS[ch]):
                self.fired[ch] += 1
