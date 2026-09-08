"""The 0x8C000000 coprocessor port's ready line.

`0x8C000000` is a FlexBus-attached coprocessor addressed in 4 KB pages. The
transfer primitive `0x400cf4a8(word)` writes four bytes most-significant
first, each as two 16-bit writes to `0x8C000002` -- `(byte << 8) | 0x80`
then `(byte << 8)` -- so bit 7 of the low byte is a write clock strobe and
the data rides in the high byte. Before the burst it writes `0x80` to
`0x8C00000A` and then spins at `0x400cf4ec` until bit 0 of a 16-bit read of
`0x8C000002` is set. That bit is the device's ready line.

`0x400cfd40(cmd, buf, swap)` locks the scheduler, sends `cmd` as a
four-byte header, then sends 4096 bytes from `buf` in four-byte groups,
then sleeps 100 microseconds through `0x40128c7c`. A `cmd` of `0xFFFFFFFF`
marks a command block; anything else is a page index, from
`0x40146148(addr, src, len)` which writes `len` bytes as 4 KB pages.

Nothing in the emulator backed that address, so bit 0 read as zero forever
and the priority-3 job worker `0x400f1fce` wedged in the spin on the very
first burst -- measured as 9.7M of 60M instructions in a two-instruction
loop, with `0x400cf4a8` entered exactly once and never returning. Because
that worker never finished its first job, none of the five queued jobs
(`KitActive::updateSingleMirror`, `saveProjectToMmc(tempProject)`,
`Migrate presets`, `Update MMC Caches`, `Load all samples`) ever ran.

State honestly what this model is and is not: it makes the ready line
readable, and **the pacing comes from the firmware's own 100 microsecond
sleep between 4 KB transfers, not from us**. We do not know the device's
real word-accept rate, so a `poll_delay` knob is provided (report ready
only after that many consecutive status polls) and defaults to 0, meaning
always ready. Nothing beyond the ready line is modelled: writes are
accepted and discarded, and if the firmware ever needs a *response* from
this device the model will have to grow.
"""
import struct

from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE

BASE   = 0x8C000000
STATUS = BASE + 0x02        # 16-bit: read = status (bit 0 ready), write = data
LATCH  = BASE + 0x0A        # written 0x80 to open a burst
READY  = 0x0001


class Fifo:
    """The ready line of the 0x8C000000 coprocessor port."""

    def __init__(self, m, poll_delay=0):
        self.m = m
        self.poll_delay = poll_delay
        self.polls = 0            # consecutive status reads since the last write
        self.words = 0            # data words accepted, for reporting
        # One latch write per FOUR-BYTE GROUP, not per 4KB transfer:
        # 0x400cf4a8 opens the port for each group, so a single
        # 0x400cfd40 push of 4096 bytes shows up as 1025 of these.
        self.bursts = 0

        # A scoped hook is used rather than Machine.mmio because the value
        # is computed, not constant, and the reads are 16-bit so only two
        # bytes are written back -- Machine.install_mmio writes four and
        # would clobber 0x8C000004.
        def on_read(uc, typ, addr, size, val, data):
            self.polls += 1
            ready = READY if self.polls > self.poll_delay else 0
            uc.mem_write(STATUS, struct.pack('>H', ready))
        m.uc.hook_add(UC_HOOK_MEM_READ, on_read, begin=STATUS, end=STATUS + 1)

        def on_write(uc, typ, addr, size, val, data):
            self.words += 1
            self.polls = 0
        m.uc.hook_add(UC_HOOK_MEM_WRITE, on_write, begin=STATUS, end=STATUS + 1)

        def on_latch(uc, typ, addr, size, val, data):
            self.bursts += 1
        m.uc.hook_add(UC_HOOK_MEM_WRITE, on_latch, begin=LATCH, end=LATCH + 1)


def install(m, ev=None, poll_delay=0):
    """Model the coprocessor port's ready line. -> the Fifo, also ev['dsp']."""
    fifo = Fifo(m, poll_delay)
    if ev is not None:
        ev['dsp'] = fifo
    return fifo
