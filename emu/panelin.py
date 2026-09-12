"""Front-panel input: buttons and encoders, delivered the way hardware does.

There is no key matrix to model. `tools/mmiotrace.py` measured 60M post-intro
instructions on each build and found zero GPIO, zero DSPI and zero unclaimed
MMIO -- the ColdFire never scans a panel. A separate microcontroller does, and
it talks over UART8: eDMA channel 34 fills a 1024-byte ring and vector 154
hands each byte to the driver's receive callback.

The wire format is a header byte followed by a payload:

    header = (tag << 4) | channel

    tag 0x2   1 byte   buttons -- an 8-bit STATE BITMASK for that channel's
                       eight buttons, not a press/release event. The firmware
                       XORs it against the previous byte for the channel and
                       derives the edges itself, so a caller only has to say
                       what is held right now.
    tag 0x3   1 byte   encoders -- a SIGNED delta, not gray code and not
                       separate inc/dec messages. Channels 0..8 map through a
                       nine-entry table: eight data encoders plus level.
    tag 0x7   8 bytes  a block the console task consumes; not input.

Any other tag is parsed and discarded by the firmware.

The parser is byte-identical in both builds -- only the data addresses move.
That is why every address here comes from `emu/symbols.py` instead of being
written down: `emu/serial.py` hardcoded Digitakt's and so did the wrong thing
on Digitone in silence.
"""
import struct

from unicorn.m68k_const import UC_M68K_REG_PC

# eDMA channel 34's live write pointer. A hardware register, so unlike every
# driver address in this module it really is the same in both builds.
TCD34_DADDR = 0xFC045450

RX_VECTOR = 154
RING_MASK = 0x3FF

TAG_BUTTON = 0x2
TAG_ENCODER = 0x3

# Eight data encoders plus the level encoder. Corroborated independently:
# the firmware's channel->index table has exactly nine valid entries in both
# builds, and runs into unrelated rodata past that.
ENCODERS = 9


def _u32(m, addr):
    return struct.unpack('>I', m.uc.mem_read(addr, 4))[0]


def feed(m, profile, data):
    """Deliver raw bytes as the panel's DMA would. -> new PC.

    Writes into the receive ring, advances the channel's DADDR with the same
    modulo the hardware applies, then raises the RX vector so the firmware's
    own ISR drains it. This is `emu/serial.py`'s mechanism -- proven there by
    the receive callback firing once per byte -- with the ring pointer
    resolved per build rather than hardcoded to Digitakt's.
    """
    base = _u32(m, profile.uart8_ring_ptr)
    daddr = _u32(m, TCD34_DADDR)
    for byte in data:
        m.uc.mem_write(daddr, bytes([byte]))
        daddr = base + (((daddr - base) + 1) & RING_MASK)
    m.uc.mem_write(TCD34_DADDR, struct.pack('>I', daddr))
    m.raise_vector(RX_VECTOR)
    return m.uc.reg_read(UC_M68K_REG_PC)


def buttons(m, profile, channel, mask):
    """Set the state of one group of eight buttons. -> new PC.

    `mask` is the whole group's state, bit n meaning button n of `channel` is
    held. The firmware edge-detects against what it last saw, so holding
    button 3 of group 0 and then letting go is `buttons(.., 0, 0x08)` then
    `buttons(.., 0, 0x00)` -- there is no separate release message on the
    wire.
    """
    if not 0 <= channel <= 0x0F:
        raise ValueError('button channel must be 0..15, got %r' % (channel,))
    if not 0 <= mask <= 0xFF:
        raise ValueError('button mask must be a byte, got %r' % (mask,))
    return feed(m, profile, bytes([(TAG_BUTTON << 4) | channel, mask]))


def press(m, profile, channel, bit, held=0):
    """Hold one button down, with `held` (a mask) still held alongside it."""
    if not 0 <= bit <= 7:
        raise ValueError('button bit must be 0..7, got %r' % (bit,))
    return buttons(m, profile, channel, held | (1 << bit))


def release(m, profile, channel, bit, held=0):
    """Let one button up, with `held` (a mask) still held."""
    if not 0 <= bit <= 7:
        raise ValueError('button bit must be 0..7, got %r' % (bit,))
    return buttons(m, profile, channel, held & ~(1 << bit))


def encoder(m, profile, channel, delta):
    """Turn one encoder by `delta` detents; negative is counter-clockwise.

    The firmware accumulates deltas per encoder and clamps what it flushes to
    +/-30, so a value outside a signed byte is refused here rather than
    wrapping silently into the opposite direction.
    """
    if not 0 <= channel < ENCODERS:
        raise ValueError('encoder channel must be 0..%d, got %r'
                         % (ENCODERS - 1, channel))
    if not -128 <= delta <= 127:
        raise ValueError('encoder delta must fit a signed byte, got %r'
                         % (delta,))
    return feed(m, profile, bytes([(TAG_ENCODER << 4) | channel,
                                   delta & 0xFF]))


def state(m, profile):
    """Everything worth looking at when panel input is not landing."""
    base = _u32(m, profile.uart8_ring_ptr)
    daddr = _u32(m, TCD34_DADDR)
    return {
        'ring_base': base,
        'daddr': daddr,
        'produced': daddr - base,
        'consumed': _u32(m, profile.uart8_consume_idx),
        'rx_callback': _u32(m, profile.uart8_rx_callback),
    }
