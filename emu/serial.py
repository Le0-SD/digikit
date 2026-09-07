"""UART8 receive, which does not go through the CPU at all.

The thing we were overlooking about this ColdFire is **eDMA**. Feeding bytes to
`emu/console.py`'s programmed-I/O UART model could never have worked, because
the firmware never reads UDR8 to receive: DMA channel 34 does it.

From the init at 0x40002516 and the ISR at 0x40001f1a:

    TCD34.SADDR = 0xEC07000C          ; UDR8, fixed (SOFF = 0)
    TCD34.ATTR  = 0x0050              ; DMOD = 10 -> destination modulo 1024
    TCD34.DADDR = 0x4FE1A000          ; a 1024-byte ring
    TCD34.NBYTES = 1                  ; one byte per request

    vector 154 (0x40001f1a):
        idx  = [0x4094CDA4]           ; consume index
        base = [0x4094CD84]           ; ring base
        while base + idx != [0xFC045450]:      ; DADDR is the live write pointer
            byte = ring[idx]; idx = (idx + 1) & 0x3FF
            [0x4094CDB4](byte)                 ; registered callback

So the DMA's own DADDR register is the producer pointer and the ISR polls it.
That means injecting input needs no general eDMA emulation -- just write into
the ring, advance DADDR with the same 1024 modulo, and raise vector 154.

Verified working: feeding b'#HELLO\\r\\n' drives the callback exactly 8 times
and the bytes are enqueued onto the serial message queue at 0x47D9ADC0.

What is NOT yet working: nothing drains 0x47D9ADC0. Its consumer is the task
at 0x401136EE (prio 3), created lazily by the singleton at 0x401134CC (guard
0x44F1E070) the first time anything asks for the serial service -- and nothing
in our boot ever does. `create_serial_task` below runs that initialiser, which
does create the task, but it has not been observed draining the queue yet.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn.m68k_const import UC_M68K_REG_PC

RING_BASE_PTR = 0x4094CD84      # -> 0x4FE1A000
CONSUME_IDX   = 0x4094CDA4
RX_CALLBACK   = 0x4094CDB4
TCD34_DADDR   = 0xFC045450      # eDMA channel 34, live write pointer
RX_VECTOR     = 154
RING_MASK     = 0x3FF

SERIAL_QUEUE  = 0x47D9ADC0      # where received bytes end up
CONSOLE_QUEUE = 0x40388EAC      # what the console task waits on
ALLOC         = 0x401114A8
SERIAL_INIT   = 0x401134CC      # creates the 0x401136EE consumer task
SERIAL_GUARD  = 0x44F1E070

STUB_ADDR     = 0x32000000      # scratch for synthesised call stubs
STUB_VECTOR   = 201


def _u32(m, addr):
    return struct.unpack('>I', m.uc.mem_read(addr, 4))[0]


def feed(m, data):
    """Deliver bytes as if DMA had received them. -> new PC.

    Writes into the receive ring, advances the channel's DADDR with the same
    modulo the hardware applies, then raises the RX vector so the firmware's
    own ISR drains it.
    """
    base = _u32(m, RING_BASE_PTR)
    daddr = _u32(m, TCD34_DADDR)
    for byte in data:
        m.uc.mem_write(daddr, bytes([byte]))
        daddr = base + (((daddr - base) + 1) & RING_MASK)
    m.uc.mem_write(TCD34_DADDR, struct.pack('>I', daddr))
    m.raise_vector(RX_VECTOR)
    return m.uc.reg_read(UC_M68K_REG_PC)


def create_serial_task(m):
    """Run the lazy initialiser that creates the 0x401136EE consumer task.

    The firmware only calls this on first use of the serial service, which our
    boot never reaches. Synthesised as a stub run through an unused vector, so
    it executes in the machine's own context rather than hijacking registers:

        pea.l $40 ; jsr ALLOC ; addq.l #4,a7
        move.l d0,-(a7) ; jsr SERIAL_INIT ; addq.l #4,a7 ; rte
    """
    stub = (struct.pack('>HH', 0x4878, 0x0040)
            + struct.pack('>HI', 0x4EB9, ALLOC)
            + b'\x58\x8f'
            + b'\x2f\x00'
            + struct.pack('>HI', 0x4EB9, SERIAL_INIT)
            + b'\x58\x8f'
            + b'\x4e\x73')
    m.ensure(STUB_ADDR)
    m.uc.mem_write(STUB_ADDR, stub)
    m.uc.mem_write(0x40000000 + STUB_VECTOR * 4, struct.pack('>I', STUB_ADDR))
    m.raise_vector(STUB_VECTOR)
    return m.uc.reg_read(UC_M68K_REG_PC)


def state(m):
    """Everything worth looking at when debugging serial input."""
    base = _u32(m, RING_BASE_PTR)
    return {
        'ring_base': base,
        'daddr': _u32(m, TCD34_DADDR),
        'produced': _u32(m, TCD34_DADDR) - base,
        'consumed': _u32(m, CONSUME_IDX),
        'rx_callback': _u32(m, RX_CALLBACK),
        'serial_q_count': _u32(m, SERIAL_QUEUE + 4),
        'console_q_count': _u32(m, CONSOLE_QUEUE + 4),
        'serial_task_made': _u32(m, SERIAL_GUARD) != 0,
    }


if __name__ == '__main__':
    from emu.longrun import build, spin
    snap = sys.argv[1] if len(sys.argv) > 1 else 'snapshots/console450M.snap'
    cmd = (sys.argv[2] if len(sys.argv) > 2 else '#HELLO').encode() + b'\r\n'
    m, ev, st, pc, inq, at = build(snap)
    hits = {'callback': 0}
    at(_u32(m, RX_CALLBACK),
       lambda uc, a, s, d: hits.__setitem__('callback', hits['callback'] + 1))
    pc, _, _ = spin(m, pc, 2_000_000)
    def show(tag):
        st_ = state(m)
        print('%-7s ring=0x%08x produced=%d consumed=%d  serial_q=%d '
              'console_q=%d  serial_task=%s'
              % (tag, st_['ring_base'], st_['produced'], st_['consumed'],
                 st_['serial_q_count'], st_['console_q_count'],
                 st_['serial_task_made']))
    show('before')
    pc = create_serial_task(m)
    pc, _, _ = spin(m, pc, 20_000_000)
    pc = feed(m, cmd)
    pc, _, _ = spin(m, pc, 60_000_000)
    show('after')
    print('rx callback invocations: %d (expected %d)' % (hits['callback'], len(cmd)))
    print('prints: %r' % ev['prints'][:20])
    print('uart out: %r' % bytes(ev['uart_out'])[:200])
