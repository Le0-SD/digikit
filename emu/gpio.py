"""The board loopback that decides whether storage exists.

This is the answer to "why does the eSDHC driver never run" (HANDOVER 6b).

`0x400cf20a` calls the gate `0x4011fe60` and then:

    400cf214  tst.l d0
    400cf216  bne.b $400cf258     ; NON-ZERO -> skip card init entirely
    400cf218  jsr $4011fed6       ; card init, only when d0 == 0

so storage initialises only when the gate returns **zero**, and the gate returns
zero only by falling out of its ten-iteration loop:

    4011fe8c  moveq #$b,d0        ; 11
    4011fe8e  subq.l #1,d0        ; ..10, 9, 8
    4011fe90  beq.b $4011feca     ; exhausted -> return 0  == "card is there"
    4011fe96  move.b #$10,$ec09401b   ; PPDSDR_D: write 1 SETS  -> drive D4 high
    4011fe9c  move.b $ec09401a,d1     ; PPDSDR_C: read the pins
    4011fea6  bne.b $4011feb2         ; C3 high -> second half; low -> return 1
    4011feb6  move.b #$ef,$ec094027   ; PCLRR_D: write 0 CLEARS -> drive D4 low
    4011febc  move.b $ec09401a,d1
    4011fec4  beq.b $4011fe8e         ; C3 low -> go round again
    4011fec8  bra.b $4011fea8         ; C3 still high -> return 1

Read it as a continuity check: drive D4 high and C3 must go high, drive D4 low
and C3 must go low, ten times over. Anything else is an early return 1 and the
whole eSDHC is skipped. **The success case is the loop running out**, which is
backwards from how these usually read and is worth pointing out.

Unmodelled GPIO reads zero, so C3 is low on the very first read, the gate
returns 1 on its first pass, and the driver is never entered — measured from
`boot40M.snap` over 120M instructions: gate 1 hit, card init 0 hits, zero eSDHC
register accesses ever.

`0xEC094000` is the GPIO port module (RM chapter 15): PODR +0x00, PDDR +0x0C,
PPDSDR +0x18, PCLRR +0x24, one byte per port A..K. So `0xec09401a` is
PPDSDR_C, `0xec09401b` is PPDSDR_D and `0xec094027` is PCLRR_D.

**Turning this on alone will hang the boot**, and that is the model being
honest rather than a bug in it: with the gate satisfied the driver proceeds
into `0x4011fed6` and spins forever at `0x4012001e` waiting for SYSCTL's INITA
bit to self-clear, because nothing models the eSDHC. Measured: 36,988,467
SYSCTL reads and no progress. It is useful now for reaching the driver, and
becomes usable when there is a controller model behind it.
"""
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE

GPIO = 0xEC094000
PODR, PDDR, PPDSDR, PCLRR = GPIO, GPIO + 0x0C, GPIO + 0x18, GPIO + 0x24
PORT_C, PORT_D = 2, 3

PPDSDR_C = PPDSDR + PORT_C      # 0xEC09401A -- read: the pins
PPDSDR_D = PPDSDR + PORT_D      # 0xEC09401B -- write 1 to SET an output bit
PCLRR_D = PCLRR + PORT_D        # 0xEC094027 -- write 0 to CLEAR an output bit

DRIVE_BIT = 0x10                # port D bit 4, the driven side
SENSE_BIT = 0x08                # port C bit 3, the sensed side


class SdGate:
    """Wire port C bit 3 to follow port D bit 4, which is what the board does.

    Three narrow hooks, so nothing runs on unrelated memory traffic. Reading
    the sensed port is serviced the way `Machine.install_mmio` does it -- write
    the value into the backing store from inside the read hook.
    """

    def __init__(self, m):
        uc = m.uc
        self.m = m
        self.driven = 0
        self.sets = 0
        self.clears = 0
        self.senses = 0

        def on_set(u, typ, addr, size, val, data):
            if val & DRIVE_BIT:
                self.driven = 1
                self.sets += 1

        def on_clear(u, typ, addr, size, val, data):
            # PCLRR clears the bits written as ZERO and leaves ones alone.
            if not (val & DRIVE_BIT):
                self.driven = 0
                self.clears += 1

        def on_sense(u, typ, addr, size, val, data):
            self.senses += 1
            cur = bytes(u.mem_read(PPDSDR_C, 1))[0] & ~SENSE_BIT
            u.mem_write(PPDSDR_C,
                        bytes([cur | (SENSE_BIT if self.driven else 0)]))

        uc.hook_add(UC_HOOK_MEM_WRITE, on_set, begin=PPDSDR_D, end=PPDSDR_D)
        uc.hook_add(UC_HOOK_MEM_WRITE, on_clear, begin=PCLRR_D, end=PCLRR_D)
        uc.hook_add(UC_HOOK_MEM_READ, on_sense, begin=PPDSDR_C, end=PPDSDR_C)

    def __repr__(self):
        return ('SdGate(driven=%d sets=%d clears=%d senses=%d)'
                % (self.driven, self.sets, self.clears, self.senses))
