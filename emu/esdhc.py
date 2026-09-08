"""The eSDHC controller and the eMMC behind it.

`0xFC0CC000`, 16 KB, PBC0 slot 51 (RM chapter 25). Reached only when
`build(sdgate=True)` satisfies the board loopback of `emu/gpio.py` -- without
that the driver is never entered at all. See HANDOVER section 6b.

What the firmware does with it, from the driver map:

  * `0x4011fe10` writes CMDARG then XFERTYP -- **writing XFERTYP issues the
    command** -- and then blocks on semaphore `0x44e26f38`, returning the
    status word `0x44e26f1c` that the ISR is supposed to have written.
  * `0x401208fe` reads blocks with CMD18, `0x40120ae4` writes with CMD25.
  * `XFERTYP[DMAEN]` is never set and DSADDR/ADMASAR are never referenced: the
    controller's own DMA is unused, and bulk data moves through the SoC's eDMA
    with `SADDR = DATPORT`.
  * Init ends with the eMMC **bus test**, and it is a real handshake, not a
    magic number. `0x40120242` writes `0x5A` to DATPORT under CMD19
    (BUSTEST_W), then CMD14 (BUSTEST_R) must read back a word whose low byte
    XORed with `0xA5` is zero (`0x401202c6`). `~0x5A == 0xA5`: the card returns
    the inverse of whatever the host sent, so the model inverts the captured
    pattern rather than hardcoding the constant.

Modelling notes that cost time:

**Reads are served from the backing store, not a read hook.** Every register
this model owns is kept up to date in guest memory as state changes, so an
ordinary read just works and no hook runs on the hot path. Only two addresses
carry write hooks -- SYSCTL, whose self-clearing bits have to be cleared, and
XFERTYP, which is the command trigger.

**`uc.mem_write` from Python does not fire write hooks** (HANDOVER trap 13),
so the model updating its own registers cannot recurse into itself.

**A write hook fires BEFORE the store lands.** Reading the register back from
inside one gives the OLD value, and anything written from inside it is then
overwritten by the store that is still to come. So a write hook must use its
own `value` argument, and a register whose value has to be *corrected* is
handled on READ instead -- which is what SYSCTL's self-clearing bits do here.
Getting this wrong looks exactly like the model not being installed: the INITA
spin stays at 36,988,467 reads and nothing else changes.

**Self-clearing bits are why the driver used to hang.** `SYSCTL` bit 27 INITA
sends 80 init clocks and clears itself; bits 24-26 RSTA/RSTC/RSTD are software
resets that do the same. Backed by plain RAM they read back whatever was
written, and `0x4012001e` spins forever -- measured at 36,988,467 reads.
"""
import struct

BASE = 0xFC0CC000
SIZE = 0x1000

DSADDR, BLKATTR, CMDARG, XFERTYP = 0x00, 0x04, 0x08, 0x0C
CMDRSP0, CMDRSP1, CMDRSP2, CMDRSP3 = 0x10, 0x14, 0x18, 0x1C
DATPORT, PRSSTAT, PROCTL, SYSCTL = 0x20, 0x24, 0x28, 0x2C
IRQSTAT, IRQSTATEN, IRQSIGEN = 0x30, 0x34, 0x38
AUTOC12ERR, HOSTCAPBLT, WML = 0x3C, 0x40, 0x44
FEVT, ADMAESR, ADMASAR, VENDOR, HOSTVER = 0x50, 0x54, 0x58, 0xC0, 0xFC

NAME = {DSADDR: 'DSADDR', BLKATTR: 'BLKATTR', CMDARG: 'CMDARG',
        XFERTYP: 'XFERTYP', CMDRSP0: 'CMDRSP0', CMDRSP1: 'CMDRSP1',
        CMDRSP2: 'CMDRSP2', CMDRSP3: 'CMDRSP3', DATPORT: 'DATPORT',
        PRSSTAT: 'PRSSTAT', PROCTL: 'PROCTL', SYSCTL: 'SYSCTL',
        IRQSTAT: 'IRQSTAT', IRQSTATEN: 'IRQSTATEN', IRQSIGEN: 'IRQSIGEN',
        AUTOC12ERR: 'AUTOC12ERR', HOSTCAPBLT: 'HOSTCAPBLT', WML: 'WML',
        FEVT: 'FEVT', ADMAESR: 'ADMAESR', ADMASAR: 'ADMASAR',
        VENDOR: 'VENDOR', HOSTVER: 'HOSTVER'}

# XFERTYP bits
DMAEN, BCEN, AC12EN = 1 << 0, 1 << 1, 1 << 2
DTDSEL, MSBSEL = 1 << 4, 1 << 5
DPSEL = 1 << 21

# PRSSTAT bits
CIHB, CDIHB, DLA, SDSTB = 1 << 0, 1 << 1, 1 << 2, 1 << 3
BWEN, BREN = 1 << 10, 1 << 11
CINS = 1 << 16
CLSL = 1 << 23
DLSL0 = 1 << 24

# IRQSTAT bits
CC, TC, BGE, DINT = 1 << 0, 1 << 1, 1 << 2, 1 << 3
BWR, BRR = 1 << 4, 1 << 5
CINS_IRQ = 1 << 6

# SYSCTL self-clearing bits
RSTA, RSTC, RSTD, INITA = 1 << 24, 1 << 25, 1 << 26, 1 << 27

# Reset values, RM Table 25-2. PRSSTAT's documented reset is 0xFF8800F8; we add
# CINS because a card IS inserted, which is the whole point of the model.
RESET = {
    DSADDR: 0, BLKATTR: 0x00010000, CMDARG: 0, XFERTYP: 0,
    CMDRSP0: 0, CMDRSP1: 0, CMDRSP2: 0, CMDRSP3: 0, DATPORT: 0,
    PRSSTAT: 0xFF8800F8 | CINS,
    PROCTL: 0x00000020, SYSCTL: 0x00008008,
    IRQSTAT: 0, IRQSTATEN: 0x117F013F, IRQSIGEN: 0,
    AUTOC12ERR: 0, HOSTCAPBLT: 0x07F30000, WML: 0x08100810,
    ADMAESR: 0, ADMASAR: 0, VENDOR: 1, HOSTVER: 0x00001201,
}

# The driver's own status word, written by the ISR on real hardware.
# 0x4011fe10 sets it to 1 before issuing and returns it after the wait.
DRV_STATUS = 0x44E26F1C


class Card:
    """A minimal eMMC. Only what the identification sequence asks for.

    `capacity_blocks` is in 512-byte sectors. CMD3 assigns RCA 2 (a
    host-assigned RCA is illegal for SD and standard for eMMC, which is how we
    know this is an eMMC and not a card).
    """

    def __init__(self, image=None, capacity_blocks=0x00760000):
        self.image = image
        self.blocks = capacity_blocks
        self.rca = 0
        self.selected = False
        # OCR: bit31 power-up done, bit30 sector addressing, voltage window.
        self.ocr = 0xC0FF8080
        # CID/CSD as four longwords each, R2 order {RSP3[23:0],RSP2,RSP1,RSP0}.
        self.cid = [0x00000000, 0x00000000, 0x00000000, 0x00110000]
        self.csd = [0x00000000, 0x00000000, 0x00000000, 0x00000000]

    def command(self, idx, arg):
        """-> (resp0, resp1, resp2, resp3). R1 is a card-status word."""
        r1 = 0x00000900          # state=transfer(4), READY_FOR_DATA
        if idx == 0:             # GO_IDLE_STATE, no response
            self.selected = False
            return (0, 0, 0, 0)
        if idx == 1:             # SEND_OP_COND -> OCR, bit31 must end set
            return (self.ocr, 0, 0, 0)
        if idx in (2, 9, 10):    # ALL_SEND_CID / SEND_CSD / SEND_CID -> R2
            src = self.csd if idx == 9 else self.cid
            return tuple(src)
        if idx == 3:             # SET_RELATIVE_ADDR (eMMC: host assigns)
            self.rca = (arg >> 16) & 0xFFFF
            return (r1, 0, 0, 0)
        if idx == 7:             # SELECT/DESELECT_CARD
            self.selected = ((arg >> 16) & 0xFFFF) == self.rca
            return (r1, 0, 0, 0)
        return (r1, 0, 0, 0)

    def read_word(self, idx, pattern):
        """-> the next word the host will read out of DATPORT.

        CMD14 is BUSTEST_R: the eMMC returns the bitwise inverse of the
        pattern the host sent under CMD19, which is why the driver's check is
        `read ^ 0xA5 == 0` after writing 0x5A.
        """
        if idx == 14:
            return (~pattern) & 0xFFFFFFFF
        return 0


class Esdhc:
    """The controller. `log` collects (command index, argument) in order."""

    def __init__(self, m, card=None, trace=False):
        from unicorn import UC_HOOK_MEM_WRITE
        self.m = m
        self.uc = m.uc
        self.card = card or Card()
        self.trace = trace
        self.log = []
        self.pattern = 0           # last word the host wrote to DATPORT
        for off, val in RESET.items():
            self._put(off, val)
        from unicorn import UC_HOOK_MEM_READ
        # SYSCTL is corrected on READ: see the note above about write hooks
        # running before the store.
        self.uc.hook_add(UC_HOOK_MEM_READ, self._on_sysctl_read,
                         begin=BASE + SYSCTL, end=BASE + SYSCTL + 3)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_xfertyp,
                         begin=BASE + XFERTYP, end=BASE + XFERTYP + 3)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_datport_write,
                         begin=BASE + DATPORT, end=BASE + DATPORT + 3)

    # -- register access -------------------------------------------------
    def _put(self, off, val):
        self.uc.mem_write(BASE + off, struct.pack('>I', val & 0xFFFFFFFF))

    def _get(self, off):
        return struct.unpack('>I', bytes(self.uc.mem_read(BASE + off, 4)))[0]

    def _set_bits(self, off, bits):
        self._put(off, self._get(off) | bits)

    def _clr_bits(self, off, bits):
        self._put(off, self._get(off) & ~bits)

    # -- hooks -----------------------------------------------------------
    def _on_sysctl_read(self, uc, typ, addr, size, val, data):
        """INITA and the three software resets have already self-cleared.

        Done on read rather than on write because a write hook runs before the
        store: anything cleared there is put straight back by the store that
        follows. The driver sets INITA and then polls, so the first poll sees
        it clear, which is the behaviour the manual describes.
        """
        cur = self._get(SYSCTL)
        if cur & (INITA | RSTA | RSTC | RSTD):
            self._put(SYSCTL, cur & ~(INITA | RSTA | RSTC | RSTD))

    def _on_xfertyp(self, uc, typ, addr, size, val, data):
        """Writing XFERTYP issues the command.

        `val` is the value being stored; the store has not happened yet, so
        reading XFERTYP back here would give the previous command.
        """
        xfer = val & 0xFFFFFFFF if size == 4 else self._get(XFERTYP)
        idx = (xfer >> 24) & 0x3F
        arg = self._get(CMDARG)
        self.log.append((idx, arg))
        r0, r1, r2, r3 = self.card.command(idx, arg)
        self._put(CMDRSP0, r0)
        self._put(CMDRSP1, r1)
        self._put(CMDRSP2, r2)
        self._put(CMDRSP3, r3)
        # Command completes instantly: never leave the inhibit bits set, or
        # the driver's `(PRSSTAT & 3) == 0` waits never finish.
        self._clr_bits(PRSSTAT, CIHB | CDIHB | DLA)
        self._set_bits(IRQSTAT, CC | TC)
        # A data command has to make the buffer look ready, or the driver
        # spins on PRSSTAT: BWEN at 0x40120236 before it writes, BREN at
        # 0x401202b2 before it reads.
        if xfer & DPSEL:
            if xfer & DTDSEL:                       # card -> host
                self._set_bits(PRSSTAT, BREN)
                self._set_bits(IRQSTAT, BRR)
                self._put(DATPORT, self.card.read_word(idx, self.pattern))
            else:                                   # host -> card
                self._set_bits(PRSSTAT, BWEN)
                self._set_bits(IRQSTAT, BWR)
        # The ISR's bookkeeping. 0x4011fe10 pre-sets this to 1 and returns it
        # after the wait; `unblock` satisfies the wait, so without this the
        # caller always sees "still in progress".
        self.uc.mem_write(DRV_STATUS, struct.pack('>I', 0))
        if self.trace:
            print('[esdhc] CMD%-2d arg=%#010x xfertyp=%#010x -> %#010x'
                  % (idx, arg, xfer, r0))

    def _on_datport_write(self, uc, typ, addr, size, val, data):
        """Capture what the host puts in the buffer, for the bus test."""
        self.pattern = val & 0xFFFFFFFF

    def __repr__(self):
        return 'Esdhc(commands=%d, %s)' % (
            len(self.log), ' '.join('CMD%d' % c for c, _ in self.log[:16]))
