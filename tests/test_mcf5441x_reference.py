# pyright: reportMissingImports=false
"""The mixed-source MCF5441x reference contract must match the emulator's own constants.

Loads docs/contracts/mcf5441x-reference-v1.json -- stable facts only, each
tagged with its own source (upstream Linux, docs/refs/linux-m5441x-893e1178.md,
or the NetBurner NNDK headers, docs/refs/netburner-mcf5441x-layout.md) -- and
asserts it agrees with the existing named constants in emu/pit.py,
emu/dtim.py, emu/gpio.py, emu/boot.py, emu/esdhc.py and emu/edma.py. Does not
require network access or the vendored corpora at runtime; the contract file
is the only input.
"""

import json
import unittest
from pathlib import Path

from emu import boot, dtim, edma, esdhc, gpio, pit

CONTRACT_PATH = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "contracts"
    / "mcf5441x-reference-v1.json"
)


def load_contract():
    with open(CONTRACT_PATH, encoding="utf-8") as f:
        return json.load(f)


def _int(x):
    return int(x, 16) if isinstance(x, str) else x


class IntcContractTest(unittest.TestCase):
    def test_controller_bases_and_vector_bases_match_pit_module(self):
        contract = load_contract()
        expected = [
            (_int(c["base"]), c["vector_base"]) for c in contract["intc"]["controllers"]
        ]
        self.assertEqual(list(pit.INTC), expected)

    def test_icr_base_matches(self):
        contract = load_contract()
        for c in contract["intc"]["controllers"]:
            self.assertEqual(_int(c["icr0_offset"]), pit.ICR_BASE)

    def test_imr_offset_matches_netburner_intcstruct(self):
        contract = load_contract()
        self.assertEqual(_int(contract["intc"]["imr_offset"]), pit.IMR_BASE)
        self.assertEqual(contract["intc"]["imr_offset_source"], "netburner")


class PitContractTest(unittest.TestCase):
    def test_bases_and_vectors_match(self):
        contract = load_contract()
        chans = contract["pit"]["channels"]
        self.assertEqual([_int(c["base"]) for c in chans], list(pit.BASES))
        self.assertEqual([c["vector"] for c in chans], list(pit.VECTORS))

    def test_source_to_vector_arithmetic(self):
        contract = load_contract()
        intc2_base = next(
            c["vector_base"]
            for c in contract["intc"]["controllers"]
            if c["name"] == "INTC2"
        )
        for c in contract["pit"]["channels"]:
            self.assertEqual(c["vector"], intc2_base + c["source"])

    def test_bus_clock_domain_is_core_over_2(self):
        contract = load_contract()
        self.assertEqual(contract["pit"]["clock_domain"], "BUSCLK")
        # emu/pit.py's F_BUS *is* the bus clock (132 MHz), core/2 of a 264 MHz
        # core clock -- the arithmetic this asserts is that F_BUS is used
        # directly as the PIT clock domain, not divided again.
        self.assertEqual(pit.F_BUS, 132_000_000)


class DtimContractTest(unittest.TestCase):
    def test_bases_and_vectors_match(self):
        contract = load_contract()
        chans = contract["dtim"]["channels"]
        self.assertEqual([_int(c["base"]) for c in chans], list(dtim.BASES))
        self.assertEqual([c["vector"] for c in chans], list(dtim.VECTORS))

    def test_source_to_vector_arithmetic(self):
        contract = load_contract()
        intc0_base = 64
        for c in contract["dtim"]["channels"]:
            self.assertEqual(c["vector"], intc0_base + c["source"])

    def test_register_offsets_match(self):
        contract = load_contract()
        offs = contract["dtim"]["register_offsets"]
        self.assertEqual(_int(offs["DTMR"]), dtim.DTMR)
        self.assertEqual(_int(offs["DTXMR"]), dtim.DTXMR)
        self.assertEqual(_int(offs["DTER"]), dtim.DTER)
        self.assertEqual(_int(offs["DTRR"]), dtim.DTRR)
        self.assertEqual(_int(offs["DTCN"]), dtim.DTCN)

    def test_clk_field_and_bus_div_16_arithmetic_via_public_period(self):
        """Exercise Dtims.period through the same public path Pits uses.

        Constructs a Machine, arms DTIM3 the way the Linux dma_timer.c CLK
        field encodes bus/16 (contract: bits [2:1] = 0b10), and checks the
        resulting instruction period against the formula
        (DTRR+1) * (prescale+1) * 16 / F_BUS * ips -- the same TRR+1 and
        BUSCLK/16 arithmetic emu/dtim.py already documents.
        """
        from emu.harness import Machine

        contract = load_contract()
        clk = contract["dtim"]["clk_field"]
        bus_div_16 = int(clk["bus_div_16"], 2)
        self.assertEqual(bus_div_16, 2)  # (dtmr >> 1) & 0x03 == 2 selects /16

        m = Machine()
        base = dtim.BASES[3]
        m.ensure(base)
        prescale_field = 0
        dtrr = 999
        dtmr = dtim.RST | dtim.ORRI | (bus_div_16 << 1) | (prescale_field << 8)
        m.uc.mem_write(base + dtim.DTMR, dtmr.to_bytes(2, "big"))
        m.uc.mem_write(base + dtim.DTXMR, b"\x00")
        m.uc.mem_write(base + dtim.DTRR, dtrr.to_bytes(4, "big"))

        d = dtim.Dtims(m, channels=(3,), clear_stale=False)
        ips = d.ips
        expected = (dtrr + 1) * (prescale_field + 1) * 16 / dtim.F_BUS * ips
        actual = d.period(3)
        assert actual is not None
        self.assertAlmostEqual(float(actual), expected)

    def test_bus_div_16_matches_dma_freq_domain(self):
        contract = load_contract()
        self.assertEqual(contract["dtim"]["bus_div_16_clock_domain"], "BUSCLK / 16")


class UartContractTest(unittest.TestCase):
    def test_uart8_base_matches_boot_module(self):
        contract = load_contract()
        uart8 = next(c for c in contract["uart"]["channels"] if c["name"] == "UART8")
        base = _int(uart8["base"])
        self.assertEqual(boot.UART8_USR, base + 0x04)
        self.assertEqual(boot.UART8_DAT, base + 0x0C)

    def test_source_to_vector_arithmetic_for_both_channels(self):
        contract = load_contract()
        intc1_base = 128
        for c in contract["uart"]["channels"]:
            self.assertEqual(c["vector"], intc1_base + c["source"])

    def test_uart9_recorded_but_not_yet_modeled(self):
        # UART9 is a contract fact for future use; nothing in emu/ references
        # it today, so there is no emulator constant to cross-check here.
        contract = load_contract()
        names = {c["name"] for c in contract["uart"]["channels"]}
        self.assertIn("UART9", names)


class GpioContractTest(unittest.TestCase):
    def test_addresses_match_gpio_module(self):
        contract = load_contract()
        g = contract["gpio"]
        base = _int(g["base"])
        self.assertEqual(gpio.GPIO, base)
        self.assertEqual(gpio.PODR, base + _int(g["podr_offset"]))
        self.assertEqual(gpio.PDDR, base + _int(g["pddr_offset"]))
        self.assertEqual(gpio.PPDSDR, base + _int(g["ppdsdr_offset"]))
        self.assertEqual(gpio.PCLRR, base + _int(g["pclrr_offset"]))
        self.assertEqual(gpio.PORT_C, g["port_c_offset"])
        self.assertEqual(gpio.PORT_D, g["port_d_offset"])


class EsdhcContractTest(unittest.TestCase):
    def test_base_matches(self):
        contract = load_contract()
        self.assertEqual(esdhc.BASE, _int(contract["esdhc"]["base"]))

    def test_irq_vector_matches_intc2_source_31(self):
        contract = load_contract()
        intc2_base = next(
            c["vector_base"]
            for c in contract["intc"]["controllers"]
            if c["name"] == "INTC2"
        )
        esdhc_fact = contract["esdhc"]
        self.assertEqual(esdhc_fact["irq_source_source"], "netburner")
        self.assertEqual(
            esdhc_fact["irq_vector"], intc2_base + esdhc_fact["irq_source"]
        )
        self.assertEqual(esdhc_fact["irq_vector"], 223)

    def test_xfertyp_offset_and_command_index_bits_match(self):
        contract = load_contract()
        self.assertEqual(esdhc.XFERTYP, _int(contract["esdhc"]["xfertyp_offset"]))
        xfer = 0x12 << 24  # command index 0x12 in bits [29:24]
        idx = (xfer >> 24) & 0x3F
        self.assertEqual(idx, 0x12)
        self.assertEqual(contract["esdhc"]["xfertyp_command_index_bits"], "[29:24]")

    def test_deferred_lane_xor_quirks_are_recorded(self):
        contract = load_contract()
        self.assertEqual(contract["esdhc"]["byte_lane_xor"], 3)
        self.assertEqual(contract["esdhc"]["word_lane_xor"], 2)
        self.assertEqual(contract["esdhc"]["lane_xor_source"], "linux")


class EdmaContractTest(unittest.TestCase):
    def test_bases_and_tcd_stride_match(self):
        contract = load_contract()
        e = contract["edma"]
        self.assertEqual(edma.EDMA_BASE, _int(e["base"]))
        self.assertEqual(edma.TCD_BASE, _int(e["tcd_base"]))
        self.assertEqual(e["source"], "netburner")

    def test_tcd_field_offsets_match(self):
        contract = load_contract()
        offs = contract["edma"]["tcd_offsets"]
        self.assertEqual(_int(offs["SADDR"]), edma.SADDR)
        self.assertEqual(_int(offs["DADDR"]), edma.DADDR)
        self.assertEqual(_int(offs["CITER"]), edma.CITER)
        self.assertEqual(_int(offs["BITER"]), edma.BITER)
        self.assertEqual(_int(offs["DOFF"]), edma.DOFF)


if __name__ == "__main__":
    unittest.main()
