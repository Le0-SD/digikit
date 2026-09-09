# pyright: reportMissingImports=false
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from unicorn.m68k_const import UC_M68K_REG_D1

from emu.harness import Machine
from emu.trace import JsonlMmioTrace
from tools.early_init_contract import (
    analyze_bytes,
    join_qemu,
    load_contract,
    main,
    validate_contract,
)


def image(relocation=b"\x23\xd0\x40\x28\x81\x90"):
    data = bytearray(0x140)
    # The complete, intentionally tiny established bootstrap sequence.
    data[0xE8:0x130] = (
        b"\x41\xef\x00\x04" + relocation + b"\x2e\x7c\x48\x00\x00\x00"
        b"\x70\x25\x41\xf9\xfc\x04\x00\x2d\x10\xbc\x00\x11"
        b"\x13\xc0\xfc\x04\x00\x2f\x10\xbc\x00\x12\x10\xbc\x00\x13"
        b"\x10\xbc\x00\x14\x10\xbc\x00\x20\x10\xbc\x00\x24"
        b"\x41\xf9\xec\x09\x00\x0e\x30\x10\x08\x80\x00\x0b\x30\x80"
    )
    return bytes(data)


class EarlyInitContractTest(unittest.TestCase):
    def test_contract_and_deterministic_synthetic_analysis(self):
        self.assertEqual(
            len(validate_contract(load_contract())["static_write_events"]), 7
        )
        self.assertEqual(analyze_bytes(image()), analyze_bytes(image()))
        falsified = copy.deepcopy(load_contract())
        falsified["static_write_events"][0]["value"] = "0x10"
        with self.assertRaisesRegex(ValueError, "write disagreement"):
            analyze_bytes(image(), contract=falsified)
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "MAIN.bin"
            first, second = Path(d) / "one.json", Path(d) / "two.json"
            source.write_bytes(image())
            main(["--main", str(source), "--out", str(first)])
            main(["--main", str(source), "--out", str(second)])
            self.assertEqual(first.read_bytes(), second.read_bytes())
        # The opcode/form still matches after this immediate mutation, so this
        # must reach tuple comparison rather than fail a literal-byte check.
        with self.assertRaisesRegex(ValueError, "write disagreement"):
            analyze_bytes(image().replace(b"\x10\xbc\x00\x24", b"\x10\xbc\x00\x26"))

    def test_join_is_exact_and_digitone_stays_static(self):
        records = analyze_bytes(image())
        sha = hashlib.sha256(image()).hexdigest()
        seed = {
            "firmware_sha256": sha,
            "events": [
                {
                    "pc": "0x40000500",
                    "address": "0xfc04002d",
                    "direction": "write",
                    "size": 1,
                    "value": "0x11",
                }
            ],
        }
        joined = join_qemu(records, sha, seed)
        self.assertIn("DYNAMIC_QEMU", joined[0]["provenance"])
        self.assertNotIn("DYNAMIC_QEMU", joined[1]["provenance"])
        self.assertFalse(join_qemu(records, "not-digitakt", seed)[0]["qemu_joined"])

    def test_trace_is_disabled_or_read_only_and_narrow(self):
        # This synthetic trace test does not exercise the runtime guard.
        with patch("emu.unicorn_compat.require_compatible_unicorn"):
            program = bytes.fromhex("701213c0002000001239002000004e71")
            plain = Machine()
            plain.load(program, 0x1000)
            plain.ensure(0x200000)
            self.assertEqual(plain.install_mmio_trace(), [])
            plain.uc.emu_start(0x1000, 0x1010)
            expected = plain.uc.reg_read(UC_M68K_REG_D1)
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / "trace.jsonl"
                traced = Machine()
                traced.load(program, 0x1000)
                traced.ensure(0x200000)
                sink = JsonlMmioTrace(path)
                self.assertEqual(
                    len(
                        traced.install_mmio_trace(
                            sink, [(0x200000, 0x200003)], {0x200000: "TEST"}, owned=True
                        )
                    ),
                    2,
                )
                traced.uc.emu_start(0x1000, 0x1010)
                traced.close()
                self.assertTrue(sink.closed)
                traced.close()  # owned cleanup is deterministic and idempotent.
                events = [json.loads(x) for x in path.read_text().splitlines()]
            self.assertEqual(traced.uc.reg_read(UC_M68K_REG_D1), expected)
            self.assertEqual(
                [(x["direction"], x["width"]) for x in events],
                [("write", 8), ("read", 8)],
            )
            self.assertEqual(events[1]["value"], None)
            self.assertEqual(events[1]["read_phase"], "before-value-unknown")

    def test_esdhc_inita_acceptance_record_is_bounded(self):
        records = load_contract()["acceptance_records"]
        self.assertIn(
            {
                "kind": "esdhc-sysctl-inita-poll",
                "address": "0xfc0cc02c",
                "mask": "0x08000000",
                "site": "0x4012001e",
                "scope": "bounded model acceptance; not whole-eSDHC coverage",
                "provenance": ["STATIC_ANALYSIS"],
            },
            records,
        )


if __name__ == "__main__":
    unittest.main()
