"""Opt-in integration check for lawfully supplied, extracted MAIN images."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.early_init_contract import load_contract, main


@unittest.skipUnless(
    os.environ.get("DT2_EARLY_INIT_REAL") == "1",
    "set DT2_EARLY_INIT_REAL=1 with explicit MAIN image paths",
)
class RealEarlyInitContractTest(unittest.TestCase):
    def test_verified_images_and_qemu_seed_are_deterministic(self):
        dt = Path(os.environ["DT2_DIGITAKT_MAIN"])
        dn = Path(os.environ["DT2_DIGITONE_MAIN"])
        seed = Path(os.environ["DT2_EARLY_INIT_QEMU_SEED"])
        contract = load_contract()
        with tempfile.TemporaryDirectory() as d:
            first, second = Path(d) / "one.json", Path(d) / "two.json"
            args = ["--main", str(dt), "--main", str(dn), "--qemu-seed", str(seed)]
            main(args + ["--out", str(first)])
            main(
                [
                    "--main",
                    str(dn),
                    "--main",
                    str(dt),
                    "--qemu-seed",
                    str(seed),
                    "--out",
                    str(second),
                ]
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            result = json.loads(first.read_text())
        hashes = {image["firmware_sha256"] for image in result["images"]}
        self.assertEqual(hashes, set(contract["firmware"].values()))
        self.assertTrue(result["comparison"]["identical_access_sequence"])
        joins = {
            image["firmware_sha256"]: sum(e["qemu_joined"] for e in image["events"])
            for image in result["images"]
        }
        self.assertEqual(joins[contract["firmware"]["digitakt_main_sha256"]], 8)
        self.assertEqual(joins[contract["firmware"]["digitone_main_sha256"]], 0)

    def test_build_closes_owned_trace_when_kick_fails(self):
        from emu import longrun
        from emu.trace import JsonlMmioTrace

        sinks = []

        class TrackingTrace(JsonlMmioTrace):
            def __init__(self, path):
                super().__init__(path)
                sinks.append(self)

        with tempfile.TemporaryDirectory() as d:
            with (
                patch("emu.trace.JsonlMmioTrace", TrackingTrace),
                patch("emu.edma.kick", side_effect=RuntimeError("forced kick failure")),
            ):
                with self.assertRaisesRegex(RuntimeError, "forced kick failure"):
                    longrun.build(
                        "snapshots/boot400M.snap",
                        trace_path=Path(d) / "trace.jsonl",
                        trace_ranges=((0xFC04002D, 0xFC04002F),),
                    )
        self.assertEqual(len(sinks), 1)
        self.assertTrue(sinks[0].closed)
