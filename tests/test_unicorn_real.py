"""Opt-in dual-firmware panel regression; proprietary inputs stay outside git."""

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(
    os.environ.get("DT2_UNICORN_REAL") == "1",
    "set DT2_UNICORN_REAL=1 and provide the documented inputs",
)
class UnicornRealPanelTest(unittest.TestCase):
    # Full PNG hashes from the validated deadline-stepped acceptance run.
    PANELS = {
        "DT": {
            "sha256": "0a609f3457e3808dae73f8e047df3362a88b359e410c18fb789da4f6efde9c3c",
            "tasks": 6,
            "frames": "frames flushed=211 distinct=127",
        },
        "DN": {
            "sha256": "c23aae90b3ac0d1bf3cf99ca7760bf64c8f34ae78fc3919be8f92ac6f01ca5e7",
            "tasks": 4,
            "frames": "frames flushed=185 distinct=112",
        },
    }

    def test_patched_semantics_and_both_real_panels(self):
        required = [
            "DT2_UNICORN_REAL_%s_%s" % (name, field)
            for name in self.PANELS
            for field in ("MAIN", "SNAPSHOT", "INSTRS")
        ]
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            self.skipTest("set required real-regression inputs: " + ", ".join(missing))
        subprocess.run([sys.executable, "-m", "emu.unicorn_compat"], check=True)
        for name, expected in self.PANELS.items():
            prefix = "DT2_UNICORN_REAL_%s_" % name
            image, snapshot = (
                os.environ[prefix + "MAIN"],
                os.environ[prefix + "SNAPSHOT"],
            )
            instrs = os.environ[prefix + "INSTRS"]
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / (name + ".png")
                env = os.environ | {"DT2_MAIN_IMG": image}
                panel = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "emu.panel",
                        snapshot,
                        instrs,
                        "3",
                        str(output),
                    ],
                    check=True,
                    env=env,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(
                    len(re.findall(r"^\s*TASK entry=", panel.stdout, re.M)),
                    expected["tasks"],
                )
                self.assertRegex(panel.stdout, r"(?m)^.*\bstop=limit$")
                self.assertIn(expected["frames"], panel.stdout)
                self.assertEqual(
                    hashlib.sha256(output.read_bytes()).hexdigest(), expected["sha256"]
                )


if __name__ == "__main__":
    unittest.main()
