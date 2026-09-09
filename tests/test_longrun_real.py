"""Opt-in regression for the Digitone SLC host-write setup."""

import os
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(
    os.environ.get("DT2_LONGRUN_SLC_REAL") == "1",
    "set DT2_LONGRUN_SLC_REAL=1 and provide explicit Digitone inputs",
)
class DigitoneSlcBuildTest(unittest.TestCase):
    def test_build_maps_slc_flag_page_before_host_write(self):
        from emu import longrun

        snapshot = Path(os.environ["DT2_DIGITONE_SNAPSHOT"])
        main = Path(os.environ["DT2_DIGITONE_MAIN"])
        syx = Path(os.environ["DT2_DIGITONE_SYX"])
        with patch.dict(os.environ, {"DT2_MAIN_IMG": str(main)}):
            m, *_ = longrun.build(str(snapshot), syx=str(syx), slc=True)
        try:
            self.assertIn(0x4FE00000, m.mapped)
            self.assertEqual(bytes(m.uc.mem_read(0x4FE49198, 1)), b"\x01")
        finally:
            m.close()
