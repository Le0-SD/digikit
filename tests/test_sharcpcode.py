"""Synthetic SHARC p-code measurement command coverage."""

import os
import sys
import unittest
from importlib import import_module

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools"))
P = import_module("sharcpcode")


class SharcImportArgumentsTest(unittest.TestCase):
    def test_dt2_label_table_is_configured_and_forwarded(self):
        spec = P.IMAGES["dt2-1.16"]
        self.assertEqual(spec["label_tables"], ["16b8ac:4"])
        argv = P.sharc_import_args("blob", "dt2_SHARC", "project", spec)
        self.assertEqual(
            argv,
            [
                sys.executable,
                os.path.join(P.TOOLS, "sharc_import.py"),
                "blob",
                "--name",
                "dt2_SHARC",
                "--project",
                "project",
                "--project-name",
                P.PROJECT_NAME,
                "--label-table",
                "16b8ac:4",
                "--seed-calls",
                "--analyze",
                "--overwrite",
            ],
        )

    def test_dn2_import_arguments_do_not_add_label_tables(self):
        argv = P.sharc_import_args("blob", "dn2_SHARC", "project", P.IMAGES["dn2-1.11"])
        self.assertNotIn("--label-table", argv)


if __name__ == "__main__":
    unittest.main()
