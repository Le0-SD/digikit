# pyright: reportMissingImports=false
"""Unit coverage for guirun's stateful timer checkpoint setup."""

import os
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools"))
import guirun


class GuirunTimerCheckpointTest(unittest.TestCase):
    def test_main_requests_deferred_timer_restore(self):
        class StopAfterBuild(Exception):
            pass

        def fake_build(*args, **kwargs):
            self.assertEqual(kwargs["deferred_components"], ("timers",))
            raise StopAfterBuild

        with (
            mock.patch.object(sys, "argv", ["guirun.py", "checkpoint.snap"]),
            mock.patch.object(guirun, "build", side_effect=fake_build),
            self.assertRaises(StopAfterBuild),
        ):
            guirun.main()

    def test_restored_timers_are_preserved_without_construction(self):
        timers = SimpleNamespace(sources=(SimpleNamespace(ips=18_720_000),))

        def restore():
            events["checkpoint_components"]["timers"] = timers
            return timers

        events: dict[str, Any] = {
            "restore_checkpoint_timers": restore,
            "checkpoint_components": {},
        }
        result, restored = guirun.restore_or_construct_timers(
            events,
            lambda: self.fail("must not construct over restored timer state"),
        )

        self.assertIs(result, timers)
        self.assertTrue(restored)
        self.assertIs(events["checkpoint_components"]["timers"], timers)

    def test_legacy_timers_are_constructed_and_registered(self):
        timers = SimpleNamespace(sources=(SimpleNamespace(ips=4_680_000),))
        events: dict[str, Any] = {
            "restore_checkpoint_timers": lambda: None,
            "checkpoint_components": {},
        }

        result, restored = guirun.restore_or_construct_timers(events, lambda: timers)

        self.assertIs(result, timers)
        self.assertFalse(restored)
        self.assertIs(events["checkpoint_components"]["timers"], timers)

    def test_explicit_ips_rejects_different_saved_rate(self):
        timers = SimpleNamespace(sources=(SimpleNamespace(ips=18_720_000),))
        events: dict[str, Any] = {
            "restore_checkpoint_timers": lambda: timers,
            "checkpoint_components": {},
        }

        with self.assertRaisesRegex(RuntimeError, "conflicts with checkpoint"):
            guirun.restore_or_construct_timers(events, lambda: None, 4_680_000)

    def test_run_timer_clock_removes_restored_checkpoint_origin(self):
        timers = SimpleNamespace(now=74_936_800)
        self.assertEqual(guirun.run_timer_clock(timers, 60_272_373), 14_664_427)

    def test_block_profile_is_sorted_and_labelled_perturbing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blocks.json"
            guirun.write_block_profile(path, Counter({0x20: 2, 0x10: 3}))

            self.assertEqual(
                path.read_text(),
                '{"entries": [{"address": 16, "hits": 3}, '
                '{"address": 32, "hits": 2}], "kind": "basic-block entries", '
                '"perturbing": true}',
            )


if __name__ == "__main__":
    unittest.main()
