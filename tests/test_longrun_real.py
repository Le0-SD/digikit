# pyright: reportMissingImports=false
"""Opt-in regression for image-derived Digitone SLC guest semantics."""

import os
import struct
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(
    os.environ.get("DT2_LONGRUN_SLC_REAL") == "1"
    and all(
        os.environ.get(name)
        for name in (
            "DT2_DIGITAKT_MAIN",
            "DT2_DIGITONE_MAIN",
            "DT2_DIGITONE_SNAPSHOT",
            "DT2_DIGITONE_SYX",
        )
    ),
    "set DT2_LONGRUN_SLC_REAL=1 and provide explicit Digitone and Digitakt inputs",
)
class DigitoneSlcBuildTest(unittest.TestCase):
    def _run_predicate(self, image, predicate, status, old_status):
        """Execute the actual guest helper and return D0 for one status byte."""
        from unicorn import UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_PROT_ALL, Uc
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_D0

        uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        try:
            # The helper is leaf code; a mapped sentinel return makes this a
            # narrow guest execution test rather than a host-memory readback.
            uc.mem_map(0x40000000, 0x310000, UC_PROT_ALL)
            uc.mem_write(0x40000400, image)
            for addr in (status, old_status):
                uc.mem_map(addr & ~0xFFFF, 0x10000, UC_PROT_ALL)
            uc.mem_map(0x4FF00000, 0x1000, UC_PROT_ALL)
            uc.mem_write(status, b"\x00")
            uc.mem_write(old_status, b"\x00")
            uc.mem_write(status, b"\x01")
            uc.reg_write(UC_M68K_REG_A7, 0x4FF00800)
            uc.mem_write(0x4FF00800, struct.pack(">I", 0x40000000))
            uc.emu_start(predicate, 0x40000000, count=50)
            return uc.reg_read(UC_M68K_REG_D0)
        finally:
            # unicorn's Python binding releases this handle on collection.
            del uc

    def _run_caller_branch(self, image, caller, status, old_status):
        """Stop at the real caller's fail or success destination."""
        from unicorn import (
            UC_ARCH_M68K,
            UC_HOOK_CODE,
            UC_MODE_BIG_ENDIAN,
            UC_PROT_ALL,
            Uc,
        )
        from unicorn.m68k_const import UC_M68K_REG_A7

        failure, success, hit = 0x4002E990, 0x4002E99A, []
        uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        try:
            uc.mem_map(0x40000000, 0x310000, UC_PROT_ALL)
            uc.mem_write(0x40000400, image)
            for addr in (status, old_status):
                uc.mem_map(addr & ~0xFFFF, 0x10000, UC_PROT_ALL)
            uc.mem_map(0x4FF00000, 0x1000, UC_PROT_ALL)
            uc.mem_write(status, b"\x00")
            uc.mem_write(old_status, b"\x00")
            uc.mem_write(status, b"\x01")
            uc.reg_write(UC_M68K_REG_A7, 0x4FF00800)

            def checkpoint(machine, address, size, data):
                if address in (failure, success):
                    hit.append(address)
                    machine.emu_stop()

            uc.hook_add(UC_HOOK_CODE, checkpoint, begin=failure, end=success)
            uc.emu_start(caller, 0, count=50)
            return hit
        finally:
            del uc

    def test_build_uses_resolved_status_and_guest_success_branch(self):
        from emu import longrun, symbols

        snapshot = Path(os.environ["DT2_DIGITONE_SNAPSHOT"])
        main = Path(os.environ["DT2_DIGITONE_MAIN"])
        syx = Path(os.environ["DT2_DIGITONE_SYX"])
        image = main.read_bytes()
        profile = symbols.resolve(image)
        dt_image = Path(os.environ["DT2_DIGITAKT_MAIN"]).read_bytes()
        dt_profile = symbols.resolve(dt_image)

        # These are image-derived checks, not firmware-name address rules.
        self.assertEqual(dt_profile.slc_status_addr, 0x4FE49198)
        self.assertEqual(profile.slc_status_predicate, 0x4011DC48)
        self.assertEqual(profile.slc_status_addr, 0x4E531198)
        old_status = dt_profile.slc_status_addr
        self.assertEqual(
            image[
                profile.slc_status_predicate
                - profile.load_addr : profile.slc_status_predicate
                - profile.load_addr
                + 20
            ],
            bytes.fromhex("71b94e5311987201b28067084a8056c071004e75"),
        )

        # The actual DN init caller compares D0 with one then BEQs over the
        # `MMC NOT IN SLC MODE` dialog setup. Its call/branch bytes prove the
        # predicate result, rather than merely proving a host byte was mapped.
        caller = bytes.fromhex("4eb94011dc487201b280670a")
        self.assertEqual(image.count(caller), 1)
        caller_addr = image.find(caller) + profile.load_addr
        self.assertEqual(caller_addr, 0x4002E984)

        # Red regression: the old Digitakt page is ignored by the DN guest
        # predicate. Green: its extracted operand returns D0 == 1, so the
        # caller's BEQ success branch is taken.
        self.assertEqual(
            self._run_predicate(
                image, profile.slc_status_predicate, old_status, profile.slc_status_addr
            ),
            0,
        )
        self.assertEqual(
            self._run_predicate(
                image, profile.slc_status_predicate, profile.slc_status_addr, old_status
            ),
            1,
        )
        self.assertEqual(
            self._run_caller_branch(
                image, caller_addr, old_status, profile.slc_status_addr
            ),
            [0x4002E990],
        )
        self.assertEqual(
            self._run_caller_branch(
                image, caller_addr, profile.slc_status_addr, old_status
            ),
            [0x4002E99A],
        )

        with patch.dict(os.environ, {"DT2_MAIN_IMG": str(main)}):
            m, *_ = longrun.build(str(snapshot), syx=str(syx), slc=True)
        try:
            self.assertIn(profile.slc_status_addr & ~0xFFFFF, m.mapped)
            self.assertEqual(bytes(m.uc.mem_read(profile.slc_status_addr, 1)), b"\x01")
        finally:
            m.close()


if __name__ == "__main__":
    unittest.main()
