#!/usr/bin/env python3
"""Verify the DT2 1.16 ColdFire-frame reader in the SHARC image.

This is a bounded, byte-backed interface probe.  It verifies the static
instruction chain and runs three explicitly calibrated symbolic slices.  The
slices are discovery evidence, not strict startup qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from sharcldr import LoadedMemory
import sharc_trace as trace


DT2_116_BLOB_SHA256 = (
    "0f514a12a2255f5c081e292c47f1f29462003177658da4bbae0a22fd737fffa2"
)
MACHINE_OFFSET = 0x94
TRACKS = 16
TX_FRAME_BYTES = 0x802


CHECKS: tuple[tuple[int, str, Mapping[str, int], str], ...] = (
    (0x1C0F3C, "17b", {"ureg[6:0]": 39, "data[15:0]": 0xFFFF}, "M7=-1"),
    (0x1C0F40, "17b", {"ureg[6:0]": 38, "data[15:0]": 1}, "M6=1"),
    (0x1C0F44, "17b", {"ureg[6:0]": 37, "data[15:0]": 0}, "M5=0"),
    (
        0x1C7719,
        "5b_move",
        {"srcureghigh[4:0]": 5, "srcureglow[1:1]": 0, "srcureglow[0:0]": 1, "dstureg[6:0]": 8},
        "caller copies I5 to argument R8",
    ),
    (
        0x1C771E,
        "25a_direct",
        {"addr[23:16]": 0x1C, "addr[15:0]": 0x2B24},
        "caller invokes frame processor",
    ),
    (0x1C2CC1, "19a", {"is[2:0]": 4, "data[15:0]": 0x75C}, "sibling frame offset 0x75c"),
    (0x1C2CCB, "19a", {"is[2:0]": 1, "data[15:0]": 0x94}, "I1 += machine offset 0x94"),
    (
        0x1C2CD4,
        "5a_move",
        {"srcureghigh[4:0]": 4, "srcureglow[1:1]": 0, "srcureglow[0:0]": 1, "dstureg[6:0]": 26},
        "preserve I1+0x94 in I10",
    ),
    (0x1C2CD7, "19a", {"is[2:0]": 4, "data[15:0]": 0x73C}, "sibling frame offset 0x73c"),
    (
        0x1C2CA6,
        "5a_move",
        {"srcureghigh[4:0]": 9, "srcureglow[1:1]": 1, "srcureglow[0:0]": 1, "dstureg[6:0]": 11},
        "copy fixed M7=-1 shift amount to R11",
    ),
    (
        0x1C2CFF,
        "5a_move",
        {"compute[22:16]": 0x20, "compute[15:0]": 0x05FB},
        "R5 = LSHIFT R15 by R11",
    ),
    (
        0x1C2D02,
        "5b_move",
        {"srcureghigh[4:0]": 1, "srcureglow[1:1]": 0, "srcureglow[0:0]": 1, "dstureg[6:0]": 32},
        "copy R5 to M0",
    ),
    (
        0x1C33C4,
        "5a_move",
        {"srcureghigh[4:0]": 6, "srcureglow[1:1]": 1, "srcureglow[0:0]": 0, "dstureg[6:0]": 16},
        "restore I10 into I0",
    ),
    (
        0x1C33C7,
        "3b",
        {"i[2:0]": 4, "m[2:0]": 0, "l": 1, "x": 1, "w": 0, "ureg[6:0]": 1},
        "load cached per-track short word",
    ),
    (
        0x1C33D2,
        "3b",
        {"i[2:0]": 0, "m[2:0]": 0, "l": 1, "x": 1, "w": 0, "ureg[6:0]": 0},
        "load frame short word at scaled I0+M0",
    ),
    (0x1C33D7, "2c", {"compute[11:0]": 0x310}, "compare cached R1 with frame R0"),
    (
        0x1C33DF,
        "8a_rel",
        {"cond[4:0]": 0, "j": 1, "reladdr[15:0]": 10},
        "branch on EQ (unchanged)",
    ),
    (
        0x1C33E2,
        "6b_shiftimm",
        {"shiftimm[22:16]": 1, "shiftimm[15:0]": 0xF822},
        "delay slot computes R2 = ASHIFT R2 by -8",
    ),
    (
        0x1C33E5,
        "15b",
        {"i[2:0]": 5, "d": 1, "ureg[6:0]": 2, "data[6:0]": 49},
        "common delay-slot store of shifted R2",
    ),
    (
        0x1C33E7,
        "15b",
        {"i[2:0]": 5, "d": 1, "ureg[6:0]": 46, "data[6:0]": 49},
        "non-EQ-only overwrite with M14",
    ),
)


def extract_machine_types(frame: bytes) -> list[int]:
    """Extract the sixteen big-endian machine-type words from a TX frame."""
    if len(frame) != TX_FRAME_BYTES:
        raise ValueError(
            f"frame is {len(frame)} bytes; expected exactly {TX_FRAME_BYTES}"
        )
    return [
        int.from_bytes(frame[MACHINE_OFFSET + 2 * i : MACHINE_OFFSET + 2 * i + 2], "big")
        for i in range(TRACKS)
    ]


def _verify_static(memory: LoadedMemory) -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    for pc, expected_form, expected_fields, role in CHECKS:
        insn = trace.decode_at(memory, None, pc)
        if insn.type_name != expected_form:
            raise ValueError(
                f"{pc:#x}: expected {expected_form}, decoded {insn.type_name}"
            )
        if insn.length_bytes is None or insn.raw is None:
            raise ValueError(f"{pc:#x}: confident instruction has no extent or raw word")
        mismatches = {
            name: {"expected": value, "actual": insn.fields.get(name)}
            for name, value in expected_fields.items()
            if insn.fields.get(name) != value
        }
        if mismatches:
            raise ValueError(f"{pc:#x}: field mismatch: {mismatches}")
        storage = memory.read_sw(pc, insn.length_bytes)
        if storage is None:
            raise ValueError(f"{pc:#x}: instruction bytes are not loader-backed")
        verified.append(
            {
                "pc_sw": pc,
                "form": insn.type_name,
                "bytes": storage.hex(),
                "raw": f"0x{insn.raw:0{insn.length_bytes * 2}x}",
                "role": role,
            }
        )
    return verified


def _probe_track(memory: LoadedMemory, track: int) -> dict[str, Any]:
    states = trace.trace(
        memory,
        None,
        0x1C33C4,
        sets={
            "I10": trace.Affine(MACHINE_OFFSET, (("spi_rx", 1),)),
            "M0": track,
            "I7": 0x270000,
            "B7": 0,
            "L7": 0,
            "M7": -1,
            "I6": 0x270000,
        },
        max_steps=100,
        max_states=256,
        concrete_memory=True,
        follow_loaded_calls=True,
        continue_external_calls=True,
        dossier_bytes=16,
        assume_nw32=True,
        core_reset_state=True,
    )
    loads = {
        event["expression"]
        for state in states
        for event in state.trace
        if event.get("pc_sw") == 0x1C33D2 and event.get("action") == "load"
    }
    expected = f"spi_rx + {MACHINE_OFFSET + 2 * track:#x}"
    if loads != {expected}:
        raise ValueError(f"track {track}: expected {expected}, observed {sorted(loads)}")
    pcs = {event.get("pc_sw") for state in states for event in state.trace}
    if not {0x1C33D7, 0x1C33DF}.issubset(pcs):
        raise ValueError(f"track {track}: compare/branch endpoint was not reached")
    changed_stores = {
        (event.get("ureg"), event.get("expression"))
        for state in states
        for event in state.trace
        if event.get("pc_sw") == 0x1C33E7 and event.get("action") == "store"
    }
    if changed_stores != {("M14", "I5 + 196")}:
        raise ValueError(
            f"track {track}: unexpected non-EQ store {sorted(changed_stores)}"
        )
    return {
        "track": track,
        "seeded_i10": "spi_rx + 0x94",
        "seeded_m0": track,
        "load_pc_sw": 0x1C33D2,
        "byte_address": expected,
        "access_width": "short-word-sign-extended",
        "compare_pc_sw": 0x1C33D7,
        "eq_branch_pc_sw": 0x1C33DF,
        "non_eq_first_effect": "DM(I5 + 0xc4) = M14",
        "non_eq_effect_pc_sw": 0x1C33E7,
        "terminal_states": len(states),
        "qualifying": False,
    }


def build_report(blob_path: Path, frame_path: Path | None = None) -> dict[str, Any]:
    blob = blob_path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != DT2_116_BLOB_SHA256:
        raise ValueError(
            f"wrong SHARC image: expected {DT2_116_BLOB_SHA256}, got {digest}"
        )
    memory = LoadedMemory.from_stream(blob)
    report: dict[str, Any] = {
        "schema": 1,
        "image_sha256": digest,
        "evidence": "static-byte-backed plus calibrated symbolic slices",
        "qualifying": False,
        "coldfire_contract": {
            "payload_bytes": TX_FRAME_BYTES,
            "machine_word": "big-endian 16-bit at 0x94 + 2*track",
            "tracks": TRACKS,
        },
        "static_chain": _verify_static(memory),
        "calibrated_track_probes": [_probe_track(memory, i) for i in (0, 1, 15)],
        "result": {
            "reader_function_sw": 0x1C2B24,
            "load_pc_sw": 0x1C33D2,
            "compare_pc_sw": 0x1C33D7,
            "unchanged_branch_pc_sw": 0x1C33DF,
            "machine_word": "DM(spi_rx + 0x94 + 2*track) (SWSE)",
            "behavior": "compare received word with cached per-track word; EQ skips the M14 overwrite at DM(I5+0xc4)",
            "non_eq_first_effect": "0x1c33e7 stores M14 to DM(I5+0xc4)",
        },
    }
    if frame_path is not None:
        frame = frame_path.read_bytes()
        report["frame"] = {
            "path": str(frame_path),
            "sha256": hashlib.sha256(frame).hexdigest(),
            "bytes": len(frame),
            "machine_types": extract_machine_types(frame),
        }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("blob", type=Path, help="DT2 1.16 section_7_BLOB.bin")
    parser.add_argument("--frame", type=Path, help="optional 0x802-byte ColdFire TX frame")
    parser.add_argument("-o", "--output", type=Path, help="write JSON report here")
    args = parser.parse_args()
    report = build_report(args.blob, args.frame)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
