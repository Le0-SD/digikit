# pyright: reportMissingImports=false
"""Semantic compatibility check for the patched Unicorn m68k SR read."""

import json
from functools import lru_cache

INSTALL_COMMAND = "tools/install-patched-unicorn.sh"


def _run_case(factory, value, expected):
    """Exercise a lazy TST followed by a host SR read and guest BEQ."""
    from unicorn.m68k_const import (
        UC_M68K_REG_D1,
        UC_M68K_REG_PC,
        UC_M68K_REG_SR,
    )

    uc = factory()
    # move.l #value,d0; tst.l d0; beq taken; move.l #111,d1; bra done;
    # taken: move.l #222,d1.  This is the known failing SR/branch shape.
    code = (
        b"\x20\x3c"
        + value.to_bytes(4, "big")
        + bytes.fromhex("4a80 6708 223c0000006f 6006 223c000000de")
    )
    uc.mem_map(0, 0x10000)
    uc.mem_write(0x1000, code + b"\x4e\x71" * 8)
    uc.reg_write(UC_M68K_REG_PC, 0x1000)
    uc.reg_write(UC_M68K_REG_SR, 0x2004)  # deliberately seed stale Z
    uc.emu_start(0x1000, 0, count=2)
    sr = uc.reg_read(UC_M68K_REG_SR) & 0x1F
    uc.emu_start(uc.reg_read(UC_M68K_REG_PC), 0, count=4)
    result = uc.reg_read(UC_M68K_REG_D1)
    return {
        "input": value,
        "sr": sr,
        "branch_value": result,
        "expected_sr": 4 if value == 0 else 0,
        "expected_branch_value": expected,
        "pass": sr == (4 if value == 0 else 0) and result == expected,
    }


def evaluate(factory=None):
    """Return bounded diagnostics; ``factory`` makes this testable without Unicorn."""
    if factory is None:
        from unicorn import UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, Uc
        from unicorn.m68k_const import UC_CPU_M68K_CFV4E

        def runtime_factory():
            uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
            uc.ctl_set_cpu_model(UC_CPU_M68K_CFV4E)
            return uc

        factory = runtime_factory
    cases = {
        "zero_z_taken": _run_case(factory, 0, 0xDE),
        "nonzero_z_clear": _run_case(factory, 1, 0x6F),
    }
    return {"compatible": all(case["pass"] for case in cases.values()), "cases": cases}


@lru_cache(maxsize=1)
def _evaluate_runtime():
    """Cache the real runtime probe; injected evaluators remain uncached."""
    return evaluate()


def require_compatible_unicorn():
    """Raise before a machine can run with a destructive Unicorn SR read."""
    try:
        import unicorn
    except ImportError as exc:
        raise RuntimeError(
            "Unicorn is required; run `uv sync` then `%s`" % INSTALL_COMMAND
        ) from exc
    if getattr(unicorn, "__version__", None) != "2.1.4":
        raise RuntimeError(
            "This project requires unicorn==2.1.4; run `uv sync` then `%s`"
            % INSTALL_COMMAND
        )
    result = _evaluate_runtime()
    if not result["compatible"]:
        failed = ", ".join(
            name for name, case in result["cases"].items() if not case["pass"]
        )
        raise RuntimeError(
            "Installed Unicorn fails the m68k SR/branch compatibility check (%s). "
            "Run `%s` (uv sync restores stock Unicorn, which this guard rejects)."
            % (failed, INSTALL_COMMAND)
        )
    return result


def main():
    try:
        print(json.dumps(require_compatible_unicorn(), sort_keys=True))
    except RuntimeError as exc:
        print("Unicorn compatibility check failed: %s" % exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
