# pyright: reportMissingImports=false
"""Semantic compatibility check for patched Unicorn m68k CCR behavior."""

import json
from functools import lru_cache

INSTALL_COMMAND = "tools/install-patched-unicorn.sh"


def _run_case(factory, value, expected):
    """Exercise a lazy CMP followed by a code-hook SR read and guest BEQ."""
    from unicorn import UC_HOOK_CODE
    from unicorn.m68k_const import (
        UC_M68K_REG_A2,
        UC_M68K_REG_D1,
        UC_M68K_REG_D4,
        UC_M68K_REG_PC,
        UC_M68K_REG_SR,
    )

    uc = factory()
    # cmp.l a2,d4; beq taken; move.l #111,d1; bra done;
    # taken: move.l #222,d1.  This is the count-hook failure shape.
    code = bytes.fromhex("b88a 6708 223c0000006f 6006 223c000000de")
    uc.mem_map(0, 0x10000)
    uc.mem_write(0x1000, code + b"\x4e\x71" * 8)
    uc.reg_write(UC_M68K_REG_PC, 0x1000)
    uc.reg_write(UC_M68K_REG_SR, 0x2004)  # deliberately seed stale Z
    observed_sr = []

    def read_sr_from_code_hook(uc_, address, size, data):
        observed_sr.append(uc_.reg_read(UC_M68K_REG_SR) & 0x1F)

    uc.reg_write(UC_M68K_REG_A2, 0)
    uc.reg_write(UC_M68K_REG_D4, value)
    # The BEQ hook runs after CMP but before the branch consumes its flags.
    uc.hook_add(UC_HOOK_CODE, read_sr_from_code_hook, begin=0x1002, end=0x1002)
    uc.emu_start(0x1000, 0, count=5)
    sr = observed_sr[0] if len(observed_sr) == 1 else None
    result = uc.reg_read(UC_M68K_REG_D1)
    return {
        "input": value,
        "sr": sr,
        "branch_value": result,
        "expected_sr": 4 if value == 0 else 0,
        "expected_branch_value": expected,
        "pass": sr == (4 if value == 0 else 0) and result == expected,
    }


def _run_count_boundary_case(factory):
    """A count stop at the instruction after CMP must expose CMP's CCR.

    Unicorn's count hook stops on instruction N+1.  The m68k translator must
    therefore have committed the lazy producer from instruction N before
    returning to the host at that hook.
    """
    from unicorn.m68k_const import (
        UC_M68K_REG_A2,
        UC_M68K_REG_D4,
        UC_M68K_REG_PC,
        UC_M68K_REG_SR,
    )

    uc = factory()
    uc.mem_map(0, 0x10000)
    # cmp.l a2,d4; beq $102e.  The branch is deliberately not executed:
    # count=1 returns at its hook, immediately after the compare.
    uc.mem_write(0x1000, bytes.fromhex("b88a672c") + b"\x4e\x71" * 32)
    uc.reg_write(UC_M68K_REG_PC, 0x1000)
    uc.reg_write(UC_M68K_REG_SR, 0x2001)  # stale Z clear
    uc.reg_write(UC_M68K_REG_A2, 0x44605678)
    uc.reg_write(UC_M68K_REG_D4, 0x44605678)
    uc.emu_start(0x1000, 0, count=1)
    pc = uc.reg_read(UC_M68K_REG_PC)
    sr = uc.reg_read(UC_M68K_REG_SR) & 0x1F
    return {"pc": pc, "sr": sr, "pass": pc == 0x1002 and sr == 4}


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
        "count_boundary_cmp_z": _run_count_boundary_case(factory),
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
            "Installed Unicorn fails the m68k CCR compatibility check (%s). "
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
