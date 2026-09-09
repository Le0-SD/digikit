# Patched Unicorn requirement

The emulator requires `unicorn==2.1.4` with the small m68k SR-read patch in
`patches/unicorn-2.1.4-m68k-sr-read.patch`. Stock Unicorn destructively reads
lazy condition-code state: a host SR read can change the following guest branch.
That prevents the Digitone from running.

Install it into the project interpreter after `uv sync`:

```sh
tools/install-patched-unicorn.sh
```

The installer makes a temporary clone of official Unicorn tag 2.1.4, verifies
commit `8028ec436f2d9376525352dd38ed9ed6b9f6be10` and the checked-in patch,
builds only m68k in Release mode, atomically replaces that interpreter's native
library, then runs the semantic check. It does not vendor Unicorn source or use
a fork. Set `PYTHON=/path/to/python` to target another already-installed project
interpreter.

`python -m emu.unicorn_compat` runs the compatibility check directly. It covers
both a zero result (Z taken) and nonzero result (Z clear) after a host SR read;
it is semantic rather than a binary hash allowlist. `Machine` and `emu.run
--check` refuse an incompatible runtime before normal emulation begins. Running
`uv sync` can restore the stock wheel, in which case the guard intentionally
rejects it; rerun the installer.

This establishes that Digitakt renders and that Digitone's Main OS executes and
renders. It is not a claim of a full hardware-equivalent Digitone boot.

`tests/test_unicorn_real.py` is opt-in (`DT2_UNICORN_REAL=1`). Supply
`DT2_UNICORN_REAL_DT_MAIN`, `..._DT_SNAPSHOT`, `..._DT_INSTRS` and matching
`DN` variables for lawfully obtained inputs. It checks the semantic guard and
full panel PNG hashes without retaining inputs or outputs.

Timer-stepped execution has no arbitrary `cap` boundary. Only actual timer
deadlines may subdivide a timer-stepped run; arbitrary subdivisions are
unsupported because they change firmware-visible execution boundaries.
