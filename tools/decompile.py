# fmt: off
"""Print decompiled C for the function containing each given address, from an
already-imported/analyzed Ghidra program, via PyGhidra -- no analyzeHeadless
startup cost (that's seconds of JVM+project load instead of the ~minutes a
fresh `-process ... -postScript` invocation costs).

    GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.3/libexec \
    uv run python tools/decompile.py PROGRAM_NAME 0x40001622 [0x... ...]
                                      [--project ~/ghidra-projects/dt2]
                                      [--project-name dt2]

`PROGRAM_NAME` is the program's path inside the project, e.g.
"dn2_MAIN_OS.bin" or "section_3_MAIN_OS.bin" (leading slash optional).
Addresses are hex, with or without a leading "0x".

Read-only: opens the program the same way tools/apply-profile.py's dry-run
does, decompiles, and releases -- no transaction, nothing saved, nothing
about the program on disk changes.
"""
import argparse
import os
import sys

# See tools/apply-profile.py for why: tools/ghidra/ is a plain directory
# (Java scripts for ghidra.sh) that shadows the real `ghidra` Java-bridge
# namespace PyGhidra needs once tools/ is on sys.path -- which it is by
# default when this script is run as `python tools/decompile.py`.
_here = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [p for p in sys.path if os.path.abspath(p or '.') != _here]

DEFAULT_PROJECT = os.path.expanduser('~/ghidra-projects/dt2')
DEFAULT_PROJECT_NAME = 'dt2'
TIMEOUT_SECONDS = 60


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('program', help='program path inside the project, e.g. dn2_MAIN_OS.bin')
    ap.add_argument('addr', nargs='+', help='hex address(es), e.g. 0x40001622')
    ap.add_argument('--project', default=DEFAULT_PROJECT)
    ap.add_argument('--project-name', default=DEFAULT_PROJECT_NAME)
    args = ap.parse_args(argv)

    addrs = [int(a, 16) for a in args.addr]

    os.environ.setdefault('GHIDRA_INSTALL_DIR', '/opt/homebrew/Cellar/ghidra/12.1.3/libexec')
    import pyghidra
    pyghidra.start(verbose=False)

    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    program_path = args.program if args.program.startswith('/') else '/' + args.program

    project = pyghidra.open_project(args.project, args.project_name, create=False)
    try:
        with pyghidra.program_context(project, program_path) as program:
            fm = program.getFunctionManager()
            af = program.getAddressFactory()
            space = af.getDefaultAddressSpace()

            ifc = DecompInterface()
            ifc.setOptions(DecompileOptions())
            ifc.openProgram(program)
            try:
                for a in addrs:
                    addr = space.getAddress(a)
                    func = fm.getFunctionContaining(addr)
                    print('=' * 72)
                    if func is None:
                        print('0x%08x: no function contains this address' % a)
                        continue
                    print('0x%08x  in  %s  (entry 0x%s)'
                          % (a, func.getName(), func.getEntryPoint()))
                    result = ifc.decompileFunction(func, TIMEOUT_SECONDS, pyghidra.task_monitor())
                    if not result.decompileCompleted():
                        print('decompilation failed: %s' % result.getErrorMessage())
                        continue
                    print(result.getDecompiledFunction().getC())
            finally:
                ifc.dispose()
    finally:
        project.close()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
