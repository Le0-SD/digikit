"""Run the emulator against a firmware `.syx`, in one command.

    uv run python -m emu.run [firmware.syx] [--weakptr] [--slc] [--scale N]

Everything between a `.syx` and a live panel, with each prerequisite checked
and built if it can be. There are three, and only the middle one still needs a
tool this repo does not ship:

  1. the `.syx` itself -- yours, never redistributed here;
  2. `sections/section_3_MAIN_OS.bin`, the decompressed ColdFire image;
  3. a boot snapshot, which this builds for you on first run (a few minutes).

**Step 2 is the manual one.** The container's sections are compressed, and the
only implementation of the decompressor known to be correct is the device's
own, at `0x80000432` -- which lives in section 2, which is itself compressed.
It cannot bootstrap itself, so extraction needs an outside tool. The stream is
*not* stock aPLib: a stock depacker emits the first data byte as a literal,
whereas here that byte (`0xfd` in 1.15C section 2) is a tag byte with 1 meaning
literal, and the six bytes after it are the output's first six verbatim. Anyone
wanting to close this should write the depacker against that observation and
check it byte-for-byte with `emu.oracle.depack`, which runs the real thing.
"""
import os
import subprocess
import sys

SYX = 'Digitakt_II_OS1.15C.syx'
TESTED = 'Digitakt II OS 1.15C'
MAIN_IMG = 'sections/section_3_MAIN_OS.bin'
SNAPSHOT = 'snapshots/boot400M.snap'
LADDER = '60000000,120000000,200000000,280000000,400000000'

EXTRACT_HELP = """\
Missing: %s

The firmware sections are compressed inside the .syx and this repo cannot
decompress them yet (see emu/run.py's docstring for why, and what it would
take). Extract them once with elektron-firmware-tool, which supports device
0x14 = Digitakt II:

    elektron-firmware-tool -i %s -o sections/

    https://github.com/mischa85/elektron-firmware-tool

That writes sections/section_3_MAIN_OS.bin and its siblings, and you will not
need to do it again."""


def need_syx(path):
    if os.path.exists(path):
        return
    raise SystemExit(
        'Missing firmware: %s\n\n'
        'No Elektron firmware ships with this repository and none ever should\n'
        '-- it is copyright Elektron. Supply your own lawfully-obtained copy\n'
        'and put it in the working directory. Only %s has been tested.'
        % (path, TESTED))


def need_sections(syx):
    if os.path.exists(MAIN_IMG):
        return
    raise SystemExit(EXTRACT_HELP % (MAIN_IMG, syx))


def need_snapshot(snapshot):
    """Build the boot ladder if the snapshot is not there. -> True if built."""
    if os.path.exists(snapshot):
        return False
    print('No %s yet. Building the boot snapshots -- one cold boot from\n'
          'reset, about 400M instructions, so expect a few minutes. This\n'
          'happens once.\n' % snapshot, flush=True)
    r = subprocess.run([sys.executable, '-m', 'emu.checkpoint', 'make', LADDER])
    if r.returncode != 0 or not os.path.exists(snapshot):
        raise SystemExit('Snapshot build failed; cannot continue.')
    print('\nBuilt %s.\n' % snapshot)
    return True


USAGE = """usage: python -m emu.run [firmware.syx] [snapshot] [options]

  --weakptr    step over the weak_ptr branches that freeze the main task
  --slc        force the eMMC SLC flag (unnecessary with the eSDHC model)
  --scale N    integer panel zoom (default: fits your screen)
  --help       this

Only %s has been tested.""" % TESTED


def main(argv):
    if '--help' in argv or '-h' in argv:
        print(USAGE)
        return 0
    flags = [a for a in argv if a.startswith('--')]
    rest = [a for a in argv if not a.startswith('--')]
    if '--scale' in argv:                       # --scale takes a value
        i = argv.index('--scale')
        if i + 1 < len(argv) and argv[i + 1] in rest:
            rest.remove(argv[i + 1])
    syx = rest[0] if rest else SYX
    snapshot = rest[1] if len(rest) > 1 else SNAPSHOT

    need_syx(syx)
    need_sections(syx)
    if syx != SYX:
        print('Note: only %s has been tested. Addresses throughout this\n'
              'project are specific to that build, so a different firmware\n'
              'will very likely not boot.\n' % TESTED)
    need_snapshot(snapshot)

    cmd = [sys.executable, '-m', 'emu.gui', snapshot] + flags
    print('$ %s\n' % ' '.join(cmd), flush=True)
    return subprocess.call(cmd)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
