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
import hashlib
import os
import subprocess
import sys

from emu import config

TESTED = config.TESTED_NAME
SNAPSHOT = 'boot400M.snap'
LADDER = '60000000,120000000,200000000,280000000,400000000'
MARKER = '.source-sha256'


def marker_path():
    return os.path.join(config.sections_dir(), MARKER)

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


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def paths_for(syx):
    """-> (snapshot, prefix) for this firmware.

    Sections and snapshots are firmware-specific, and `sections/` can only hold
    one firmware at a time because the filenames are fixed. The tested build
    keeps the historic paths so existing snapshots and every path in the docs
    still work; anything else gets its own directory, so a second firmware can
    never quietly resume the first one's boot.
    """
    if config.is_tested(syx):
        return config.snapshot(SNAPSHOT), config.snapshot('boot')
    stem = os.path.splitext(os.path.basename(syx))[0]
    return (config.snapshot(os.path.join(stem, SNAPSHOT)),
            config.snapshot(os.path.join(stem, 'boot')))


def need_matching_sections(syx, accept=False):
    """Refuse to pair the sections with a firmware they did not come from.

    Nothing in the extracted filenames records which `.syx` produced them, and
    the names are fixed, so the directory holds exactly one firmware at a time.
    Without this a second firmware silently runs against the first one's code.

    When there is no marker the provenance is genuinely unknown, so this does
    NOT guess. For the tested build it records and continues, because that is
    what a pre-existing checkout almost certainly holds; for anything else it
    stops and makes you say so with --accept-sections. An earlier version wrote
    the marker unconditionally and thereby labelled one device's sections with
    another device's hash, which is precisely the failure it exists to prevent.
    """
    digest = sha256(syx)
    path = marker_path()
    if os.path.exists(path):
        was = open(path).read().strip()
        if was == digest:
            return
        raise SystemExit(
            '%s/ does not belong to %s.\n\n'
            '  sections came from  %s\n'
            '  you asked for       %s\n\n'
            'The section filenames are fixed, so that directory holds only one\n'
            'firmware at a time. Re-extract to switch:\n\n'
            '    rm -rf %s/\n'
            '    elektron-firmware-tool -i %s -o %s/'
            % (config.sections_dir(), os.path.basename(syx), was[:16],
               digest[:16], config.sections_dir(), syx, config.sections_dir()))
    if not (config.is_tested(syx) or accept):
        raise SystemExit(
            'Cannot tell which firmware %s/ was extracted from, and you asked\n'
            'for %s, which is not the tested build.\n\n'
            'Those sections are most likely another firmware\'s, and running\n'
            'them would emulate that one under this one\'s name. Either\n'
            're-extract:\n\n'
            '    rm -rf %s/\n'
            '    elektron-firmware-tool -i %s -o %s/\n\n'
            'or pass --accept-sections if you are certain they match.'
            % (config.sections_dir(), os.path.basename(syx),
               config.sections_dir(), syx, config.sections_dir()))
    open(path, 'w').write(digest + '\n')
    print('Recorded %s/ as belonging to %s (%s).\n'
          % (config.sections_dir(), os.path.basename(syx), digest[:16]))


def need_syx(path):
    if path and os.path.exists(path):
        return
    raise SystemExit(
        'Missing firmware: %s\n\n'
        'No Elektron firmware ships with this repository and none ever should\n'
        '-- it is copyright Elektron. Supply your own lawfully-obtained copy\n'
        'and put it in the working directory. Only %s has been tested.'
        % (path, TESTED))


def need_sections(syx):
    config.main_image()          # raises config.NotFound with the how-to


def need_snapshot(snapshot, prefix, syx):
    """Build the boot ladder if the snapshot is not there. -> True if built."""
    if os.path.exists(snapshot):
        return False
    os.makedirs(os.path.dirname(snapshot) or '.', exist_ok=True)
    print('No %s yet. Building the boot snapshots -- one cold boot from\n'
          'reset, about 400M instructions, so expect a few minutes. This\n'
          'happens once.\n' % snapshot, flush=True)
    r = subprocess.run([sys.executable, '-m', 'emu.checkpoint', 'make',
                        LADDER, prefix, syx])
    if r.returncode != 0 or not os.path.exists(snapshot):
        raise SystemExit('Snapshot build failed; cannot continue.')
    print('\nBuilt %s.\n' % snapshot)
    return True


USAGE = """usage: python -m emu.run [firmware.syx] [snapshot] [options]

  --weakptr    step over the weak_ptr branches that freeze the main task
  --slc        force the eMMC SLC flag (unnecessary with the eSDHC model)
  --scale N    integer panel zoom (default: fits your screen)
  --accept-sections
               confirm the extracted sections match the firmware you named
  --check      resolve and validate everything, then stop without running
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
    syx = config.firmware(rest[0] if rest else None)
    default_snap, prefix = paths_for(syx)
    snapshot = rest[1] if len(rest) > 1 else default_snap

    need_sections(syx)
    need_matching_sections(syx, accept='--accept-sections' in flags)
    if not config.is_tested(syx):
        print('Note: only %s has been tested, and every address in this\n'
              'project is specific to that build. A different firmware will\n'
              'very likely not boot. Its snapshots go under %s so they cannot\n'
              'be confused with the tested build\'s.\n' % (TESTED, prefix))
    if '--check' in flags:
        print('Checks passed. firmware=%s  sections=%s/  snapshot=%s'
              % (syx, config.sections_dir(), snapshot))
        return 0
    need_snapshot(snapshot, prefix, syx)

    gui_flags = [f for f in flags
                 if f not in ('--accept-sections', '--check')]
    cmd = [sys.executable, '-m', 'emu.gui', snapshot, '--syx', syx] + gui_flags
    print('$ %s\n' % ' '.join(cmd), flush=True)
    return subprocess.call(cmd)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
