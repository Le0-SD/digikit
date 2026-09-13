#!/usr/bin/env python3
"""Acceptance gate for the repack chain: rebuild a firmware .syx from
extracted sections, then re-extract the rebuilt container with the
DEVICE's own depacker and prove every section comes back byte-identical.

What this proves: the container write path -- dt2/build.py's packing,
its ELE3 table, the per-section storage rules, 8-in-7 encoding, SysEx
framing -- reproduces content that the device's own depacker (emu/oracle.py,
run under Unicorn) accepts and decodes to exactly the bytes it started
from. That is a strong claim about the write path, checked against the
real decoder rather than against this project's own packer's inverse.

What this does NOT prove: that the rebuilt .syx is acceptable to a real
device. Two fields in the format are still unrecovered and only carried
through as placeholders -- the preamble's 32-bit content checksum and the
per-message byte-125 checksum inside each SysEx message (see dt2/build.py).
The store-only packer in dt2/aplib.py also makes the image roughly three
times its original size, which the device's staging buffer may or may not
accept. DO NOT FLASH the output of this tool.

Runtime is dominated by depacking MAIN OS (section 3, ~3.1 MB) under
emulation: expect ~90 seconds. --quick skips that section and finishes
in a few seconds, for iteration; its result is a partial gate, not a
pass on the real thing.

    uv run python tools/roundtrip.py FIRMWARE.syx
        [--sections DIR]      default: sections/
        [--out FILE]          also write the rebuilt .syx here
        [--accept-sections]   skip the provenance check against FIRMWARE.syx
        [--quick]             skip section 3 (MAIN OS); partial gate only
"""
import argparse
import hashlib
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dt2 import build
from dt2.container import container as C
from emu.oracle import depack
from emu.extract import classify, NAMES, SOURCE_MARKER

TABLE_OFF = 0x20


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def check_provenance(syx, sections_dir, accept):
    """Refuse to run against sections that were extracted from a different
    .syx -- see emu/run.py's need_matching_sections, which this follows."""
    if accept:
        return
    marker_path = os.path.join(sections_dir, SOURCE_MARKER)
    digest = sha256(syx)
    if not os.path.exists(marker_path):
        raise SystemExit(
            'No %s in %s/, so it is not known which firmware these sections\n'
            'came from. Re-extract, or pass --accept-sections if you are\n'
            'certain they match %s.' % (SOURCE_MARKER, sections_dir, syx))
    was = open(marker_path).read().strip()
    if was != digest:
        raise SystemExit(
            '%s/ belongs to a different firmware image.\n\n'
            '  sections came from  %s\n'
            '  you asked for       %s\n\n'
            'Verifying one device\'s rebuild against another device\'s\n'
            'sections would produce a meaningless failure. Re-extract, or\n'
            'pass --accept-sections if you are certain they match.'
            % (sections_dir, was[:16], digest[:16]))


def load_sections(sections_dir):
    """-> {section_id: decompressed bytes}, one per id in emu/extract.py's
    NAMES, read from the fixed section_<id>_<name>.bin filenames."""
    orig = {}
    for sid, name in NAMES.items():
        path = os.path.join(sections_dir, 'section_%d_%s.bin' % (sid, name))
        if not os.path.exists(path):
            raise SystemExit('missing extracted section: %s' % path)
        with open(path, 'rb') as fh:
            orig[sid] = fh.read()
    return orig


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('syx', help='the firmware .syx to round-trip')
    ap.add_argument('--sections', default='sections',
                     help='directory of extracted sections (default: sections/)')
    ap.add_argument('--out', help='also write the rebuilt .syx here')
    ap.add_argument('--accept-sections', action='store_true',
                     help='skip the provenance check against FIRMWARE.syx')
    ap.add_argument('--quick', action='store_true',
                     help='skip section 3 (MAIN OS); partial gate only, a few seconds')
    args = ap.parse_args(argv)

    check_provenance(args.syx, args.sections, args.accept_sections)
    orig = load_sections(args.sections)

    out = build.rebuild(args.syx, replacements=dict(orig))

    if args.out:
        with open(args.out, 'wb') as fh:
            fh.write(out)

    fd, tmp_path = tempfile.mkstemp(suffix='.syx')
    os.close(fd)
    try:
        with open(tmp_path, 'wb') as fh:
            fh.write(out)

        c = C(tmp_path)
        n = struct.unpack_from('>I', c, 0x1C)[0]
        boot = orig[2]

        print('%-4s %-10s %-8s %12s %12s  %s' %
              ('id', 'name', 'kind', 'decomp len', 'dest', 'result'))
        all_ok = True
        for k in range(n):
            sid, off, clen, dest = struct.unpack_from('>IIII', c, TABLE_OFF + 16 * k)
            name = NAMES.get(sid, '?')
            if args.quick and sid == 3:
                print('%-4d %-10s %-8s %12s %#12x  %s' %
                      (sid, name, '-', '-', dest, 'SKIPPED (quick)'))
                continue
            kind, payload = classify(bytes(c[off:off + clen]))
            got = depack(boot, payload) if kind == 'packed' else payload
            ok = got == orig[sid]
            all_ok = all_ok and ok
            print('%-4d %-10s %-8s %12d %#12x  %s' %
                  (sid, name, kind, len(got), dest, 'OK' if ok else 'MISMATCH'))
    finally:
        os.remove(tmp_path)

    src_size = os.path.getsize(args.syx)
    out_size = len(out)
    print()
    print('source %d bytes, rebuilt %d bytes (%.2fx)' %
          (src_size, out_size, out_size / src_size))

    if args.quick:
        print()
        print('PARTIAL GATE (--quick): section 3 (MAIN OS) was not verified.')

    print()
    if all_ok:
        print('PASS' + (' (partial)' if args.quick else ''))
        return 0
    print('FAIL')
    return 1


if __name__ == '__main__':
    sys.exit(main())
