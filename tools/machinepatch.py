#!/usr/bin/env python3
"""Relocate the UI's source machine-list table into the MAIN OS cave, live.

Milestone A of adding an eighth machine. `docs/FINDINGS.md`'s "The ColdFire
machine dispatch" section established that the UI's *source* machine list is
seven big-endian u32 at rodata `0x401e1958`-`0x401e1974` (`{0,1,2,3,6,4,5}`),
copied into a `std::vector<int>` by `FUN_40051fbc` via two `pea` bounds at
`0x40052000` (END) and `0x4005200a` (START). This tool patches a resumed
snapshot, before `FUN_40051fbc` runs, so that:

  - a new 8-entry table `{0,1,2,3,6,4,5,7}` is written into the MAIN OS cave
    at `0x402f9c14` (58,188 zero bytes in the static image, confirmed clear
    of the one runtime-written byte at `0x402fa193`);
  - the two `pea` operands are repointed at the cave copy instead of the
    original rodata table.

It then proves the firmware actually reads the relocated copy -- and not the
original -- by installing `mmiotrace.py`'s `CountingSink` over both the cave
range and the original table's rodata range, and reporting which one saw
read traffic.

Index 7 has no eighth descriptor entry, so it falls back to descriptor entry
6 (the existing "MANUAL SLICE" collapses index 6 and would-be index 7 to the
same descriptor). Expect the new row to render as a second MANUAL SLICE.
That is the correct, unsurprising result for Milestone A: this proves the
list-relocation plumbing works, not that a new machine type exists yet.

Milestone B (`--milestone b`) goes further: it installs an eighth machine
*descriptor*, reached via a cave trampoline that replaces `FUN_400caf48`
(the ColdFire machine dispatch at `0x400caf48`). Types 0..6 resolve exactly
as before (delegated back to the original `0x42923644` array), type 7
resolves to a new 44-byte descriptor built in the cave (fields copied from
entry 6, MANUAL SLICE, but with distinct name-string reps), and anything
out of range still falls back to entry 6, matching the original's forgiving
failure mode. It then unit-tests the patched dispatch directly, by calling
`0x400caf48` in the live guest for arguments 0..8 and checking D0 against
the expected descriptor address for each.

Bisecting Milestone B's halves independently: `--parts list` alone (the
8-entry table, dispatch left unpatched) fails to boot; `--parts dispatch`
alone boots fine. So the failure is caused by the list gaining an eighth
entry, not by the trampoline, the descriptor, or the cave writes. That
turned out to be specifically the value 7: `FUN_4005d7b8` maps machine
type to a UI group id, and mapped type 7 to group 0, a group nothing else
uses. `--parts group` patches its exact-equality bound test into a range
test so 7 lands in the same group as 6. `--parts name` installs an eighth
row in the display-name table (`FUN_400dcc50`) so the new machine gets its
own "Placeholder"/"PLC" strings instead of falling back to an existing
entry's. `--parts both` (the default) applies all four halves. `--eighth`
exists to tell "eight entries is too many" apart from "the value 7 is the
problem": run with `--parts list --eighth N` for some other N.

This tool patches **guest memory on a resumed snapshot only**. It does not
modify any file, does not touch the firmware image on disk, and produces
nothing flashable -- the patch evaporates when the emulator process exits.

Modelled on `tools/memdump.py` (resume/build, intro-handover spin loop,
argparse/JSON conventions) and `tools/mmiotrace.py` (`CountingSink`,
`install_mmio_trace`). As in both, `reg_read(UC_M68K_REG_SR)` is never
called between `emu_start` calls -- it clobbers condition codes on this
patched Unicorn build.

Usage:
    uv run python tools/machinepatch.py --syx Digitakt_II_OS1.15C.syx \\
        --snapshot snapshots/boot400M.snap --json out/machinepatch.json

    uv run python tools/machinepatch.py --syx Digitakt_II_OS1.15C.syx \\
        --snapshot snapshots/boot400M.snap --no-patch --json out/control.json
"""
import argparse
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.m68k_const import UC_M68K_REG_A0, UC_M68K_REG_D0, UC_M68K_REG_PC

from addrtrace import load_main_image
from mmiotrace import CountingSink

from emu import symbols
from emu.dtim import Dtims, Timers
from emu.harness import PAGE
from emu.longrun import build, spin
from emu.pit import Pits, intro_running

END_SITE = 0x40052000
START_SITE = 0x4005200a
END_WANT = bytes.fromhex('4879401e1974')
START_WANT = bytes.fromhex('4879401e1958')
TABLE_D_LO, TABLE_D_HI = 0x401e1958, 0x401e1973
ORIGINAL_TABLE = (0, 1, 2, 3, 6, 4, 5)
NEW_TABLE = ORIGINAL_TABLE + (7,)
DEFAULT_CAVE = 0x402f9c14
DEFAULT_EIGHTH = 7

DISPATCH = 0x400caf48
DISPATCH_WANT = bytes.fromhex('7206202f0004')
DESCRIPTOR_BASE = 0x42923644
DESCRIPTOR_STRIDE = 0x2c
FALLBACK_DESCRIPTOR = 0x4292374c
DESCRIPTOR_FIELDS = (0xf8, 0xf9, 0, 0xfb, 0xfc, 0xfd, 0, 0xfe, 0x0a)
DEFAULT_CAVE_B = 0x40303e5c
TRAMP_OFF = 0x000
DESC_OFF = 0x100
LNAME_OFF = 0x140
LCHARS_OFF = 0x14c
SNAME_OFF = 0x160
SCHARS_OFF = 0x16c
TABLE_B_OFF = 0x180
LONG_NAME = 'PLACEHOLDER'
SHORT_NAME = 'PLHD'
SCRATCH_PAGE = 0x1ff00000
DISPATCH_SENTINEL = 0xdeadbee0

GROUP_ADDR = 0x4005d7ca
GROUP_WANT = bytes.fromhex('7206b2806604')
GROUP_NEW = bytes.fromhex('7207b2806504')

NAME_ADDR = 0x400dcc50
NAME_HEAD_WANT = bytes.fromhex('7206202f0004b2806514')
NAME_LEA_ADDR = 0x400dcc60
NAME_LEA_WANT = bytes.fromhex('41f9401fbc50')
NAME_TABLE_SRC = 0x401fbc50
NAME_TABLE_ROWS = 7
NAME_TABLE_ROW_BYTES = 12
NAME_TABLE_OFF = 0x200
LONGSTR_OFF = 0x280
SHORTSTR_OFF = 0x290
LONGSTR = b'Placeholder\x00'
SHORTSTR = b'PLC\x00'


def build_trampoline(cave_b):
    desc = cave_b + DESC_OFF
    return (
        bytes.fromhex('202f0004')
        + bytes.fromhex('7207')
        + bytes.fromhex('b280')
        + bytes.fromhex('6608')
        + bytes.fromhex('203c') + struct.pack('>I', desc)
        + bytes.fromhex('4e75')
        + bytes.fromhex('7206')
        + bytes.fromhex('b280')
        + bytes.fromhex('6510')
        + bytes.fromhex('123c002c')
        + bytes.fromhex('4c010800')
        + bytes.fromhex('0680') + struct.pack('>I', DESCRIPTOR_BASE)
        + bytes.fromhex('4e75')
        + bytes.fromhex('203c') + struct.pack('>I', FALLBACK_DESCRIPTOR)
        + bytes.fromhex('4e75')
    )


def build_descriptor(cave_b):
    return struct.pack('>11I', cave_b + LCHARS_OFF, cave_b + SCHARS_OFF,
                        *DESCRIPTOR_FIELDS)


def build_rep(name):
    chars = name.encode('ascii') + b'\x00'
    return struct.pack('>IIi', len(name), len(name), -1) + chars


def patch_b(m, cave_b, parts=('list', 'dispatch', 'group', 'name'),
            eighth=DEFAULT_EIGHTH):
    lines = []

    if 'dispatch' in parts:
        cur = bytes(m.uc.mem_read(DISPATCH, 6))
        if cur != DISPATCH_WANT:
            raise SystemExit(
                'machinepatch: %#010x holds %s, expected %s'
                % (DISPATCH, cur.hex(), DISPATCH_WANT.hex()))
    if 'list' in parts:
        for site, want in ((END_SITE, END_WANT), (START_SITE, START_WANT)):
            cur = bytes(m.uc.mem_read(site, 6))
            if cur != want:
                raise SystemExit(
                    'machinepatch: %#010x holds %s, expected %s'
                    % (site, cur.hex(), want.hex()))
    if 'group' in parts:
        cur = bytes(m.uc.mem_read(GROUP_ADDR, len(GROUP_WANT)))
        if cur != GROUP_WANT:
            raise SystemExit(
                'machinepatch: %#010x holds %s, expected %s'
                % (GROUP_ADDR, cur.hex(), GROUP_WANT.hex()))
    if 'name' in parts:
        cur = bytes(m.uc.mem_read(NAME_ADDR, len(NAME_HEAD_WANT)))
        if cur != NAME_HEAD_WANT:
            raise SystemExit(
                'machinepatch: %#010x holds %s, expected %s'
                % (NAME_ADDR, cur.hex(), NAME_HEAD_WANT.hex()))
        cur = bytes(m.uc.mem_read(NAME_LEA_ADDR, len(NAME_LEA_WANT)))
        if cur != NAME_LEA_WANT:
            raise SystemExit(
                'machinepatch: %#010x holds %s, expected %s'
                % (NAME_LEA_ADDR, cur.hex(), NAME_LEA_WANT.hex()))

    m.ensure(cave_b)

    if 'dispatch' in parts:
        tramp = build_trampoline(cave_b)
        old = bytes(m.uc.mem_read(cave_b + TRAMP_OFF, len(tramp)))
        m.uc.mem_write(cave_b + TRAMP_OFF, tramp)
        lines.append('%#010x  %s -> %s' % (cave_b + TRAMP_OFF, old.hex(), tramp.hex()))

        desc = build_descriptor(cave_b)
        old = bytes(m.uc.mem_read(cave_b + DESC_OFF, len(desc)))
        m.uc.mem_write(cave_b + DESC_OFF, desc)
        lines.append('%#010x  %s -> %s' % (cave_b + DESC_OFF, old.hex(), desc.hex()))

        lrep = build_rep(LONG_NAME)
        old = bytes(m.uc.mem_read(cave_b + LNAME_OFF, len(lrep)))
        m.uc.mem_write(cave_b + LNAME_OFF, lrep)
        lines.append('%#010x  %s -> %s' % (cave_b + LNAME_OFF, old.hex(), lrep.hex()))

        srep = build_rep(SHORT_NAME)
        old = bytes(m.uc.mem_read(cave_b + SNAME_OFF, len(srep)))
        m.uc.mem_write(cave_b + SNAME_OFF, srep)
        lines.append('%#010x  %s -> %s' % (cave_b + SNAME_OFF, old.hex(), srep.hex()))

    if 'list' in parts:
        tbytes = struct.pack('>8I', *(ORIGINAL_TABLE + (eighth,)))
        old = bytes(m.uc.mem_read(cave_b + TABLE_B_OFF, len(tbytes)))
        m.uc.mem_write(cave_b + TABLE_B_OFF, tbytes)
        lines.append('%#010x  %s -> %s' % (cave_b + TABLE_B_OFF, old.hex(), tbytes.hex()))

        for site, new_ptr in ((START_SITE, cave_b + TABLE_B_OFF),
                               (END_SITE, cave_b + TABLE_B_OFF + len(tbytes))):
            old = bytes(m.uc.mem_read(site + 2, 4))
            new = struct.pack('>I', new_ptr)
            m.uc.mem_write(site + 2, new)
            lines.append('%#010x  %s -> %s' % (site + 2, old.hex(), new.hex()))

    if 'group' in parts:
        old = bytes(m.uc.mem_read(GROUP_ADDR, len(GROUP_NEW)))
        m.uc.mem_write(GROUP_ADDR, GROUP_NEW)
        lines.append('%#010x  %s -> %s' % (GROUP_ADDR, old.hex(), GROUP_NEW.hex()))

    if 'name' in parts:
        table_addr = cave_b + NAME_TABLE_OFF
        long_addr = cave_b + LONGSTR_OFF
        short_addr = cave_b + SHORTSTR_OFF

        rows = bytes(m.uc.mem_read(NAME_TABLE_SRC,
                                    NAME_TABLE_ROWS * NAME_TABLE_ROW_BYTES))
        old = bytes(m.uc.mem_read(table_addr, len(rows)))
        m.uc.mem_write(table_addr, rows)
        lines.append('%#010x  %s -> %s' % (table_addr, old.hex(), rows.hex()))

        row8 = struct.pack('>III', long_addr, short_addr, 0)
        row8_addr = table_addr + NAME_TABLE_ROWS * NAME_TABLE_ROW_BYTES
        old = bytes(m.uc.mem_read(row8_addr, len(row8)))
        m.uc.mem_write(row8_addr, row8)
        lines.append('%#010x  %s -> %s' % (row8_addr, old.hex(), row8.hex()))

        old = bytes(m.uc.mem_read(long_addr, len(LONGSTR)))
        m.uc.mem_write(long_addr, LONGSTR)
        lines.append('%#010x  %s -> %s' % (long_addr, old.hex(), LONGSTR.hex()))

        old = bytes(m.uc.mem_read(short_addr, len(SHORTSTR)))
        m.uc.mem_write(short_addr, SHORTSTR)
        lines.append('%#010x  %s -> %s' % (short_addr, old.hex(), SHORTSTR.hex()))

        # The bound is the moveq's IMMEDIATE, the second byte of `72 06`, not
        # the opcode byte -- writing at NAME_ADDR itself destroys the
        # instruction.
        old = bytes(m.uc.mem_read(NAME_ADDR + 1, 1))
        m.uc.mem_write(NAME_ADDR + 1, b'\x07')
        lines.append('%#010x  %s -> %s'
                     % (NAME_ADDR + 1, old.hex(), b'\x07'.hex()))

        old = bytes(m.uc.mem_read(NAME_LEA_ADDR + 2, 4))
        new = struct.pack('>I', table_addr)
        m.uc.mem_write(NAME_LEA_ADDR + 2, new)
        lines.append('%#010x  %s -> %s' % (NAME_LEA_ADDR + 2, old.hex(), new.hex()))

    if 'dispatch' in parts:
        old = bytes(m.uc.mem_read(DISPATCH, 6))
        new = b'\x4e\xf9' + struct.pack('>I', cave_b)
        m.uc.mem_write(DISPATCH, new)
        lines.append('%#010x  %s -> %s' % (DISPATCH, old.hex(), new.hex()))

    return lines


def call_dispatch(m, arg, scratch_sp, sentinel):
    uc = m.uc
    saved_d = [uc.reg_read(UC_M68K_REG_D0 + i) for i in range(8)]
    saved_a = [uc.reg_read(UC_M68K_REG_A0 + i) for i in range(8)]
    saved_pc = uc.reg_read(UC_M68K_REG_PC)

    uc.mem_write(scratch_sp, struct.pack('>I', sentinel))
    uc.mem_write(scratch_sp + 4, struct.pack('>I', arg))
    uc.reg_write(UC_M68K_REG_A0 + 7, scratch_sp)

    uc.emu_start(DISPATCH, sentinel)
    d0 = uc.reg_read(UC_M68K_REG_D0) & 0xffffffff

    for i in range(8):
        uc.reg_write(UC_M68K_REG_D0 + i, saved_d[i])
        uc.reg_write(UC_M68K_REG_A0 + i, saved_a[i])
    uc.reg_write(UC_M68K_REG_PC, saved_pc)
    return d0


def read_cstr(m, addr, limit=64):
    chars = bytearray()
    for i in range(limit):
        b = bytes(m.uc.mem_read(addr + i, 1))[0]
        if b == 0:
            break
        chars.append(b)
    return chars.decode('latin1')


def read_rep(m, addr):
    length, cap, refcount = struct.unpack('>IIi', bytes(m.uc.mem_read(addr, 12)))
    chars = bytes(m.uc.mem_read(addr + 12, length))
    return {
        'length': length,
        'capacity': cap,
        'refcount': refcount,
        'text': chars.decode('latin1'),
    }


def patch(m, cave_addr):
    lines = []
    for site, want in ((END_SITE, END_WANT), (START_SITE, START_WANT)):
        cur = bytes(m.uc.mem_read(site, 6))
        if cur != want:
            raise SystemExit(
                'machinepatch: %#010x holds %s, expected %s'
                % (site, cur.hex(), want.hex()))

    m.ensure(cave_addr)
    new_bytes = struct.pack('>8I', *NEW_TABLE)
    old_cave = bytes(m.uc.mem_read(cave_addr, len(new_bytes)))
    m.uc.mem_write(cave_addr, new_bytes)
    lines.append('%#010x  %s -> %s' % (cave_addr, old_cave.hex(), new_bytes.hex()))

    for site, new_ptr in ((START_SITE, cave_addr), (END_SITE, cave_addr + 32)):
        old = bytes(m.uc.mem_read(site + 2, 4))
        new = struct.pack('>I', new_ptr)
        m.uc.mem_write(site + 2, new)
        lines.append('%#010x  %s -> %s' % (site + 2, old.hex(), new.hex()))

    return lines


def run(args):
    main_img, _ = load_main_image(args.syx)
    profile = symbols.resolve(main_img)

    m, ev, st, pc, inq, at = build(
        args.snapshot, syx=args.syx, unblock=True, softfloat=True,
        bitmap=True, dsp=True, slc=args.slc,
        sdgate=args.sdgate, esdhc=args.esdhc)

    patch_lines = []
    if not args.no_patch:
        patch_lines = patch(m, args.cave)

    sink = CountingSink()
    ranges = ((args.cave, args.cave + 31), (TABLE_D_LO, TABLE_D_HI))
    m.install_mmio_trace(sink, ranges=ranges, owned=False)

    intro = intro_running(m, profile.intro_pit3_isr)
    pits = Timers(Pits(m, hold=intro), Dtims(m, channels=(3,), hold=intro))
    phase = {'post_intro': not intro}

    if intro and profile.intro_done is not None:
        def handover(uc, a, size, data):
            pits.release()
            phase['post_intro'] = True
        at(profile.intro_done, handover)

    done, pc_, stop = 0, pc, 'limit'
    t0 = time.time()
    target = args.instrs
    while True:
        pc_, executed, stop = spin(m, pc_, max(target - done, args.chunk),
                                    pits=pits)
        done += executed
        if stop != 'limit':
            break
        if done >= target and phase['post_intro']:
            break
        if done >= target and not phase['post_intro']:
            if done >= args.max_instrs:
                break
            target = min(target + args.chunk, args.max_instrs)

    raw = bytes(m.uc.mem_read(args.cave, 32))
    table = list(struct.unpack('>8I', raw))

    def range_report(lo, hi):
        keys = [k for k in sink.first_pc if lo <= k[0] <= hi and k[1] == 'read']
        addrs = sorted(set(k[0] for k in keys))
        events = sum(v for k, v in _counts(sink, lo, hi))
        return {
            'range': '0x%08x-0x%08x' % (lo, hi),
            'events': events,
            'distinct_addrs': len(addrs),
            'first_pc': {'0x%08x' % a: '0x%08x' % sink.first_pc[(a, 'read')]
                         for a in addrs},
        }

    cave_report = range_report(args.cave, args.cave + 31)
    tabled_report = range_report(TABLE_D_LO, TABLE_D_HI)

    mode = 'control' if args.no_patch else 'patched'
    if mode == 'patched':
        cave_ok = cave_report['events'] > 0
        tabled_ok = tabled_report['events'] == 0
        if cave_ok and tabled_ok:
            verdict = 'PASS: relocated table read, original table D untouched'
        else:
            fails = []
            if not cave_ok:
                fails.append('relocated range saw zero reads')
            if not tabled_ok:
                fails.append('original table D range still saw reads')
            verdict = 'FAIL: ' + '; '.join(fails)
    else:
        verdict = ('control: original table D events=%d, cave events=%d'
                   % (tabled_report['events'], cave_report['events']))

    return {
        'syx': args.syx,
        'snapshot': args.snapshot,
        'mode': mode,
        'cave': '0x%08x' % args.cave,
        'patch_lines': patch_lines,
        'cave_range': cave_report,
        'table_d_range': tabled_report,
        'readback_table': ['0x%08x' % v for v in table],
        'reached_post_intro': phase['post_intro'],
        'instrs': done,
        'stop': stop,
        'elapsed_s': round(time.time() - t0, 1),
        'verdict': verdict,
    }


def _counts(sink, lo, hi):
    keys = [k for k in sink.first_pc if lo <= k[0] <= hi and k[1] == 'read']
    for key in keys:
        total = sum(bucket.get(key, 0) for bucket in sink.buckets)
        total += sink.cur.get(key, 0)
        yield key, total


def run_b(args):
    main_img, _ = load_main_image(args.syx)
    profile = symbols.resolve(main_img)

    m, ev, st, pc, inq, at = build(
        args.snapshot, syx=args.syx, unblock=True, softfloat=True,
        bitmap=True, dsp=True, slc=args.slc,
        sdgate=args.sdgate, esdhc=args.esdhc)

    patch_lines = []
    if not args.no_patch:
        patch_lines = patch_b(m, args.cave_b, parts=args.parts, eighth=args.eighth)

    intro = intro_running(m, profile.intro_pit3_isr)
    pits = Timers(Pits(m, hold=intro), Dtims(m, channels=(3,), hold=intro))
    phase = {'post_intro': not intro}

    if intro and profile.intro_done is not None:
        def handover(uc, a, size, data):
            pits.release()
            phase['post_intro'] = True
        at(profile.intro_done, handover)

    done, pc_, stop = 0, pc, 'limit'
    t0 = time.time()
    target = args.instrs
    while True:
        pc_, executed, stop = spin(m, pc_, max(target - done, args.chunk),
                                    pits=pits)
        done += executed
        if stop != 'limit':
            break
        if done >= target and phase['post_intro']:
            break
        if done >= target and not phase['post_intro']:
            if done >= args.max_instrs:
                break
            target = min(target + args.chunk, args.max_instrs)

    mode = 'control' if args.no_patch else 'patched'
    table = []
    descriptor = None
    long_name = None
    short_name = None
    name_row8 = None

    if mode == 'patched':
        m.ensure(SCRATCH_PAGE)
        scratch_sp = SCRATCH_PAGE + PAGE - 0x100
        expected = {a: DESCRIPTOR_BASE + a * DESCRIPTOR_STRIDE for a in range(7)}
        expected[7] = (args.cave_b + DESC_OFF if 'dispatch' in args.parts
                        else FALLBACK_DESCRIPTOR)
        expected[8] = FALLBACK_DESCRIPTOR
        for a in range(9):
            got = call_dispatch(m, a, scratch_sp, DISPATCH_SENTINEL)
            table.append({
                'arg': a,
                'expected': '0x%08x' % expected[a],
                'actual': '0x%08x' % got,
                'match': got == expected[a],
            })

        desc_raw = bytes(m.uc.mem_read(args.cave_b + DESC_OFF, 44))
        descriptor = ['0x%08x' % w for w in struct.unpack('>11I', desc_raw)]
        long_name = read_rep(m, args.cave_b + LNAME_OFF)
        short_name = read_rep(m, args.cave_b + SNAME_OFF)

        if 'name' in args.parts:
            row8_addr = (args.cave_b + NAME_TABLE_OFF
                         + NAME_TABLE_ROWS * NAME_TABLE_ROW_BYTES)
            row8_raw = bytes(m.uc.mem_read(row8_addr, NAME_TABLE_ROW_BYTES))
            long_ptr, short_ptr, third_ptr = struct.unpack('>III', row8_raw)
            name_row8 = {
                'addr': '0x%08x' % row8_addr,
                'raw': row8_raw.hex(),
                'long_ptr': '0x%08x' % long_ptr,
                'short_ptr': '0x%08x' % short_ptr,
                'third_ptr': '0x%08x' % third_ptr,
                'long_str': read_cstr(m, long_ptr),
                'short_str': read_cstr(m, short_ptr),
            }

        dispatch_ok = all(row['match'] for row in table)
        if dispatch_ok and phase['post_intro']:
            verdict = 'PASS: all nine dispatch results match, reached post-intro'
        else:
            fails = []
            if not dispatch_ok:
                fails.append('dispatch mismatch on arg(s) %s'
                              % [row['arg'] for row in table if not row['match']])
            if not phase['post_intro']:
                fails.append('did not reach post-intro')
            verdict = 'FAIL: ' + '; '.join(fails)
    else:
        verdict = 'control: no patch applied, dispatch not exercised'

    return {
        'syx': args.syx,
        'snapshot': args.snapshot,
        'mode': mode,
        'cave_b': '0x%08x' % args.cave_b,
        'patch_lines': patch_lines,
        'dispatch_table': table,
        'descriptor': descriptor,
        'long_name': long_name,
        'short_name': short_name,
        'name_row8': name_row8,
        'reached_post_intro': phase['post_intro'],
        'instrs': done,
        'stop': stop,
        'elapsed_s': round(time.time() - t0, 1),
        'verdict': verdict,
    }


def print_report(report):
    print(json.dumps(report, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--syx', required=True)
    ap.add_argument('--snapshot', required=True)
    ap.add_argument('--cave', type=lambda s: int(s, 0), default=DEFAULT_CAVE,
                     help='MAIN OS cave address to write the relocated table '
                          'into (default: 0x402f9c14)')
    ap.add_argument('--milestone', choices=('a', 'b'), default='a',
                     help='a: relocate the source table (default). '
                          'b: install an eighth machine descriptor via a '
                          'cave trampoline and unit-test the dispatch.')
    ap.add_argument('--cave-b', dest='cave_b', type=lambda s: int(s, 0),
                     default=DEFAULT_CAVE_B,
                     help='cave address for --milestone b (default: '
                          '0x40303e5c)')
    ap.add_argument('--parts',
                     choices=('list', 'dispatch', 'group', 'name', 'both'),
                     default='both',
                     help='which half of --milestone b to apply: the list '
                          'relocation, the dispatch trampoline, the group-id '
                          'range fix, the display-name table, or both/all '
                          'four (default: both)')
    ap.add_argument('--eighth', type=lambda s: int(s, 0), default=DEFAULT_EIGHTH,
                     help='value to write as the 8th entry of the relocated '
                          'machine list for --milestone b (default: 7). '
                          'Use this to distinguish "eight entries is too '
                          'many" from "the value 7 specifically is the '
                          'problem".')
    ap.add_argument('--no-patch', action='store_true',
                     help='skip the patch, for a control run')
    ap.add_argument('--instrs', type=lambda s: int(s, 0), default=90_000_000,
                     help='instruction budget to run forward before '
                          'observing (default: 90M, enough for post-intro '
                          'handover from snapshots/boot400M.snap)')
    ap.add_argument('--max-instrs', type=lambda s: int(s, 0),
                     default=400_000_000,
                     help='hard ceiling; if handover has not happened by '
                          '--instrs, keep spinning in --chunk steps up to '
                          'this many instructions total')
    ap.add_argument('--chunk', type=lambda s: int(s, 0), default=5_000_000,
                     help='spin() chunk size for the extra post-budget '
                          'search for handover')
    ap.add_argument('--slc', action='store_true', default=True)
    ap.add_argument('--sdgate', dest='sdgate', action='store_true', default=True)
    ap.add_argument('--no-sdgate', dest='sdgate', action='store_false')
    ap.add_argument('--esdhc', dest='esdhc', action='store_true', default=True)
    ap.add_argument('--no-esdhc', dest='esdhc', action='store_false')
    ap.add_argument('--json', help='write the full report here')
    args = ap.parse_args(argv)
    args.parts = (('list', 'dispatch', 'group', 'name')
                  if args.parts == 'both' else (args.parts,))

    report = run(args) if args.milestone == 'a' else run_b(args)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)) or '.',
                     exist_ok=True)
        with open(args.json, 'w') as fh:
            json.dump(report, fh, indent=2)
    print_report(report)
    if report['mode'] == 'control':
        return 0
    return 0 if report['verdict'].startswith('PASS') else 1


if __name__ == '__main__':
    sys.exit(main())
