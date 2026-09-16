"""Does an in-place machine-type change reach the DSP frame?

Step 1b of HANDOVER-2026-09-16. The static reading (docs/FINDINGS.md, "The SRAM
row refreshes only when the track's source pointer changes") says the DSP
mirror row is refreshed wholesale by FUN_4002d438, and only when the per-track
sync-cache slot misses or is zero. Nothing incremental writes that row, so
changing a track object's machine-type byte in place should NOT reach the
frame until something invalidates the cache.

This tool tests that directly, and carries its own control so a null result
cannot be mistaken for a dead harness. Three conditions, each from a fresh
resume of the same snapshot:

  base     nothing poked                  the row and the object agree
  inplace  obj+0xa2 = NEW                 the question: does the row follow?
  invalid  obj+0xa2 = NEW, cache slot 0   the control: it must follow here

If `inplace` does not move the row but `invalid` does, the static reading is
confirmed and the harness is proven live by the same run. If neither moves,
the harness saw nothing and the run says nothing -- that is why the control is
not optional.

The frame interrupt does not fire on its own in the emulator, so the handler is
entered the way tools/sharcframe.py enters it: raise the vector, run to the
resume PC, and answer the DSPI2 driver from a hook instead of touching
hardware.

Run it on 1.16:

    DT2_SECTIONS=out/sections/dt2-1.16 DT2_SYX=Digitakt_II_OS1.16.syx \
      uv run python tools/machinecommit.py out/snapshots/dt2-1.16/boot400M.snap \
        --track 0 --type 5 --json out/maps/dt2-1.16-machinecommit.json
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn import UcError, UC_HOOK_MEM_WRITE  # noqa: E402
from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_D0, UC_M68K_REG_PC  # noqa: E402

import framelink  # noqa: E402

# Digitakt II 1.16. Every one of these is recorded in docs/FINDINGS.md under
# "The machine type reaches the SHARC" and "The SRAM row refreshes only when
# the track's source pointer changes"; the image loads at 0x40000400.
LIVE_BASE = 0x80004704      # _DAT_80004704, the live track-object array base
TRACK_STRIDE = 0x450        # per-track stride within that array
TRACK_OFF = 0x34            # the track object starts here inside its slot
TYPE_OFF = 0xa2             # machine-type byte inside the track object
ROW_BASE = 0x80003cd0       # the DSP mirror rows
ROW_STRIDE = 0x9a
CACHE_BASE = 0x8000470c     # the per-track "last synced source pointer" cache
FRAME_TYPE_OFF = 0x94       # TX frame offset of the type word, plus 2*track

ROW_REFRESH = 0x4002d438    # FUN_4002d438(src, track), the wholesale resync
INVALIDATE = 0x4002da38     # FUN_4002da38(track), unconditional cache zero
COND_INVALIDATE = 0x4002d7a4  # FUN_4002d7a4(value, track, index)
DISPATCHER = 0x40042fe2     # the DataChangeInfo dispatcher Ghidra never named

HOOKS = (
    (ROW_REFRESH, 'FUN_4002d438', 2),
    (INVALIDATE, 'FUN_4002da38', 1),
    (COND_INVALIDATE, 'FUN_4002d7a4', 3),
    (DISPATCHER, 'LAB_40042fe2', 3),
)


def rdlong(uc, addr):
    return struct.unpack('>I', uc.mem_read(addr, 4))[0]


def rdbyte(uc, addr):
    return uc.mem_read(addr, 1)[0]


def restore(snapshot, syx):
    """-> (m, at): a Machine restored from snapshot, with no timer running.

    The same flags tools/sharcframe.py uses. Resuming onto a bare Machine
    instead of through longrun.build drops its hooks and the run diverges.
    """
    from emu.longrun import build

    m, ev, st, pc, inq, at = build(snapshot, syx=syx, softfloat=True,
                                   bitmap=True, dsp=True)
    return m, at


def arg_hook(name, argc, hits):
    """A begin==end code hook that records a stacked-argument call."""

    def hook(uc, addr, size, user):
        sp = uc.reg_read(UC_M68K_REG_A7)
        words = struct.unpack('>%dI' % (argc + 1), uc.mem_read(sp, 4 * (argc + 1)))
        hits.append({'name': name, 'args': list(words[1:]), 'ret': words[0]})

    return hook


def drive(m, at, prof, track, passes, limit):
    """Enter the frame handler `passes` times. -> (frames, hits, stops)."""
    uc = m.uc
    calls = []
    hits = []

    def driver(uc, addr, size, user):
        sp = uc.reg_read(UC_M68K_REG_A7)
        ret, tx_len, tx, rx_len, rx = struct.unpack('>IIIII', uc.mem_read(sp, 20))
        data = bytes(uc.mem_read(tx, tx_len)) if tx and tx_len else b''
        calls.append(data)
        uc.reg_write(UC_M68K_REG_D0, 0)
        uc.reg_write(UC_M68K_REG_A7, sp + 4)
        uc.reg_write(UC_M68K_REG_PC, ret)

    at(prof['driver'], driver)
    for addr, name, argc in HOOKS:
        at(addr, arg_hook(name, argc, hits))

    resume = uc.reg_read(UC_M68K_REG_PC)
    frames, stops = [], []
    for _ in range(passes):
        del calls[:]
        uc.mem_write(prof['counter'], bytes(4))
        uc.reg_write(UC_M68K_REG_PC, resume)
        m.halt_vec = None
        if not m.raise_vector(prof['vector']):
            raise SystemExit('vector %d holds no handler in this snapshot'
                             % prof['vector'])
        handler = uc.reg_read(UC_M68K_REG_PC)
        stop = None
        try:
            uc.emu_start(handler, resume, count=limit)
        except UcError as e:
            stop = 'UcError: %s' % e
        pc = uc.reg_read(UC_M68K_REG_PC)
        if stop is None:
            if pc == resume:
                stop = 'returned'
            elif m.halt_vec is not None:
                # emu_start returns quietly on an unhandled vector, so a run
                # that never happened would otherwise look like a clean pass.
                stop = 'unhandled vector %d' % m.halt_vec
            else:
                stop = 'limit'
        stops.append(stop)
        frames.append(calls[-1] if calls else b'')
    return frames, hits, stops


def frame_type(frame, track):
    """-> the big-endian type word at TX offset 0x94 + 2*track, or None."""
    off = FRAME_TYPE_OFF + 2 * track
    if len(frame) < off + 2:
        return None
    return struct.unpack('>H', frame[off:off + 2])[0]


def condition(args, prof, name, poke_type, zero_cache):
    """Run one condition from a fresh resume. -> a result dict."""
    m, at = restore(args.snapshot, args.syx)
    uc = m.uc
    track = args.track

    live = rdlong(uc, LIVE_BASE)
    if live == 0:
        raise SystemExit('_DAT_80004704 is 0 in this snapshot: no live kit, so '
                         'there is no track object to change. Resume a later '
                         'snapshot.')
    obj = live + track * TRACK_STRIDE + TRACK_OFF
    row = ROW_BASE + track * ROW_STRIDE
    slot = CACHE_BASE + track * 4
    for addr in (obj, row, slot):
        m.ensure(addr)

    if args.open_gate:
        uc.mem_write(prof['gate'], bytes(4))

    before = {'obj_type': rdbyte(uc, obj + TYPE_OFF), 'row_type': rdbyte(uc, row),
              'cache': rdlong(uc, slot)}

    if poke_type is not None:
        uc.mem_write(obj + TYPE_OFF, bytes([poke_type]))
    if zero_cache:
        uc.mem_write(slot, bytes(4))

    poked = {'obj_type': rdbyte(uc, obj + TYPE_OFF), 'row_type': rdbyte(uc, row),
             'cache': rdlong(uc, slot)}

    writes = []
    uc.hook_add(UC_HOOK_MEM_WRITE,
                lambda uc, kind, addr, size, value, user:
                    writes.append({'addr': addr, 'size': size, 'value': value}),
                begin=row, end=row)

    frames, hits, stops = drive(m, at, prof, track, args.passes, args.limit)

    after = {'obj_type': rdbyte(uc, obj + TYPE_OFF), 'row_type': rdbyte(uc, row),
             'cache': rdlong(uc, slot)}
    return {
        'condition': name, 'track': track, 'obj': obj, 'row': row, 'slot': slot,
        'before': before, 'poked': poked, 'after': after,
        'row_writes': writes[:16], 'row_write_count': len(writes),
        'frame_type': [frame_type(f, track) for f in frames],
        'frame_len': [len(f) for f in frames],
        'stops': stops,
        'hits': hits[:64], 'hit_count': len(hits),
        'hit_names': sorted({h['name'] for h in hits}),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('snapshot')
    p.add_argument('--syx', help='firmware .syx (default: $DT2_SYX)')
    p.add_argument('--image', help='MAIN OS image for the frame-link profile '
                                   '(default: the sections dir)')
    p.add_argument('--track', type=int, default=0, help='track index, 0-15')
    p.add_argument('--type', type=int, default=5, dest='new_type',
                   help='machine type to write into the track object')
    p.add_argument('--passes', type=int, default=2,
                   help='frame-handler entries per condition')
    p.add_argument('--limit', type=int, default=5_000_000,
                   help='instruction budget per pass')
    p.add_argument('--open-gate', action='store_true', default=True,
                   help='write 0 to the frame gate so the handler builds a frame')
    p.add_argument('--no-open-gate', action='store_false', dest='open_gate')
    p.add_argument('--json', help='write the full result here')
    args = p.parse_args()

    if not 0 <= args.track <= 15:
        raise SystemExit('--track must be 0-15')

    image = args.image
    if image is None:
        from emu import config
        image = config.main_image()
    sha, prof = framelink.profile_for(image)
    print('image %s' % image)
    print('profile %s (sha-256 %s...)' % (prof['name'], sha[:16]))
    print('track %d, writing machine type %d\n' % (args.track, args.new_type))

    results = [
        condition(args, prof, 'base', None, False),
        condition(args, prof, 'inplace', args.new_type, False),
        condition(args, prof, 'invalid', args.new_type, True),
    ]

    print('%-9s %-19s %-19s %-11s %s' % ('condition', 'obj type b/a',
                                         'row type b/a', 'frame 0x94', 'hooks hit'))
    for r in results:
        print('%-9s %-19s %-19s %-11s %s' % (
            r['condition'],
            '%d -> %d' % (r['before']['obj_type'], r['after']['obj_type']),
            '%d -> %d' % (r['before']['row_type'], r['after']['row_type']),
            ','.join('-' if v is None else str(v) for v in r['frame_type']),
            ','.join(r['hit_names']) or 'none'))
    print()
    for r in results:
        print('%-9s stops=%s row_writes=%d frame_len=%s'
              % (r['condition'], ','.join(r['stops']), r['row_write_count'],
                 ','.join(str(n) for n in r['frame_len'])))

    base, inplace, invalid = results
    moved_inplace = inplace['after']['row_type'] != inplace['before']['row_type']
    moved_invalid = invalid['after']['row_type'] != invalid['before']['row_type']
    print()
    if not moved_invalid:
        print('INCONCLUSIVE: the control did not move the row either, so this '
              'run does not show the mechanism working at all. Check the stops '
              'column and the frame lengths before reading anything into it.')
    elif moved_inplace:
        print('An in-place type change DID reach the row: something '
              'invalidates the cache or refreshes the row on its own.')
    else:
        print('An in-place type change did NOT reach the row, and the '
              'invalidate control did. The static reading holds: the row '
              'follows the cache, not the object.')

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, 'w') as f:
            json.dump({'image': image, 'sha256': sha, 'profile': prof['name'],
                       'track': args.track, 'new_type': args.new_type,
                       'results': results}, f, indent=2, default=str)
        print('\nwrote %s' % args.json)


if __name__ == '__main__':
    main()
