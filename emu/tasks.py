"""Where is every task parked?

Only one task runs at a time, so hooking the sem_pend entry never sees the
tasks that are *already* blocked -- they are sitting inside the pend, not
entering it. Their state is in their TCB instead.

The context switcher at 0x40000410 gives the layout:

    movea.l  $47d9adb4,a0          ; a0 = current TCB
    movem.l  d0-d7/a0-a7,$c(a0)    ; registers at TCB+0x0C ..
    move.l   -4(a7),$2c(a0)        ; .. so a0 is at +0x2C and a7 at +0x48
    movea.l  $4094c914,a1          ; ready-list cursor
    movea.l  (a1),a0 ; movea.l (a0),a0   ; TCB+0x00 is the next pointer
    movem.l  $c(a0),d0-d7/a0-a7 ; rte

so a parked task's PC is on its own stack: ColdFire pushes a two-longword
exception frame, [a7] = format/vector/SR and [a7+4] = PC.

The two literal operands above, $47d9adb4 and $4094c914, are exactly what
`symbols.current_tcb` / `symbols.ready_cursor` read out of the switcher, so
they are resolved per build in emu/symbols.py rather than hardcoded here.

Usage: python -m emu.tasks <snapshot>
"""
import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from emu.snapshot import restore
from emu import config, symbols

REG_BASE = 0x0C                 # d0-d7 then a0-a7
A7_OFF   = REG_BASE + 15 * 4    # 0x48
NEXT_OFF = 0x00


def u32(m, a):
    try: return struct.unpack('>I', m.uc.mem_read(a, 4))[0]
    except Exception: return None


def parked_pc(m, tcb):
    """-> (saved a7, frame word, pc) for a task that is not currently running."""
    sp = u32(m, tcb + A7_OFF)
    if not sp: return sp, None, None
    return sp, u32(m, sp), u32(m, sp + 4)


def ready_list(m, ready_cursor, limit=32):
    """Walk the ready list from the cursor. -> list of TCB addresses."""
    cur = u32(m, ready_cursor)
    if not cur: return []
    out, node, seen = [], u32(m, cur), set()
    while node and node not in seen and len(out) < limit:
        seen.add(node)
        out.append(node)
        node = u32(m, node + NEXT_OFF)
    return out


def main(snap):
    m, extra, regs = restore(snap)
    tasks = extra.get('tasks', {})
    main_img = open(config.main_image(), 'rb').read()
    profile = symbols.resolve(main_img)
    print('snapshot %s   n=%s' % (snap, extra.get('n')))
    cur, rl = None, []
    if profile.current_tcb is None or profile.ready_cursor is None:
        print('scheduler variables (current_tcb/ready_cursor) did not '
              'resolve for this image; skipping current-task and ready-list output')
    else:
        cur = u32(m, profile.current_tcb)
        print('current TCB 0x%08x   live pc=0x%08x sr=0x%04x' % (cur, regs['pc'], regs['sr']))
        rl = ready_list(m, profile.ready_cursor)
        print('ready list (%d nodes): %s' % (len(rl), ['0x%08x' % t for t in rl]))

    print('\n%-11s %-5s %-11s %-11s %-11s %s'
          % ('tcb', 'prio', 'entry', 'saved a7', 'parked pc', 'state'))
    rows = sorted(tasks.values(), key=lambda i: i['prio'])
    for info in rows:
        tcb = info['tcb']
        if tcb == cur:
            print('  0x%08x %-5d 0x%08x %-11s 0x%08x  RUNNING'
                  % (tcb, info['prio'], info['entry'], '-', regs['pc']))
            continue
        sp, frame, pc = parked_pc(m, tcb)
        print('  0x%08x %-5d 0x%08x 0x%08x  %s  %s'
              % (tcb, info['prio'], info['entry'], sp or 0,
                 ('0x%08x' % pc) if pc else '    ?     ',
                 'ready' if tcb in rl else 'blocked'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'snapshots/ext1080M.snap')
