"""Long fast run: no per-instruction hook, chunked preemption, watch everything
that matters via begin==end hooks (free between hits)."""
import struct, sys, os, time, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn import UcError, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.m68k_const import (UC_M68K_REG_A7, UC_M68K_REG_PC, UC_M68K_REG_SR,
                                UC_M68K_REG_D0, UC_M68K_REG_A0)
import emu.dspboot as db
from emu.harness import Machine
from emu.snapshot import restore_into

TASK_CREATE, PRINT = 0x400012c8, 0x400054b4
SETPIXEL, PXCOPY   = 0x40104eb4, 0x400d315e
SWITCH_TO          = 0x4000044a
USR8, UDR8         = 0xEC070004, 0xEC07000C


def main(snapshot, instrs, chunk=500_000, send=b''):
    flash = db.build_flash('Digitakt_II_OS1.15C.syx')
    m = Machine(); st = {'seen': set(), 'n': 0, 'task_create_hits': {}}
    ev = {'tasks': [], 'prints': [], 'setpixel': 0, 'pxcopy': 0,
          'switch': collections.Counter(), 'uart_out': bytearray()}
    inq = collections.deque(send)
    m.install_isa_patches()

    def at(addr, fn):
        m.uc.hook_add(UC_HOOK_CODE, fn, begin=addr, end=addr)

    def flash_read(uc, a, s, d):
        sp = uc.reg_read(UC_M68K_REG_A7)
        ret, off, ln, dest = struct.unpack('>IIII', uc.mem_read(sp, 16))
        if ln and dest and off + ln <= len(flash):
            for p in range(0, ln + 0x100000, 0x100000): m.ensure(dest + p)
            uc.mem_write(dest, flash[off:off + ln])
        uc.reg_write(UC_M68K_REG_D0, 0); uc.reg_write(UC_M68K_REG_A7, sp + 4)
        uc.reg_write(UC_M68K_REG_PC, ret)

    def task_create(uc, a, s, d):
        sp = uc.reg_read(UC_M68K_REG_A7)
        _r, tcb, entry, prio = struct.unpack('>IIII', uc.mem_read(sp, 16))
        ev['tasks'].append((entry, prio, tcb))
        print('   TASK entry=0x%08x prio=%d tcb=0x%08x' % (entry, prio, tcb), flush=True)

    def do_print(uc, a, s, d):
        sp = uc.reg_read(UC_M68K_REG_A7)
        p = struct.unpack('>I', uc.mem_read(sp + 4, 4))[0]
        try: txt = bytes(uc.mem_read(p, 160)).split(b'\x00')[0].decode('latin1')
        except Exception: txt = '<0x%08x>' % p
        ev['prints'].append(txt)
        print('   PRINT %r' % txt, flush=True)

    at(db.FLASH_READ, flash_read)
    at(db.PEND_CALL, lambda uc,a,s,d: uc.mem_write(db.COMPLETION_SEM, struct.pack('>I',1)))
    at(TASK_CREATE, task_create)
    at(PRINT, do_print)
    at(SETPIXEL, lambda uc,a,s,d: ev.__setitem__('setpixel', ev['setpixel']+1))
    at(PXCOPY,   lambda uc,a,s,d: ev.__setitem__('pxcopy',  ev['pxcopy']+1))
    at(SWITCH_TO, lambda uc,a,s,d: ev['switch'].update([uc.reg_read(UC_M68K_REG_A0)]))

    def onr(uc, typ, addr, size, val, data):
        if addr == USR8: uc.mem_write(USR8, bytes([0x04 | (0x01 if inq else 0)]))
        elif addr == UDR8: uc.mem_write(UDR8, bytes([inq.popleft() if inq else 0]))
    def onw(uc, typ, addr, size, val, data):
        if addr == UDR8: ev['uart_out'].append(val & 0xFF)
    m.uc.hook_add(UC_HOOK_MEM_READ, onr, begin=USR8, end=UDR8+3)
    m.uc.hook_add(UC_HOOK_MEM_WRITE, onw, begin=USR8, end=UDR8+3)
    m.mmio[0xFC05C02C] = 0x100000F0; m.mmio[0xEC03802C] = 0x80000000
    m.install_mmio(); m.install_exceptions()
    pc = restore_into(m, snapshot, st)

    done, t0, stop = 0, time.time(), 'limit'
    while done < instrs:
        try: m.uc.emu_start(pc, 0, count=min(chunk, instrs - done))
        except UcError as e: stop = str(e); break
        pc = m.uc.reg_read(UC_M68K_REG_PC); done += chunk
        if (m.uc.reg_read(UC_M68K_REG_SR) & 0x0700) != 0x0700:
            m.raise_vector(32); pc = m.uc.reg_read(UC_M68K_REG_PC)
        if done % 250_000_000 == 0:
            print('  .. %dM instrs, %.1fs, tasks=%d prints=%d setPixel=%d'
                  % (done//1_000_000, time.time()-t0, len(ev['tasks']),
                     len(ev['prints']), ev['setpixel']), flush=True)
    return m, ev, done, time.time()-t0, stop


if __name__ == '__main__':
    snap = sys.argv[1]; n = int(sys.argv[2])
    send = (sys.argv[3]+'\r\n').encode() if len(sys.argv) > 3 else b''
    m, ev, done, dt, stop = main(snap, n, send=send)
    print('\n=== %d instrs in %.0fs (%.2fM/s) stop=%s ===' % (done, dt, done/dt/1e6, stop))
    print('new tasks : %d' % len(ev['tasks']))
    print('prints    : %d' % len(ev['prints']))
    print('setPixel  : %d   px_copy_to_bitmap: %d' % (ev['setpixel'], ev['pxcopy']))
    print('distinct TCBs scheduled: %d' % len(ev['switch']))
    print('uart out  : %r' % bytes(ev['uart_out'])[:200])
    w,h,buf = struct.unpack('>III', m.uc.mem_read(0x4028ae98, 12))
    px = bytes(m.uc.mem_read(buf, w*h))
    print('intro framebuffer 0x%08x nonzero: %d/%d' % (buf, sum(1 for b in px if b), w*h))
