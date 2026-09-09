"""
Extended boot harness: builds on mockboot3.py's approach (on-demand paging, m68k
exception dispatch via the vector table, RTE handling, periodic timer injection),
adding:
  - FF1.L Dn software emulation (Unicorn 2.1.4 / Capstone 5 don't decode ColdFire's
    FF1 opcode 0x04C0-0x04C7; real HW executes it fine -> vector 4 in emulation only)
  - MOVEC software emulation, executed PROACTIVELY (before Unicorn's native decoder
    sees the instruction) because at least one control-register selector used by
    this firmware (Rc=0x009) crashes Unicorn's m68k core natively (SIGABRT, not a
    catchable UcError/exception) rather than raising a clean illegal-instruction trap.
  - optional UART8 (USR8/UTB8 @ 0xEC070004/0xEC07000C) "always ready" mock.
  - stall detection: records addresses that keep recurring long after the last
    newly-discovered address, to locate the tail loop precisely.
"""

# pyright: reportMissingImports=false, reportUndefinedVariable=false
# fmt: off
import collections
import struct
import sys

from unicorn import *
from unicorn.m68k_const import *

from emu import config
from emu.unicorn_compat import require_compatible_unicorn

LOAD,ENTRY,VBR=0x40000400,0x400004e8,0x40000000
PAGE=0x100000; HALT=0x400ceeb6; EXCP_RTE=0x100
TASK_ENTRY=0x400cef6c

DREGS=[UC_M68K_REG_D0,UC_M68K_REG_D1,UC_M68K_REG_D2,UC_M68K_REG_D3,UC_M68K_REG_D4,UC_M68K_REG_D5,UC_M68K_REG_D6,UC_M68K_REG_D7]
AREGS=[UC_M68K_REG_A0,UC_M68K_REG_A1,UC_M68K_REG_A2,UC_M68K_REG_A3,UC_M68K_REG_A4,UC_M68K_REG_A5,UC_M68K_REG_A6,UC_M68K_REG_A7]
UART8_USR=0xEC070004   # USR8 - UART8 status register (MCF54418RM Table 41-6)
UART8_DAT=0xEC07000C   # URB8/UTB8 - UART8 rx/tx data register

def ff1(val):
    if val==0: return 32
    for i in range(31,-1,-1):
        if val & (1<<i): return 31-i
    return 32

DSPI0_SR=0xFC05C02C   # DSPI0 status register (MCF54418RM Table 40-3 / Ch.40)

def boot(tick_vec=32, tick_every=20000, limit=200_000_000, mock_uart8=False, mock_dspi0=False,
         verbose_illegal=False, stall_window=2_000_000, extra_probe=None):
    require_compatible_unicorn()
    uc=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN); uc.ctl_set_cpu_model(UC_CPU_M68K_CFV4E)
    try:
        IMG=open(config.main_image(),'rb').read()
    except OSError as exc:
        raise RuntimeError('cannot read MAIN OS image') from exc
    mapped=set()
    def ensure(a):
        b=a&~(PAGE-1)
        if b in mapped: return
        try: uc.mem_map(b,PAGE); mapped.add(b)
        except UcError: pass
    for a in (0,0x40000000,0x80000000,0xFC000000,0xEC000000): ensure(a)
    for o in range(0,len(IMG),PAGE): ensure(LOAD+o)
    uc.mem_write(LOAD,IMG); uc.reg_write(UC_M68K_REG_A7,0x40800000); uc.reg_write(UC_M68K_REG_SR,0x2700)
    st={'n':0,'spin':0,'seen':set(),'task_hit':None,'ff1_count':0,'movec_count':0,
        'illegal_unhandled':collections.Counter(),'curve':[],'last_new_n':0,
        'stall_pcs':collections.Counter(),'ctrlregs':{}}
    def raise_vec(u,vec):
        h=struct.unpack('>I',u.mem_read(VBR+vec*4,4))[0]
        if h==0 or h>=0x48000000: return False
        pc=u.reg_read(UC_M68K_REG_PC); sr=u.reg_read(UC_M68K_REG_SR)
        sp=u.reg_read(UC_M68K_REG_A7)-8
        u.mem_write(sp,struct.pack('>HHI',(vec<<2)&0xFFFF,sr,pc))
        u.reg_write(UC_M68K_REG_A7,sp); u.reg_write(UC_M68K_REG_PC,h); return True
    def _code(u,a,sz,d):
        st['n']+=1
        if a not in st['seen']:
            st['seen'].add(a); st['last_new_n']=st['n']
            if a==TASK_ENTRY and st['task_hit'] is None: st['task_hit']=st['n']
        elif st['n']-st['last_new_n'] > stall_window:
            st['stall_pcs'][a]+=1
        if st['n'] % 5_000_000 == 0: st['curve'].append((st['n']//1_000_000,len(st['seen'])))
        if a==HALT:
            st['spin']+=1
            if st['spin']==1:
                if mock_uart8: u.mem_write(UART8_USR, bytes([0x05]))  # TXRDY|RXRDY always set
                if mock_dspi0: u.mem_write(DSPI0_SR, struct.pack('>I',0x000000F0))  # RXCTR=0xF
            if st['spin']%tick_every==0: raise_vec(u,tick_vec)
        # --- proactive MOVEC interception (avoids native Unicorn abort) ---
        w=struct.unpack('>H',u.mem_read(a,2))[0]
        if w in (0x4E7A,0x4E7B):
            ext=struct.unpack('>H',u.mem_read(a+2,2))[0]
            rc=ext & 0xFFF; rn=(ext>>12)&7; is_a=(ext>>15)&1
            reg=(AREGS if is_a else DREGS)[rn]
            if w==0x4E7B:   # Rn -> Rc
                st['ctrlregs'][rc]=u.reg_read(reg)
            else:           # Rc -> Rn
                u.reg_write(reg, st['ctrlregs'].get(rc,0))
            u.reg_write(UC_M68K_REG_PC, a+4)
            st['movec_count']+=1
            return
        if extra_probe: extra_probe(u,a,st)
    uc.hook_add(UC_HOOK_CODE,_code)
    uc.hook_add(UC_HOOK_MEM_INVALID, lambda u,t,a,s,v,d:(ensure(a),True)[1])
    def on_intr(u,vec,d):
        if vec==EXCP_RTE:
            sp=u.reg_read(UC_M68K_REG_A7); _f,sr,pc=struct.unpack('>HHI',u.mem_read(sp,8))
            u.reg_write(UC_M68K_REG_SR,sr); u.reg_write(UC_M68K_REG_PC,pc); u.reg_write(UC_M68K_REG_A7,sp+8); return
        if vec==4:
            pc=u.reg_read(UC_M68K_REG_PC)
            w=struct.unpack('>H',u.mem_read(pc,2))[0]
            if (w & 0xFFF8)==0x04C0:
                rn=w & 7
                val=u.reg_read(DREGS[rn]); res=ff1(val)
                u.reg_write(DREGS[rn],res)
                sr=u.reg_read(UC_M68K_REG_SR); sr &= ~0x0F
                if res==0: sr|=0x04
                u.reg_write(UC_M68K_REG_SR,sr)
                u.reg_write(UC_M68K_REG_PC,pc+2)
                st['ff1_count']+=1
                return
            st['illegal_unhandled'][pc]+=1
            if verbose_illegal:
                print('   [illegal, unhandled] n=%d pc=0x%08x word=0x%04x'%(st['n'],pc,w))
        if not raise_vec(u,vec): u.emu_stop()
    uc.hook_add(UC_HOOK_INTR,on_intr)
    try: uc.emu_start(ENTRY,0,count=limit); stop='limit'
    except UcError as e: stop=str(e)
    return st,stop,uc.reg_read(UC_M68K_REG_PC)

if __name__=='__main__':
    try:
        limit=int(sys.argv[1]) if len(sys.argv)>1 else 60_000_000
    except ValueError as exc:
        raise SystemExit('instruction limit must be an integer') from exc
    mock=sys.argv[2]=='1' if len(sys.argv)>2 else False
    mock2=sys.argv[3]=='1' if len(sys.argv)>3 else False
    st,stop,pc=boot(32, limit=limit, mock_uart8=mock, mock_dspi0=mock2, verbose_illegal=True)
    print('mock_uart8=%s mock_dspi0=%s: %d instrs, %d distinct addrs, stop=%s pc=0x%08x'%(mock,mock2,st['n'],len(st['seen']),stop[:30],pc))
    print('task_hit=%s ff1_count=%d movec_count=%d'%(st['task_hit'],st['ff1_count'],st['movec_count']))
    print('curve:', '  '.join('%dM:%d'%(m,c) for m,c in st['curve']))
    print('unhandled illegal:', st['illegal_unhandled'].most_common(10))
    print('stall pcs:', [(hex(a),c) for a,c in st['stall_pcs'].most_common(15)])
