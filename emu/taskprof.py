"""Charge emulated CPU time to RTOS tasks, and sample where each task was
when it lost the CPU.

`ctx_switch` (0x40000410) is the only code that changes the current-TCB
variable once the scheduler runs; the other writer (0x40184d96) runs once
at scheduler init. At `ctx_switch_load` (`move.l a0,current_tcb`) the
variable still holds the outgoing task and A0 holds the incoming one. The
instructions since the previous switch are charged to the outgoing task,
including any interrupt handlers that ran in between. Time before the first
switch seen is not charged.

The switcher is entered through an exception and does not move A7 before
`ctx_switch_load`, so the outgoing task's exception frame is at A7:
[A7] format/vector/SR, [A7+4] the PC it resumes at (the layout emu/tasks.py
reads for parked tasks). A task preempted by the time slice shows where it
was busy; a task that blocked shows the pend it called. Above the frame,
longwords that fall in the MAIN OS code span are kept as a rough call chain
(stale stack words can appear in it too).

Installed by `tools/guirun.py --trace-tasks`, which prints `summary()` with
each progress line.
"""
import collections
import struct

from unicorn.m68k_const import UC_M68K_REG_A0, UC_M68K_REG_A7

PC_SHARE = 5.0   # resume PCs are listed for tasks with at least this share
PC_TOP = 6
CODE_LO, CODE_HI = 0x40000400, 0x40307f60   # MAIN OS code, as guirun scans
STACK_WORDS = 64
CHAIN_TOP = 8


class TaskProfile:
    """`clock()` gives the live instruction count inside a hook; `tasks` is
    the live `ev['tasks']` list of (entry, prio, tcb); `spins` is the live
    `ev['idle_spins']` dict or None."""

    def __init__(self, m, at, profile, clock, tasks, spins=None, out=print):
        self.uc = m.uc
        self.clock = clock
        self.tasks = tasks
        self.spins = spins
        self.out = out
        self.current_tcb = profile.current_tcb
        self.last = None      # clock at the previous switch
        self.current = None   # task switched in at the previous switch
        self.parked = {}      # tcb -> (clock, resume pc, call chain) at last switch-out
        self.mismatches = 0
        self.errors = 0
        self.spins_seen = spins['n'] if spins is not None else 0
        self._reset_window()
        self.missing = [name for name in ('ctx_switch_load', 'current_tcb')
                        if getattr(profile, name) is None]
        if not self.missing:
            at(profile.ctx_switch_load, self._hook)

    def _hook(self, uc, address, size, user_data):
        try:
            self._on_switch()
        except Exception as exc:   # raising here would stop emulation
            self.errors += 1
            if self.errors <= 5:
                self.out('[tasks] hook error: %r' % (exc,))

    def _u32(self, addr):
        return struct.unpack('>I', bytes(self.uc.mem_read(addr, 4)))[0]

    def _chain(self, sp):
        """Code-span longwords above the exception frame, nearest first."""
        try:
            raw = bytes(self.uc.mem_read(sp, 4 * STACK_WORDS))
        except Exception:   # the stack can end near unmapped memory
            return []
        words = struct.unpack('>%dI' % STACK_WORDS, raw)
        return [w for w in words if CODE_LO <= w <= CODE_HI][:CHAIN_TOP]

    def _on_switch(self):
        now = self.clock()
        outgoing = self._u32(self.current_tcb)
        incoming = self.uc.reg_read(UC_M68K_REG_A0)
        a7 = self.uc.reg_read(UC_M68K_REG_A7)
        resume = self._u32(a7 + 4)
        if self.last is not None:
            self.time[outgoing] += now - self.last
            if outgoing != self.current:
                self.mismatches += 1
        self.pcs[outgoing][resume] += 1
        self.parked[outgoing] = (now, resume, self._chain(a7 + 8))
        self.switched_in[incoming] += 1
        self.last, self.current = now, incoming

    def _label(self, tcb):
        for entry, prio, task_tcb in self.tasks:
            if task_tcb == tcb:
                return 'entry=0x%08x prio=%d tcb=0x%08x' % (entry, prio, tcb)
        return 'tcb=0x%08x' % tcb

    def _reset_window(self):
        self.time = collections.Counter()
        self.switched_in = collections.Counter()
        self.pcs = collections.defaultdict(collections.Counter)

    def summary(self, now):
        """Lines for the window since the last call. The running task is
        charged up to `now`, the host's instruction count between chunks.
        Every task not running now gets a `last-out` line: where it was at
        its most recent switch-out. Resets the window."""
        if self.missing:
            return ['[tasks] disabled: unresolved symbols %s'
                    % ', '.join(self.missing)]
        if self.last is not None and self.current is not None:
            self.time[self.current] += now - self.last
            self.last = now
        total = sum(self.time.values())
        head = ('[tasks] window charged=%d switches=%d mismatches=%d '
                'errors=%d' % (total, sum(self.switched_in.values()),
                               self.mismatches, self.errors))
        if self.spins is not None:
            head += ' idle-spins=%d' % (self.spins['n'] - self.spins_seen)
            self.spins_seen = self.spins['n']
        lines = [head]
        for tcb, spent in self.time.most_common():
            share = 100.0 * spent / total if total else 0.0
            lines.append('[tasks]   %5.1f%% %10d in=%-5d %s' % (
                share, spent, self.switched_in[tcb], self._label(tcb)))
            if share >= PC_SHARE and self.pcs[tcb]:
                lines.append('[tasks]          pcs %s' % ' '.join(
                    '0x%08x*%d' % item
                    for item in self.pcs[tcb].most_common(PC_TOP)))
        for tcb in sorted(self.parked):
            if tcb == self.current:
                continue
            at, pc, chain = self.parked[tcb]
            lines.append('[tasks]   last-out %s at %d pc=0x%08x via %s' % (
                self._label(tcb), at, pc,
                ' '.join('0x%08x' % w for w in chain) or '-'))
        self._reset_window()
        return lines
