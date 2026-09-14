"""Trace the firmware's UI event path: the UI queue, key dispatch to views,
and view activate/close.

Installed by `tools/guirun.py --trace-ui`. Every line starts
`[ui] <instrs> t=<count>`: instrs comes from the host's clock, t from the
firmware counter at `ui_tick_counter`. That counter is advanced by the
key-repeat code (`ui_tick_inc`), not by DTIM3: one run measured about 1.8
counts per DTIM3 tick, and the first key repeat came 24 counts after the
press. Waits are given in the same counts.

Firmware facts this relies on (Digitakt II OS 1.15C, checked by
disassembly; addresses are resolved in emu/symbols.py):

- `queue_send(queue*, item*)` stores the item POINTER in a ring. Queue
  object: +0x04 count, +0x10 mask, +0x14 storage, +0x18 write index,
  +0x1c read index. Records are 16 bytes: byte +0 type, long +4 code,
  long +8 flags, long +0xc timestamp. Type 5 is the DTIM3 tick, type 0 a
  key event.
- The main loop pops the UI queue at `mainloop`; D0 holds the item at
  `mainloop + 0xc` (those bytes are part of the `mainloop` signature).
- `ui_key_dispatch` is the call that hands a type-0 item to the view
  controller; A2 holds the item. The walk that offers it to views runs
  later in the same main-loop pass, so a key dispatch is taken to end
  when the loop comes back to `mainloop`.
- `view_offer` is the `jsr (a0)` that offers an event to one view. D3
  holds the view across the call; at `view_offer + 2`, D0 is nonzero if
  the view consumed the event. The same loop serves other event kinds, so
  offers outside a key dispatch are only counted unless verbose.
- `view_activate(this, controller)`, `view_close(this)`,
  `view_request_pop(controller)` and `view_sweep(controller)` take their
  arguments on the stack. At `view_closed_mark`, A2 is the view and the
  close guard has passed.
- Views are polymorphic, so a class name is read through the Itanium RTTI
  layout: name = cstr(*(*(vptr - 4) + 4)).

Queue latency matches pops to sends in FIFO order by item pointer. Items
already queued when the trace is installed are reported as `waited=?`.
"""
import collections
import struct

from unicorn.m68k_const import (UC_M68K_REG_A2, UC_M68K_REG_A7,
                                UC_M68K_REG_D0, UC_M68K_REG_D3)

TICK_TYPE = 5
KEY_TYPE = 0
RECORD_LEN = 16
PENDING_MAX = 4096

FLAG_BITS = ((0x01, 'press'), (0x02, 'chord'), (0x08, 'repeat'),
             (0x10, 'release'))

HOOKS = ('queue_send', 'mainloop', 'ui_queue', 'ui_key_dispatch',
         'view_offer', 'view_activate', 'view_close', 'view_closed_mark',
         'view_request_pop', 'view_sweep')


def describe_flags(flags):
    """0x0b -> 'press|chord|repeat'. Unknown bits are appended as +0x.."""
    names = [name for bit, name in FLAG_BITS if flags & bit]
    rest = flags & ~sum(bit for bit, _ in FLAG_BITS)
    if rest:
        names.append('+0x%x' % rest)
    return '|'.join(names) or '-'


def itanium_name(mangled):
    """'20MachineSelectionView' -> 'MachineSelectionView'. Anything that is
    not a plain length-prefixed name is returned unchanged."""
    digits = len(mangled) - len(mangled.lstrip('0123456789'))
    if digits == 0:
        return mangled
    rest = mangled[digits:]
    return rest if len(rest) == int(mangled[:digits]) else mangled


def describe_item(record, button_name=None):
    """Text for a 16-byte queue record."""
    if record is None:
        return 'unreadable'
    if record[0] != KEY_TYPE:
        return 'type=%d %s' % (record[0], record.hex())
    code, flags, stamp = struct.unpack('>III', record[4:16])
    label = (button_name(code) if button_name else None) or 'code'
    return '%s(%d) 0x%02x %s ts=0x%x' % (label, code, flags,
                                         describe_flags(flags), stamp)


class UiTrace:
    """Hooks the UI path and prints one line per event.

    `at(addr, fn)` installs a code hook, `clock()` returns the host's
    instruction count, `out(line)` prints. If any symbol in HOOKS is
    unresolved nothing is installed and `missing` lists them.
    """

    def __init__(self, m, at, profile, clock, out=print, verbose=False,
                 button_name=None):
        self.uc = m.uc
        self.clock = clock
        self.out = out
        self.verbose = verbose
        self.button_name = button_name
        self.queue = profile.ui_queue
        self.tick_counter = profile.ui_tick_counter
        self.pending = collections.deque()   # (instrs, tick, item, record)
        self.key = None                      # key dispatch in progress
        self.names = {}                      # vptr -> class name
        self.errors = 0
        self._reset_window()
        self.missing = [name for name in HOOKS
                        if getattr(profile, name) is None]
        if self.missing:
            return
        for addr, fn in (
                (profile.queue_send, self._on_send),
                (profile.mainloop + 0xc, self._on_pop),
                (profile.ui_key_dispatch, self._on_key),
                (profile.mainloop, self._on_key_done),
                (profile.view_offer, self._on_offer),
                (profile.view_offer + 2, self._on_offered),
                (profile.view_activate, self._on_activate),
                (profile.view_close, self._on_close),
                (profile.view_closed_mark, self._on_closed),
                (profile.view_request_pop, self._on_request_pop),
                (profile.view_sweep, self._on_sweep)):
            at(addr, self._guard(addr, fn))

    def _guard(self, addr, fn):
        def hook(uc, address, size, user_data):
            try:
                fn()
            except Exception as exc:   # raising here would stop emulation
                self.errors += 1
                if self.errors <= 5:
                    self.out('[ui] hook error at 0x%08x: %r' % (addr, exc))
        return hook

    # -- guest reads (never SR) ------------------------------------------

    def _u32(self, addr):
        return struct.unpack('>I', bytes(self.uc.mem_read(addr, 4)))[0]

    def _stack(self, n):
        """Longword n above A7: at a function entry 0 is the return address
        and 1 the first argument."""
        return self._u32(self.uc.reg_read(UC_M68K_REG_A7) + 4 * n)

    def _record(self, item):
        try:
            return bytes(self.uc.mem_read(item, RECORD_LEN))
        except Exception:   # a bad pointer faults
            return None

    def _tick(self):
        if self.tick_counter is None:
            return None
        return self._u32(self.tick_counter)

    def _name(self, obj):
        try:
            vptr = self._u32(obj)
            name = self.names.get(vptr)
            if name is None:
                typeinfo = self._u32(vptr - 4)
                raw = bytes(self.uc.mem_read(self._u32(typeinfo + 4), 96))
                name = itanium_name(raw.split(b'\0', 1)[0].decode('ascii'))
                self.names[vptr] = name
        except Exception:   # not a polymorphic object, or a bad pointer
            name = '?'
        return '%s@0x%08x' % (name, obj)

    def _describe(self, record):
        return describe_item(record, self.button_name)

    def _line(self, text):
        tick = self._tick()
        self.out('[ui] %d t=%s %s' % (self.clock(),
                                       '?' if tick is None else tick, text))

    # -- UI queue --------------------------------------------------------

    def _on_send(self):
        queue, item = self._stack(1), self._stack(2)
        if queue != self.queue:
            return
        record = self._record(item)
        depth = self._u32(queue + 4) + 1   # queue_send increments it later
        self.pending.append((self.clock(), self._tick(), item, record))
        if len(self.pending) > PENDING_MAX:
            self.pending.popleft()
            self.resyncs += 1
        self.sent += 1
        self.max_depth = max(self.max_depth, depth)
        if record is not None and record[0] == TICK_TYPE:
            self.sent_dtim3 += 1
            if not self.verbose:
                return
        self._line('q+ depth=%d item=0x%08x %s'
                   % (depth, item, self._describe(record)))

    def _match(self, item):
        """Pop the pending send for `item`; older unmatched entries are
        dropped and counted as resyncs."""
        for i, entry in enumerate(self.pending):
            if entry[2] == item:
                for _ in range(i):
                    self.pending.popleft()
                    self.resyncs += 1
                return self.pending.popleft()
        return None

    def _on_pop(self):
        item = self.uc.reg_read(UC_M68K_REG_D0)
        depth = self._u32(self.queue + 4)
        record = self._record(item)
        now, tick = self.clock(), self._tick()
        sent = self._match(item)
        self.popped += 1
        if sent is None:
            wait = 'waited=?'
        else:
            sent_at, sent_tick, _, sent_record = sent
            ticks = (None if tick is None or sent_tick is None
                     else tick - sent_tick)
            wait = 'waited=%d (%s t)' % (now - sent_at,
                                         '?' if ticks is None else ticks)
            if self.max_wait is None or now - sent_at > self.max_wait[0]:
                self.max_wait = (now - sent_at, ticks,
                                 -1 if record is None else record[0])
            if sent_record is not None and record != sent_record:
                wait += ' record-changed was=%s' % sent_record.hex()
        if record is not None and record[0] == TICK_TYPE and not self.verbose:
            return
        self._line('q- depth=%d item=0x%08x %s %s'
                   % (depth, item, wait, self._describe(record)))

    # -- key dispatch to views -------------------------------------------

    def _on_key(self):
        item = self.uc.reg_read(UC_M68K_REG_A2)
        self.key = {'record': self._record(item), 'offers': 0,
                    'consumer': None}

    def _on_key_done(self):
        key, self.key = self.key, None
        if key is None:
            return
        self._line('key-done %s offered=%d consumed-by=%s'
                   % (self._describe(key['record']), key['offers'],
                      key['consumer'] or 'none'))

    def _on_offer(self):
        view = self.uc.reg_read(UC_M68K_REG_D3)
        if self.key is None:
            self.other_offers += 1
            if self.verbose:
                self._line('offer(other) %s' % self._name(view))
            return
        self.key['offers'] += 1
        self._line('offer> %s' % self._name(view))

    def _on_offered(self):
        if self.key is None:
            return
        name = self._name(self.uc.reg_read(UC_M68K_REG_D3))
        consumed = self.uc.reg_read(UC_M68K_REG_D0) & 0xff
        if consumed and self.key['consumer'] is None:
            self.key['consumer'] = name
        self._line('offer< %s %s' % (name,
                                     'consumed' if consumed else 'passed'))

    # -- view lifecycle --------------------------------------------------

    def _on_activate(self):
        self._line('activate %s ctl=%s' % (self._name(self._stack(1)),
                                           self._name(self._stack(2))))

    def _on_close(self):
        self._line('close-call %s ret=0x%08x' % (self._name(self._stack(1)),
                                                 self._stack(0)))

    def _on_closed(self):
        self._line('closed %s' % self._name(self.uc.reg_read(UC_M68K_REG_A2)))

    def _on_request_pop(self):
        self._line('pop-request ctl=%s ret=0x%08x'
                   % (self._name(self._stack(1)), self._stack(0)))

    def _on_sweep(self):
        self._line('sweep ctl=%s' % self._name(self._stack(1)))

    # -- windowed summary ------------------------------------------------

    def _reset_window(self):
        self.sent = 0
        self.sent_dtim3 = 0
        self.popped = 0
        self.max_depth = 0
        self.max_wait = None   # (instrs, t counts, record type)
        self.other_offers = 0
        self.resyncs = 0

    def summary(self):
        """One line covering the window since the last call; resets it."""
        if self.missing:
            return ('[ui] disabled: unresolved symbols %s'
                    % ', '.join(self.missing))
        if self.max_wait is None:
            wait = '-'
        else:
            instrs, ticks, kind = self.max_wait
            wait = '%d (%s t, type %d)' % (
                instrs, '?' if ticks is None else ticks, kind)
        line = ('[ui] window sent=%d (dtim3 %d) popped=%d depth=%d '
                'tracked=%d max-depth=%d max-wait=%s other-offers=%d '
                'resyncs=%d errors=%d'
                % (self.sent, self.sent_dtim3, self.popped,
                   self._u32(self.queue + 4), len(self.pending),
                   self.max_depth, wait, self.other_offers, self.resyncs,
                   self.errors))
        self._reset_window()
        return line
