"""Boot the thing and watch the panel.

A live view of the Digitakt II's 128x64 OLED, driven by the real firmware
running under Unicorn. The emulator runs on a worker thread and writes into a
shared framebuffer whenever the firmware calls Bitmap::setPixel; the UI thread
just samples that framebuffer on a timer. Nothing here reimplements the raster
-- every lit pixel is one setPixel call the firmware actually made.

There are TWO screens and this window has to switch between them, because the
intro and the main OS draw by different routes. Measured, over the same build:

    boot400M.snap, intro running    setPixel 616,823   panel buffer     17 lit
    postintro.snap, OS running      setPixel       0   panel buffer  2,373 lit

The intro draws through `Bitmap::setPixel`, so `on_pixel` is the right source
for it. The main OS composes straight into the firmware's own framebuffer and
never calls the intercepted primitive, so after the handover the source has to
become `emu.panel.read`. Showing setPixel throughout is what made this window
sit on the intro's last frame forever while a complete user interface was
rendering in RAM -- see HANDOVER warning 6. The switch happens at INTRO_DONE,
the same point the timers are released.

    uv run python -m emu.gui [snapshot]

tkinter only, no third-party GUI dependency. Note Homebrew's python@3.14 does
not ship tkinter; uv's managed CPython does, which is why pyproject pins 3.12.
"""
import os
import queue
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn import UcError
from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_SR
from emu.longrun import build, spin
from emu.dtim import Dtims, Timers
from emu import config, device as devices, panel, panelin, symbols
from emu.pit import Pits, intro_running
from emu.screen import png

# The intro's frame rate is not a guess. PIT3 is configured at 0x400d3a7a with
# PCSR=0x0936 (prescaler 2^10) and PMR=0x2191, so one frame is (8593+1)*1024 =
# 8,800,256 bus cycles; its ISR (vector 208, 0x400d2d70 on Digitakt -- resolved
# per build as profile.intro_pit3_isr) posts the semaphore the draw loop waits
# on at 0x400d4036 (also Digitakt-specific). The bus clock is 132 MHz, taken
# from the UART baud divider at 0x400024a4 (132000000 / (32*baud)) -- which
# checks out because it also makes the RTOS tick exactly 50.000 Hz and PIT2
# 60.0 Hz.
FRAME_VECTOR = 208
FRAME_HZ = 132_000_000 / ((0x2191 + 1) * 1024)     # 14.9996

W, H = 128, 64

# Vertical space the window owes to everything that is not the panel: the
# toolbar, three status lines, and the control surface, which is several rows
# of buttons deep. Without this the auto-zoom happily fills the screen with a
# 128x64 framebuffer and clips the controls off the bottom.
RESERVE_H = 520
MAX_SCALE = 6

# Panel palette: an OLED is emissive, so the lit pixel is the bright thing and
# the ground is genuinely black rather than dark grey.
OFF = b'\x0c\x0e\x12'
ON = b'\xe8\xf6\xff'
# The worker runs under spin(pits=...), which steps to each PIT deadline and
# so delivers the OS heartbeat: the RTOS time slice (PIT0), the software timer
# wheel (PIT2) and the display frame timer (PIT3). Without it the GUI ran the
# firmware with no interrupts at all, which is why it showed none of the
# post-intro progress the harness could already reach -- the display task sat
# blocked on a semaphore only PIT3's handler ever posts.
#
# It costs about 1.8x: deadline stepping needs `count=` on emu_start, and that
# makes Unicorn install an internal per-instruction hook (see longrun.spin).
# The cost is in `count` itself and not in how often emu_start is called, so
# there is nothing to win by making BUDGET bigger than responsiveness wants.
BUDGET = 400_000          # instructions per pass, ~0.16s: pause/stop latency,
                          # and how long a panel click waits to be delivered.
                          # The cost is in emu_start's `count` rather than in
                          # how often it is called, so a smaller pass buys
                          # responsiveness almost for free.


class Emulator(threading.Thread):
    """Runs the firmware and publishes a framebuffer. Owns no widgets."""

    daemon = True

    def __init__(self, snapshot, weakptr=False, slc=False, syx=None):
        super().__init__()
        self.snapshot = snapshot
        self.weakptr = weakptr
        self.slc = slc
        self.syx = syx
        self.fb = bytearray(W * H)
        self.pause = threading.Event()
        self.stop_flag = threading.Event()
        self.ready = threading.Event()
        self.stats = {'frames': 0, 'px': 0,
                      'pc': 0, 'tcb': 0, 'tasks': 0, 'prints': 0, 'fps': 0.0,
                      'bmp': 0, 'instrs': 0, 'pit': (0, 0, 0),
                      'status': 'loading snapshot', 'mainloop': 0, 'jobs': 0,
                      'dtim3': 0, 'terminal': False, 'panel_lit': 0,
                      'source': 'setPixel'}
        self._uc = None             # set once the machine is built
        self.error = None
        self._seen = set()
        self.version = 0            # bumped on every pixel, so the UI can
        self._frame_t = time.time()  # skip redrawing an unchanged panel
        self.captured = []          # completed frames, for correct-speed replay
        self.use_panel = False      # False: setPixel (intro). True: the
                                    # firmware's own framebuffer (main OS).
        self._last_panel = None     # last panel buffer drawn, to skip repeats
        self._panel_live = False    # seen the OS draw into it at least once
        self._panel_latch = None    # newest untorn frame, grabbed at diff entry
        self.fb_front = None        # resolved once the image is known -- see run()
        self.profile = None         # the whole symbol profile, same point
        # Panel input. The UI thread must never touch guest memory: the
        # worker sits inside emu_start for a whole BUDGET at a time. So
        # clicks arrive on this queue and are applied between chunks, the
        # same safe point pause already uses.
        self.inbox = queue.Queue()
        self.device = None          # which product, identified by firmware hash
        self.held = None            # panelin.Held, once the device is known
        self.button_names = {}      # control code -> the firmware's own name
        self.encoder_names = {}
        self.device_error = None    # why there is no control surface, if so

    def _identify_device(self, m, profile):
        """Work out which product this is and read its control names.

        Degrades rather than fails: an unrecognised firmware means no control
        surface, not a dead emulator. The names are read out of the image, so
        they are this firmware's own rather than a table that can go stale.
        """
        try:
            self.device, _fw = devices.identify(config.firmware(self.syx))
            self.held = panelin.Held(self.device)
            self.button_names = panelin.control_names(m, profile, 'button')
            self.encoder_names = panelin.control_names(m, profile, 'encoder')
        except Exception as exc:                       # noqa: BLE001
            self.device_error = '%s: %s' % (type(exc).__name__, exc)

    def _drain_input(self, m, profile, pc):
        """Apply queued panel input at a chunk boundary. -> the new PC.

        Everything queued is encoded into ONE byte stream and delivered with
        a single feed, because the firmware's ISR drains the whole receive
        ring: one raised vector covers every message in it. Raising once per
        event would nest exception frames for input the ring already holds.

        Returns the PC because delivering input raises a vector, which moves
        it. Dropping the result would strand the run at the old address.
        """
        if self.held is None:
            return pc
        out = bytearray()
        while True:
            try:
                kind, code, arg = self.inbox.get_nowait()
            except queue.Empty:
                break
            if kind in ('press', 'release'):
                pos = (self.held.press(code) if kind == 'press'
                       else self.held.release(code))
                if pos is not None:
                    out += panelin.encode_buttons(*pos)
            elif kind == 'encoder':
                channel = self.device.encoder_channel(code)
                if channel is not None:
                    out += panelin.encode_encoder(channel, arg)
            elif kind == 'release_all':
                for pos in self.held.release_all():
                    out += panelin.encode_buttons(*pos)
        if not out:
            return pc
        try:
            return panelin.feed(m, profile, bytes(out))
        except Exception as exc:                       # noqa: BLE001
            self.stats['status'] = 'panel input failed: %s' % exc
            return pc

    def run(self):
        def on_pixel(x, y, val, bmp):
            self.stats['bmp'] = bmp
            if (x, y) in self._seen and len(self._seen) > W * H // 2:
                now = time.time()
                self.captured.append(bytes(self.fb))    # snapshot the finished frame
                self.stats['frames'] += 1              # coordinate repeat = new frame
                self.stats['fps'] = 1.0 / max(1e-6, now - self._frame_t)
                self._frame_t = now
                self._seen.clear()
                # Deliberately no emu_stop here any more. Under spin() a hook
                # that stops the run early makes the instruction accounting a
                # lie -- emu_start returns having executed fewer than it was
                # asked for, the loop credits itself the full step, and every
                # timer deadline drifts away from the instructions actually
                # executed. The worker regains control every BUDGET
                # instructions instead, which is soon enough for pause and
                # stop to feel immediate.
            self._seen.add((x, y))
            self.fb[y * W + x] = val
            self.stats['px'] += 1
            self.version += 1

        try:
            # NOTE: unblock=True also satisfies the frame semaphore, so the
            # animation runs unpaced -- as fast as the host manages, not at
            # FRAME_HZ. Excluding FRAME_SEM and driving vector 208 instead was
            # tried and does not work on its own: with every other wait
            # satisfied, the prio-6 task never yields, so the scheduler never
            # reschedules and the woken draw task never runs (the semaphore
            # count just climbs). Faithful pacing needs cycle accounting so
            # the RTOS tick can preempt too. Until then the status line
            # reports the shortfall against the real 15 fps rather than
            # pretending.
            # dsp=True backs the 0x8C000000 coprocessor port's ready line.
            # Without it the priority-3 job worker wedges in the ready-bit
            # spin at 0x400cf4ec on its very first transfer and none of the
            # five jobs queued at boot ever runs. See emu/dsp.py.
            extra = {'syx': self.syx} if self.syx else {}
            # sdgate/esdhc are not passed here -- build()'s own defaults
            # (True) supply the SD storage models, so they come along with
            # every call site that does not explicitly override them.
            m, ev, st, pc, inq, at = build(self.snapshot, unblock=True,
                                           softfloat=True, bitmap=True,
                                           dsp=True, on_pixel=on_pixel,
                                           weakptr=self.weakptr, slc=self.slc,
                                           **extra)
            # build() already resolved (and required) this same profile
            # internally -- see emu/symbols.py -- so re-resolving here is a
            # cache hit, not a rescan. fb_front is OPTIONAL: if it did not
            # resolve for this image, _publish_panel below just never has
            # anything to read, which is the documented degrade-gracefully
            # behaviour rather than a crash.
            main_img = open(config.main_image(), 'rb').read()
            profile = symbols.resolve(main_img)
            self.fb_front = profile.fb_front
            self.profile = profile
            self._identify_device(m, profile)
        except Exception as exc:                       # noqa: BLE001
            self.error = '%s: %s' % (type(exc).__name__, exc)
            self.stats['status'] = 'failed to load'
            print('[gui] FAILED TO LOAD: %s' % self.error, flush=True)
            self.ready.set()
            return

        self._uc = m.uc
        self._reported = 0
        # PIT0 time slice, PIT2 wheel, PIT3 display -- but not until the intro
        # has handed over. Delivering into a running intro stops it ever
        # ending (PIT3 double-posts the frame semaphore that unblock is
        # already satisfying) and stops the OS tasks spawning (PIT2). See
        # emu.pit.Pits.
        # ...and DMA timer 3, which is the 30.05 Hz tick whose ISR
        # (0x400c30e4) is the only thing at boot that sends a message to
        # 0x4094ef3c, the queue the main application task blocks on. Without
        # it that task makes exactly one pass through its message loop and
        # waits forever, which is what this window used to show. See
        # emu/dtim.py.
        intro = intro_running(m, profile.intro_pit3_isr)
        pits = Timers(Pits(m, hold=intro),
                      Dtims(m, channels=(3,), hold=intro))
        # `pits.held` is exactly "the intro is still running", so a snapshot
        # taken after it already belongs to the OS and the panel buffer is the
        # screen from the first frame.
        self.use_panel = not pits.held
        if pits.held:
            def handover(uc, a, s_, d):
                pits.release()
                self.use_panel = True
            if profile.intro_done is not None:
                at(profile.intro_done, handover)
            else:
                print('[gui] WARNING: intro_done did not resolve for this '
                      'image; timers will stay held and the intro will '
                      'never hand over', flush=True)

        # Progress markers, so the status line can say what the firmware is
        # actually doing rather than only how many pixels it drew. Resolved
        # per build now (profile.mainloop / profile.job_pump); they say
        # whether the OS actually took over after the intro: mainloop is the
        # main application task's message-loop head, jobs is the job-worker
        # pump.
        mark = self.stats
        if profile.mainloop is not None:
            at(profile.mainloop, lambda uc, a, s, d: mark.__setitem__(
                'mainloop', mark['mainloop'] + 1))
        if profile.job_pump is not None:
            at(profile.job_pump, lambda uc, a, s, d: mark.__setitem__(
                'jobs', mark['jobs'] + 1))
        # 0x4012d2fa is `bra.b` to itself -- the loop the abort path lands in.
        at(0x4012d2fa, lambda uc, a, s, d: mark.__setitem__('terminal', True))

        # Latch the frame at the diff's entry, which emu/panel.py documents as
        # the one moment [FRONT] is a complete, just-rendered frame. Reading it
        # at an arbitrary moment instead -- which _publish_panel used to do --
        # is wrong twice over: mid-flush it is torn on a page boundary, and
        # once the diff has swapped, [FRONT] is the buffer being rendered into
        # NEXT rather than the one on the panel. On screen that is a UI that
        # flickers and elements that come and go between frames.
        #
        # This is the same hook emu.panel.Capture installs, and it does change
        # the run it observes -- but this window already hooks intro_done,
        # mainloop, job_pump and the terminal loop, and it is a viewer, not a
        # measurement. Anything comparing totals should not be reading a GUI.
        if profile.panel_diff is not None and profile.fb_front is not None:
            def latch_frame(uc, a, s_, d):
                buf = panel.read(m, profile.fb_front)
                if buf is not None:
                    self._panel_latch = buf
            at(profile.panel_diff, latch_frame)
        else:
            print('[gui] WARNING: panel_diff/fb_front did not resolve for this '
                  'image; falling back to reading the framebuffer at an '
                  'arbitrary moment, which may tear', flush=True)
        self.ready.set()
        self.stats['status'] = 'running'
        while not self.stop_flag.is_set():
            if self.pause.is_set():
                self.stats['status'] = 'paused'
                time.sleep(0.05)
                continue
            # Work out the status BEFORE blocking, not after: spin sits
            # inside Unicorn for a whole BUDGET, so whatever is set here is
            # what the UI shows for that whole window. Setting it afterwards
            # leaves the stale value on screen for the entire block and the
            # fresh one for microseconds.
            #
            # fps is measured between completed frames, so it holds its last
            # value forever once the firmware stops drawing. Decay it, or the
            # panel sits frozen while the status line claims 15 fps.
            idle = time.time() - self._frame_t
            if idle > 1.0:
                self.stats['fps'] = 0.0
                self.stats['status'] = 'running, no frame for %.0fs' % idle
            else:
                self.stats['status'] = 'running'
            pc = self._drain_input(m, profile, pc)
            pc, executed, stop = spin(m, pc, BUDGET, pits=pits)
            if stop != 'limit':
                self.stats['status'] = 'halted: %s' % stop
                # Also to stdout: the status label is invisible to anyone
                # watching the terminal, which is where emu.run prints
                # everything else, so a halt there reads as a freeze.
                total = self.stats['instrs'] + executed
                print('[gui] HALTED: %s  at pc=0x%08x after %dM instr'
                      % (stop, pc, total // 1_000_000), flush=True)
                break
            self.stats['instrs'] += executed
            self._publish_panel(m)
            fired = pits.fired
            self.stats['pit'] = (fired.get('PIT0', 0), fired.get('PIT2', 0),
                                 fired.get('PIT3', 0))
            self.stats['dtim3'] = fired.get('DTIM3', 0)
            # Also say it on stdout: the window shows the panel, but the
            # interesting part of a post-intro run is what the OS is doing,
            # and that was previously visible only from emu.uiprobe.
            self._report()
            self.stats['pc'] = pc
            self.stats['tasks'] = len(ev['tasks'])
            self.stats['prints'] = len(ev['prints'])
            if self.profile.current_tcb is not None:
                try:
                    self.stats['tcb'] = struct.unpack(
                        '>I', m.uc.mem_read(self.profile.current_tcb, 4))[0]
                except UcError:
                    pass
        else:
            self.stats['status'] = 'stopped'

    def _publish_panel(self, m):
        """Once the OS owns the panel, draw the firmware's framebuffer.

        The frame comes from `_panel_latch`, grabbed at the diff's entry where
        emu/panel.py guarantees [FRONT] is complete and untorn. Polling the
        pointer here instead would sample at an arbitrary point in the flush
        and, after a swap, read the buffer being rendered into next -- the
        window flickered for exactly that reason. The fallback read is only
        for an image where panel_diff did not resolve, so no latch exists.

        A frame is counted when the bytes change, which is the firmware's own
        notion of a new frame -- unlike the setPixel path, which has to infer
        one from a repeated coordinate.
        """
        if not self.use_panel:
            return
        buf = self._panel_latch
        if buf is None:
            buf = panel.read(m, self.fb_front)
        if buf is None or buf == self._last_panel:
            return
        px = panel.lit(buf)
        if not px and not self._panel_live:
            # INTRO_DONE fires tens of millions of instructions before the OS
            # first composes a frame, and the buffer is empty until it does.
            # Blanking the window for that whole stretch would look like a
            # regression, so hold the intro's last frame until there is
            # something real to replace it with. Once the OS has drawn, later
            # blanks are genuine and do get shown.
            return
        self._panel_live = True
        self._last_panel = buf
        fb = self.fb
        for i in range(W * H):
            fb[i] = 0
        for x, y in px:
            fb[y * W + x] = 1
        now = time.time()
        self.captured.append(bytes(fb))
        self.stats['frames'] += 1
        self.stats['fps'] = 1.0 / max(1e-6, now - self._frame_t)
        self.stats['panel_lit'] = len(px)
        self.stats['source'] = 'panel'
        self._frame_t = now
        self.version += 1

    def _report(self):
        """One stdout line per ~20M instructions of OS progress.

        The window shows the panel, which after the intro is mostly blank; the
        part worth watching is what the OS is doing behind it. Printing it here
        means `uv run python -m emu.gui` says the same thing
        `python -m emu.uiprobe run` would, without needing a second run.
        """
        s = self.stats
        step = s['instrs'] // 20_000_000
        if step == self._reported:
            return
        self._reported = step
        note = ''
        if s['terminal']:
            note = ('   TERMINAL LOOP at 0x4012d2fa -- the main task is hung '
                    'on a weak pointer; re-run with --weakptr to step over it')
        print('[gui] %5.0fM instr  PIT0/2/3 %d/%d/%d  DTIM3 %d  '
              'mainloop %d  jobs %d  tasks %d  %s %d%s'
              % (s['instrs'] / 1e6, s['pit'][0], s['pit'][1], s['pit'][2],
                 s['dtim3'], s['mainloop'], s['jobs'], s['tasks'],
                 s['source'], s['panel_lit'] if s['source'] == 'panel'
                 else s['px'], note), flush=True)


class Controls(tk.Frame):
    """The front panel: click a button, scroll an encoder.

    Laid out from the device file's groups and labelled with the firmware's
    own control names, so the same code draws both products and neither the
    arrangement nor the labels are written down here.

    Every interaction goes onto the emulator's queue rather than touching
    guest memory, because the worker is inside Unicorn for a whole BUDGET at
    a time. Press and release are bound separately so a chord -- hold FUNC,
    tap a page button -- behaves the way it does on the hardware.
    """

    BG = '#15181d'
    FACE = '#222831'
    TEXT = '#cdd6e3'

    def __init__(self, master, device, button_names, encoder_names, send):
        super().__init__(master, bg=self.BG)
        self.device = device
        self.button_names = button_names
        self.encoder_names = encoder_names
        self.send = send
        self._build()

    # Character cells across before wrapping to a new row. Measured, not
    # guessed: on a 14" display 104 packs into 3 rows but 1414px wide, which
    # crowds the window edge, while 60 wraps to 7 rows and makes the surface
    # taller than the screen it saved. Anything from 84 to 92 lands on the
    # same 4-row, 1028x261 layout; 88 sits in the middle of that plateau.
    ROW_BUDGET = 88

    def _label(self, code, kind):
        names = self.button_names if kind == 'button' else self.encoder_names
        return names.get(code) or '#%d' % code

    def _group_labels(self, group):
        """-> {code: text}, with a prefix the whole group shares dropped.

        `TRIG 1`..`TRIG 16`, inside a box already titled `trigs`, spends most
        of its width repeating the word TRIG. Only a prefix ending in a space
        is cut, so PLAY and PLUS are never mangled into Y and S. A lone
        control keeps whatever follows its last space for the same reason:
        `ENCODER LEVEL` becomes `LEVEL`, while `SAMPLING` is left alone.
        """
        labels = {c: self._label(c, group.kind) for c in group.codes}
        if len(labels) < 2:
            return {c: t.rsplit(' ', 1)[-1] for c, t in labels.items()}
        cut = os.path.commonprefix(list(labels.values())).rfind(' ') + 1
        if cut <= 0:
            return labels
        return {c: (t[cut:] or t) for c, t in labels.items()}

    def _group_width(self, group, labels):
        """-> roughly how many character cells wide this group will render."""
        cells = group.columns or len(group.codes)
        widest = max((len(t) for t in labels.values()), default=2)
        return cells * (widest + (4 if group.kind == 'encoder' else 2))

    def _build(self):
        # Pack groups into rows greedily rather than on a fixed column count.
        # They differ enormously in width -- sixteen trig keys against a lone
        # LEVEL -- so a rigid grid sizes every column to its widest member,
        # leaving most of the window empty while still clipping the rest off
        # the bottom.
        row = column = used = 0
        for group in self.device.groups:
            labels = self._group_labels(group)
            width = self._group_width(group, labels)
            if column and used + width > self.ROW_BUDGET:
                row, column, used = row + 1, 0, 0
            box = tk.LabelFrame(self, text=group.name, bg=self.BG,
                                fg='#5d6a7c', bd=1, labelanchor='nw',
                                font=('SF Mono', 8))
            box.grid(row=row, column=column, sticky='nw', padx=4, pady=3)
            if group.kind == 'encoder':
                self._encoders(box, group, labels)
            elif group.layout == 'dpad':
                self._dpad(box, group, labels)
            else:
                self._buttons(box, group, labels)
            column += 1
            used += width

    def _buttons(self, box, group, labels):
        columns = group.columns or len(group.codes)
        for i, code in enumerate(group.codes):
            self._button(box, code, labels[code]).grid(
                row=i // columns, column=i % columns, padx=1, pady=1)

    def _dpad(self, box, group, labels):
        # The arrows group is UP, LEFT, DOWN, RIGHT in code order, which is
        # the order the firmware's own name table lists them in.
        places = ((0, 1), (1, 0), (1, 1), (1, 2))
        for code, (row, column) in zip(group.codes, places):
            self._button(box, code, labels[code]).grid(
                row=row, column=column, padx=1, pady=1)

    def _button(self, box, code, text):
        widget = tk.Button(box, text=text, bg=self.FACE, fg=self.TEXT,
                           activebackground='#3a4654',
                           activeforeground='#ffffff', relief='raised', bd=1,
                           highlightthickness=0, font=('SF Mono', 8),
                           width=max(2, len(text)), padx=0, pady=0)
        # Bound rather than given a `command`, which fires only on release:
        # the wire carries button STATE, so a held button must stay held.
        widget.bind('<ButtonPress-1>',
                    lambda _e, c=code: self.send('press', c, 0))
        widget.bind('<ButtonRelease-1>',
                    lambda _e, c=code: self.send('release', c, 0))
        return widget

    def _encoders(self, box, group, labels):
        columns = group.columns or len(group.codes)
        for i, code in enumerate(group.codes):
            cell = tk.Frame(box, bg=self.BG)
            cell.grid(row=i // columns, column=i % columns, padx=2, pady=1)
            face = tk.Label(cell, text=labels[code], bg=self.FACE,
                            fg=self.TEXT, font=('SF Mono', 9), width=5, pady=2)
            face.pack()
            strip = tk.Frame(cell, bg=self.BG)
            strip.pack()
            for text, step in (('-', -1), ('+', 1)):
                tk.Button(strip, text=text, bg=self.FACE, fg=self.TEXT, bd=1,
                          font=('SF Mono', 8), width=2, padx=0, pady=0,
                          command=lambda c=code, s=step:
                          self.send('encoder', c, s)).pack(side='left')
            # Wheel over an encoder turns it. Tk reports the wheel differently
            # per platform -- a signed delta on macOS and Windows, buttons 4
            # and 5 on X11 -- so all three are bound.
            for widget in (cell, face):
                widget.bind('<MouseWheel>',
                            lambda e, c=code: self._wheel(e, c))
                widget.bind('<Button-4>',
                            lambda _e, c=code: self.send('encoder', c, 1))
                widget.bind('<Button-5>',
                            lambda _e, c=code: self.send('encoder', c, -1))

    def _wheel(self, event, code):
        step = 1 if event.delta > 0 else -1
        if event.state & 0x0001:            # shift held: coarse
            step *= 10
        self.send('encoder', code, step)


class Panel(tk.Frame):
    def __init__(self, master, scale=7):
        super().__init__(master, bg='#0b0d10')
        self.scale = scale
        self.img = tk.PhotoImage(width=W, height=H)
        self.big = tk.PhotoImage(width=W * scale, height=H * scale)
        self.view = tk.Label(self, bd=0, highlightthickness=0, bg='#0b0d10',
                             image=self.big)
        self.view.pack(padx=18, pady=18)
        self._blank()

    def _blank(self):
        self.draw(bytearray(W * H))

    def draw(self, fb):
        body = b''.join(ON if v else OFF for v in fb)
        self.img.put(b'P6\n%d %d\n255\n' % (W, H) + body, to=(0, 0, W, H))
        # copy -zoom writes into the existing image; PhotoImage.zoom would
        # allocate a new one every refresh.
        self.tk.call(self.big, 'copy', self.img, '-zoom', self.scale, self.scale)


class App(tk.Tk):
    def __init__(self, snapshot, weakptr=False, slc=False, scale=None, syx=None):
        super().__init__()
        self.title('Digi emulator')
        self.configure(bg='#15181d')
        self.snapshot = snapshot
        # 128x64 is unreadable at 1:1, but the panel is not the point of the
        # window any more -- the control surface below it is, and it needs
        # real estate. RESERVE_H is what the buttons, the toolbar and the
        # status lines want; the zoom is whatever integer fits in the rest.
        # Capped well below what a large display would allow, because a panel
        # scaled edge to edge pushes the controls off the bottom. Integer
        # only: a fractional zoom would resample and invent pixels the
        # firmware never drew. Override with --scale.
        if scale is None:
            avail_w = max(1, self.winfo_screenwidth() - 160)
            avail_h = max(1, self.winfo_screenheight() - RESERVE_H)
            scale = max(1, min(MAX_SCALE, avail_w // W, avail_h // H))
        self.scale = scale

        self.panel = Panel(self, scale=scale)
        self.panel.pack(padx=14, pady=(14, 6))
        self.controls = None        # built once the worker knows the device

        bar = tk.Frame(self, bg='#15181d')
        bar.pack(fill='x', padx=20, pady=(0, 6))
        self.btn = ttk.Button(bar, text='Pause', width=9, command=self.toggle)
        self.btn.pack(side='left')
        ttk.Button(bar, text='Restart', width=9,
                   command=self.restart).pack(side='left', padx=6)
        ttk.Button(bar, text='Save PNG', width=9,
                   command=self.save).pack(side='left')
        self.replay_btn = ttk.Button(bar, text='Replay 15fps', width=12,
                                     command=self.toggle_replay)
        self.replay_btn.pack(side='left', padx=6)
        self.frames_lbl = tk.Label(bar, text='', bg='#15181d', fg='#7f8b9c',
                                   font=('SF Mono', 11))
        self.frames_lbl.pack(side='right')

        self.status = tk.Label(self, text='', bg='#15181d', fg='#9aa7b8',
                               font=('SF Mono', 11), anchor='w', justify='left')
        self.status.pack(fill='x', padx=20, pady=(0, 14))

        self.emu = None
        self.weakptr = weakptr
        self.slc = slc
        self.syx = syx
        self.shown = -1
        self.replay = None          # (frames, index, next_due) while replaying
        self.start()
        self.protocol('WM_DELETE_WINDOW', self.quit_all)
        self.after(60, self.tick)

    def start(self):
        self.emu = Emulator(self.snapshot, weakptr=self.weakptr, slc=self.slc, syx=self.syx)
        self.emu.start()

    def send_input(self, kind, code, arg):
        """Hand one panel event to the worker. Never touches guest memory."""
        if self.emu:
            self.emu.inbox.put((kind, code, arg))

    def _ensure_controls(self):
        """Build the control surface once the worker has identified the device."""
        if self.controls is not None or not self.emu or not self.emu.device:
            return
        self.controls = Controls(self, self.emu.device, self.emu.button_names,
                                 self.emu.encoder_names, self.send_input)
        self.controls.pack(padx=14, pady=(0, 10))

    def restart(self):
        if self.controls is not None:
            self.controls.destroy()
            self.controls = None
        if self.emu:
            self.emu.stop_flag.set()
            self.emu.pause.clear()
            self.emu.join(timeout=3)
        self.panel._blank()
        self.shown = -1
        self.replay = None
        self.replay_btn.configure(text='Replay 15fps')
        self.start()
        self.btn.configure(text='Pause')

    def toggle_replay(self):
        """Play the captured frames back at the rate the firmware asks for.

        Emulating in real time needs ~3x more throughput than we have, but the
        frames themselves are correct -- so replaying them at FRAME_HZ shows
        the animation at its true speed even though producing it was slower.
        """
        if self.replay is not None:
            self.replay = None
            self.replay_btn.configure(text='Replay 15fps')
            return
        frames = list(self.emu.captured) if self.emu else []
        if not frames:
            self.status.configure(text='nothing captured yet - let it run first')
            return
        if self.emu:
            self.emu.pause.set()
            self.btn.configure(text='Resume')
        self.replay = [frames, 0, time.time()]
        self.replay_btn.configure(text='Stop replay')

    def toggle(self):
        if not self.emu:
            return
        if self.emu.pause.is_set():
            self.emu.pause.clear()
            self.btn.configure(text='Pause')
        else:
            self.emu.pause.set()
            self.btn.configure(text='Resume')

    def save(self):
        os.makedirs('out', exist_ok=True)
        s = 6
        px = bytearray(W * s * H * s)
        for i, v in enumerate(self.emu.fb):
            if v:
                x, y = i % W, i // W
                for dy in range(s):
                    row = (y * s + dy) * W * s + x * s
                    for dx in range(s):
                        px[row + dx] = 255
        open('out/panel.png', 'wb').write(png(px, W * s, H * s))
        self.status.configure(text='wrote out/panel.png')

    def tick(self):
        if self.replay is not None:
            frames, i, due = self.replay
            now = time.time()
            if now >= due:
                self.panel.draw(frames[i])
                i = (i + 1) % len(frames)
                self.replay = [frames, i, max(now, due + 1.0 / FRAME_HZ)]
                self.frames_lbl.configure(
                    text='replay %d/%d at %.2f fps (true speed)'
                         % (i, len(frames), FRAME_HZ))
                self.status.configure(
                    text='replaying captured frames at the firmware\'s own rate\n'
                         'PIT3: (0x2191+1) x 1024 = 8,800,256 bus cycles @ 132 MHz',
                    fg='#9aa7b8')
            self.after(10, self.tick)
            return
        e = self.emu
        if e:
            if e.error:
                self.status.configure(text=e.error, fg='#ff8f8f')
            else:
                self._ensure_controls()
                if e.version != self.shown:
                    self.panel.draw(e.fb)      # skip if nothing was drawn
                    self.shown = e.version
                s = e.stats
                self.frames_lbl.configure(
                    text='frame %d   %.1f / %.1f fps  (%.0f%% of real time)'
                         % (s['frames'], s['fps'], FRAME_HZ,
                            100.0 * s['fps'] / FRAME_HZ))
                extra = ('  HUNG: terminal loop 0x4012d2fa (try --weakptr)'
                         if s['terminal'] else '')
                self.status.configure(
                    text='%s   %.1f fps   %d frames   %d tasks%s\n'
                         'pc 0x%08x   task 0x%08x   source %s   %s %d\n'
                         'PIT0 %d   PIT2 %d   PIT3 %d   DTIM3 %d   '
                         'mainloop %d   jobs %d   %.1fM instructions'
                         % (s['status'], s['fps'], s['frames'], s['tasks'],
                            extra,
                            s['pc'], s['tcb'], s['source'],
                            'lit' if s['source'] == 'panel' else 'setPixel',
                            s['panel_lit'] if s['source'] == 'panel'
                            else s['px'],
                            s['pit'][0], s['pit'][1], s['pit'][2],
                            s['dtim3'], s['mainloop'], s['jobs'],
                            s['instrs'] / 1e6),
                    fg='#9aa7b8')
        self.after(60, self.tick)

    def quit_all(self):
        # Join before tearing down: the worker is inside Unicorn between
        # chunks, and letting the interpreter kill a daemon thread mid-
        # emu_start crashes the process on exit (SIGBUS).
        if self.emu:
            self.emu.stop_flag.set()
            self.emu.pause.clear()
            self.emu.join(timeout=3)
        self.destroy()


if __name__ == '__main__':
    # --weakptr steps over the weak-pointer branches that otherwise freeze the
    # main task in the terminal loop after 153 messages. It is a diagnostic,
    # not a fix -- see longrun.build.  --scale N forces the integer panel zoom.
    argv = sys.argv[1:]
    weakptr = '--weakptr' in argv
    slc = '--slc' in argv
    scale = None
    if '--scale' in argv:
        i = argv.index('--scale')
        scale = max(1, int(argv[i + 1]))
        del argv[i:i + 2]
    syx = None
    if '--syx' in argv:
        i = argv.index('--syx')
        syx = argv[i + 1]
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith('--')]
    snap = args[0] if args else 'snapshots/boot400M.snap'
    if not os.path.exists(snap):
        raise SystemExit('no such snapshot: %s\n'
                         'build one with:  uv run python -m emu.checkpoint make '
                         '60000000,120000000,200000000,280000000,400000000' % snap)
    App(snap, weakptr=weakptr, slc=slc, scale=scale, syx=syx).mainloop()
