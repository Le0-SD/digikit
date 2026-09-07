"""Boot the thing and watch the panel.

A live view of the Digitakt II's 128x64 OLED, driven by the real firmware
running under Unicorn. The emulator runs on a worker thread and writes into a
shared framebuffer whenever the firmware calls Bitmap::setPixel; the UI thread
just samples that framebuffer on a timer. Nothing here reimplements the raster
-- every lit pixel is one setPixel call the firmware actually made.

    uv run python -m emu.gui [snapshot]

tkinter only, no third-party GUI dependency. Note Homebrew's python@3.14 does
not ship tkinter; uv's managed CPython does, which is why pyproject pins 3.12.
"""
import os
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unicorn import UcError
from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_SR
from emu.longrun import build, run_until
from emu.screen import png

# The intro's frame rate is not a guess. PIT3 is configured at 0x400d3a7a with
# PCSR=0x0936 (prescaler 2^10) and PMR=0x2191, so one frame is (8593+1)*1024 =
# 8,800,256 bus cycles; its ISR (vector 208, 0x400d2d70) posts the semaphore
# the draw loop waits on at 0x400d4036. The bus clock is 132 MHz, taken from
# the UART baud divider at 0x400024a4 (132000000 / (32*baud)) -- which checks
# out because it also makes the RTOS tick exactly 50.000 Hz and PIT2 60.0 Hz.
FRAME_SEM = 0x43131200
FRAME_VECTOR = 208
FRAME_HZ = 132_000_000 / ((0x2191 + 1) * 1024)     # 14.9996

W, H = 128, 64
CURRENT_TCB = 0x47d9adb4

# Panel palette: an OLED is emissive, so the lit pixel is the bright thing and
# the ground is genuinely black rather than dark grey.
OFF = b'\x0c\x0e\x12'
ON = b'\xe8\xf6\xff'
# The emulator thread runs uncounted and stops at each completed panel frame
# instead of every N instructions: `count=` on emu_start costs ~1.8x for the
# same work (see longrun.run_until). A frame is also the only boundary the UI
# actually cares about, so nothing is lost but the exact instruction tally.


class Emulator(threading.Thread):
    """Runs the firmware and publishes a framebuffer. Owns no widgets."""

    daemon = True

    def __init__(self, snapshot):
        super().__init__()
        self.snapshot = snapshot
        self.fb = bytearray(W * H)
        self.pause = threading.Event()
        self.stop_flag = threading.Event()
        self.ready = threading.Event()
        self.stats = {'frames': 0, 'px': 0,
                      'pc': 0, 'tcb': 0, 'tasks': 0, 'prints': 0, 'fps': 0.0,
                      'bmp': 0,
                      'status': 'loading snapshot'}
        self._uc = None             # set once the machine is built
        self.error = None
        self._seen = set()
        self.version = 0            # bumped on every pixel, so the UI can
        self._frame_t = time.time()  # skip redrawing an unchanged panel
        self.captured = []          # completed frames, for correct-speed replay

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
                # Hand control back to the worker loop so it can honour pause
                # and stop. Safe here and nowhere else: the setPixel HLE has
                # already written PC = return address, so the resume does not
                # land back on this hook.
                self._uc.emu_stop()
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
            m, ev, st, pc, inq, at = build(self.snapshot, unblock=True,
                                           softfloat=True, bitmap=True,
                                           on_pixel=on_pixel)
        except Exception as exc:                       # noqa: BLE001
            self.error = '%s: %s' % (type(exc).__name__, exc)
            self.stats['status'] = 'failed to load'
            self.ready.set()
            return

        self._uc = m.uc
        self.ready.set()
        self.stats['status'] = 'running'
        while not self.stop_flag.is_set():
            if self.pause.is_set():
                self.stats['status'] = 'paused'
                time.sleep(0.05)
                continue
            # Work out the status BEFORE blocking, not after: run_until sits
            # inside Unicorn for up to its timeout, so whatever is set here is
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
            pc, stop = run_until(m, pc)
            if stop != 'stopped':
                self.stats['status'] = 'halted: %s' % stop
                break
            self.stats['pc'] = pc
            self.stats['tasks'] = len(ev['tasks'])
            self.stats['prints'] = len(ev['prints'])
            try:
                self.stats['tcb'] = struct.unpack(
                    '>I', m.uc.mem_read(CURRENT_TCB, 4))[0]
            except UcError:
                pass
        else:
            self.stats['status'] = 'stopped'


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
    def __init__(self, snapshot):
        super().__init__()
        self.title('Digitakt II - panel')
        self.configure(bg='#15181d')
        self.snapshot = snapshot

        self.panel = Panel(self)
        self.panel.pack(padx=14, pady=(14, 6))

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
        self.shown = -1
        self.replay = None          # (frames, index, next_due) while replaying
        self.start()
        self.protocol('WM_DELETE_WINDOW', self.quit_all)
        self.after(60, self.tick)

    def start(self):
        self.emu = Emulator(self.snapshot)
        self.emu.start()

    def restart(self):
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
                if e.version != self.shown:
                    self.panel.draw(e.fb)      # skip if nothing was drawn
                    self.shown = e.version
                s = e.stats
                self.frames_lbl.configure(
                    text='frame %d   %.1f / %.1f fps  (%.0f%% of real time)'
                         % (s['frames'], s['fps'], FRAME_HZ,
                            100.0 * s['fps'] / FRAME_HZ))
                self.status.configure(
                    text='%s   %.1f fps   %d frames   %d tasks\n'
                         'pc 0x%08x   task 0x%08x   bitmap 0x%08x   setPixel %d'
                         % (s['status'], s['fps'], s['frames'], s['tasks'],
                            s['pc'], s['tcb'], s['bmp'], s['px']),
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
    snap = sys.argv[1] if len(sys.argv) > 1 else 'snapshots/boot400M.snap'
    if not os.path.exists(snap):
        raise SystemExit('no such snapshot: %s\n'
                         'build one with:  uv run python -m emu.checkpoint make '
                         '60000000,120000000,200000000,280000000,400000000' % snap)
    App(snap).mainloop()
