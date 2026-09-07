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
from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
from emu.longrun import build
from emu.screen import png

W, H = 128, 64
SET_PIXEL = 0x40104eb4
CURRENT_TCB = 0x47d9adb4

# Panel palette: an OLED is emissive, so the lit pixel is the bright thing and
# the ground is genuinely black rather than dark grey.
OFF = b'\x0c\x0e\x12'
ON = b'\xe8\xf6\xff'
CHUNK = 250_000          # instructions between UI-visible updates


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
        self.stats = {'instrs': 0, 'rate': 0.0, 'frames': 0, 'px': 0,
                      'pc': 0, 'tcb': 0, 'tasks': 0, 'prints': 0,
                      'status': 'loading snapshot'}
        self.error = None
        self._seen = set()

    def run(self):
        try:
            m, ev, st, pc, inq, at = build(self.snapshot, unblock=True)
        except Exception as exc:                       # noqa: BLE001
            self.error = '%s: %s' % (type(exc).__name__, exc)
            self.stats['status'] = 'failed to load'
            self.ready.set()
            return

        def on_setpixel(uc, a, s, d):
            sp = uc.reg_read(UC_M68K_REG_A7)
            _ret, _this, x, y, val = struct.unpack('>IIIII', uc.mem_read(sp, 20))
            if x < W and y < H:
                if (x, y) in self._seen and len(self._seen) > W * H // 2:
                    self.stats['frames'] += 1          # coordinate repeat = new frame
                    self._seen.clear()
                self._seen.add((x, y))
                self.fb[y * W + x] = 1 if val else 0
                self.stats['px'] += 1
        at(SET_PIXEL, on_setpixel)

        self.ready.set()
        self.stats['status'] = 'running'
        t0, last, done = time.time(), 0, 0
        while not self.stop_flag.is_set():
            if self.pause.is_set():
                self.stats['status'] = 'paused'
                time.sleep(0.05)
                t0, last = time.time(), done
                continue
            self.stats['status'] = 'running'
            try:
                m.uc.emu_start(pc, 0, count=CHUNK)
            except UcError as exc:
                self.stats['status'] = 'halted: %s' % exc
                break
            pc = m.uc.reg_read(UC_M68K_REG_PC)
            done += CHUNK
            elapsed = time.time() - t0
            if elapsed > 0.4:
                self.stats['rate'] = (done - last) / elapsed / 1e6
                t0, last = time.time(), done
            self.stats['instrs'] = done
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
        self.view = tk.Label(self, bd=0, highlightthickness=0, bg='#0b0d10')
        self.view.pack(padx=18, pady=18)
        self._blank()

    def _blank(self):
        self.draw(bytearray(W * H))

    def draw(self, fb):
        body = b''.join(ON if v else OFF for v in fb)
        self.img.put(b'P6\n%d %d\n255\n' % (W, H) + body, to=(0, 0, W, H))
        self._zoomed = self.img.zoom(self.scale, self.scale)
        self.view.configure(image=self._zoomed)


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
        self.frames_lbl = tk.Label(bar, text='', bg='#15181d', fg='#7f8b9c',
                                   font=('SF Mono', 11))
        self.frames_lbl.pack(side='right')

        self.status = tk.Label(self, text='', bg='#15181d', fg='#9aa7b8',
                               font=('SF Mono', 11), anchor='w', justify='left')
        self.status.pack(fill='x', padx=20, pady=(0, 14))

        self.emu = None
        self.start()
        self.protocol('WM_DELETE_WINDOW', self.quit_all)
        self.after(60, self.tick)

    def start(self):
        self.emu = Emulator(self.snapshot)
        self.emu.start()

    def restart(self):
        if self.emu:
            self.emu.stop_flag.set()
        self.panel._blank()
        self.start()
        self.btn.configure(text='Pause')

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
        e = self.emu
        if e:
            if e.error:
                self.status.configure(text=e.error, fg='#ff8f8f')
            else:
                self.panel.draw(e.fb)
                s = e.stats
                self.frames_lbl.configure(text='frame %d' % s['frames'])
                self.status.configure(
                    text='%s   %.2fM instr/s   %dM executed\n'
                         'pc 0x%08x   task 0x%08x   setPixel %d   tasks +%d'
                         % (s['status'], s['rate'], s['instrs'] // 1_000_000,
                            s['pc'], s['tcb'], s['px'], s['tasks']),
                    fg='#9aa7b8')
        self.after(60, self.tick)

    def quit_all(self):
        if self.emu:
            self.emu.stop_flag.set()
        self.destroy()


if __name__ == '__main__':
    snap = sys.argv[1] if len(sys.argv) > 1 else 'snapshots/boot400M.snap'
    if not os.path.exists(snap):
        raise SystemExit('no such snapshot: %s\n'
                         'build one with:  uv run python -m emu.checkpoint make '
                         '60000000,120000000,200000000,280000000,400000000' % snap)
    App(snap).mainloop()
