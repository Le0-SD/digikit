# pyright: reportMissingImports=false
"""Create a boot snapshot, and resume from one.

make:   uv run python -m emu.checkpoint make 60000000,400000000 [prefix] [syx]
resume: uv run python -m emu.checkpoint resume snapshots/boot400M.snap 5000000
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicorn.m68k_const import UC_M68K_REG_PC

import emu.dspboot as db
import emu.longrun as lr
from emu import config
from emu.snapshot import save


def _integer(text, label):
    try:
        return int(text)
    except (TypeError, ValueError) as exc:
        raise SystemExit("invalid %s: %r" % (label, text)) from exc


def _points(text):
    return [
        _integer(value, "checkpoint instruction count") for value in text.split(",")
    ]


def save_longrun(machine, ev, timers, path, extra=None):
    """Save stateful longrun state, including timer cadence.

    Example: ``save_longrun(m, ev, timers, '/tmp/run.snap', {'n': n})``.
    On restore, call ``ev['restore_checkpoint_timers']()`` before execution.
    ``make`` and timer-less ``resume`` remain legacy helpers and do not save
    timer cadence.
    """
    components = dict(ev["checkpoint_components"])
    components["timers"] = timers
    return save(
        machine,
        path,
        extra=extra,
        components=components,
        manifest=ev["checkpoint_manifest"],
    )


def make(points, prefix="snapshots/boot", syx=None, img_path=None):
    """Save a LADDER of checkpoints in one pass.

    `points` is a list of instruction counts. Saving mid-run is safe because
    save() only reads state; emulation continues afterwards. One slow pass
    yields several resume points, so later blocker work can start deep.
    """
    syx = config.firmware(syx)
    image_path = config.main_image(img_path)
    try:
        with open(image_path, "rb") as image:
            img = image.read()
    except OSError as exc:
        raise RuntimeError("cannot read MAIN OS image %r" % image_path) from exc
    points = sorted(points)
    todo = list(points)
    box = {"m": None, "saved": []}

    def hook(uc, addr, size, st):
        if todo and st["n"] >= todo[0]:
            at = todo.pop(0)
            path = "%s%dM.snap" % (prefix, at // 1_000_000)
            info = save(
                box["m"],
                path,
                extra={
                    "n": st["n"],
                    "seen": sorted(st["seen"]),
                    "tasks": {hex(k): v for k, v in st["task_create_hits"].items()},
                },
            )
            box["saved"].append(
                (
                    at,
                    path,
                    info,
                    len(st["seen"]),
                    len(st["task_create_hits"]),
                    uc.reg_read(UC_M68K_REG_PC),
                )
            )
            print(
                "  [%dM] %s  %d addrs, %d tasks, pc=0x%08x, %d B"
                % (
                    at // 1_000_000,
                    path,
                    len(st["seen"]),
                    len(st["task_create_hits"]),
                    uc.reg_read(UC_M68K_REG_PC),
                    info["bytes_on_disk"],
                ),
                flush=True,
            )

    m, st, stop = db.run(
        syx,
        img,
        limit=points[-1] + 1_000_000,
        extra_hook=hook,
        fast=True,
        verbose=False,
        machine_out=box,
    )
    return box["saved"]


def resume(path, extra_instrs, hook=None, chunk=500_000):
    """Restore and run forward. Returns (machine, new_addrs, stop_reason, n).

    Resuming has to happen onto an ALREADY-hooked Machine: restoring onto a
    bare one drops the flash HLE, the completion-semaphore patch and the
    scheduler tick, and the run then diverges while still looking plausible
    (docs/NEXT.md trap 4). longrun.build does the hooking, so go through it
    rather than snapshot.restore().
    """
    from unicorn import UC_HOOK_CODE

    m, ev, st, pc, inq, at = lr.build(path)
    carried = set(st["seen"])
    if hook:
        m.uc.hook_add(UC_HOOK_CODE, hook)
    pc, done, stop = lr.spin(m, pc, extra_instrs, chunk)
    st["n"] += done
    return m, st["seen"] - carried, stop, done, st, ev


def extend(path, points, prefix="snapshots/ext", chunk=500_000):
    """Resume `path` and save a ladder of further checkpoints.

    `points` are instruction counts measured FROM the resume point, so
    extend('snapshots/boot280M.snap', [200e6, 400e6]) writes checkpoints at an
    absolute 480M and 680M. Coverage (`seen`) is carried through unchanged --
    tracking new coverage needs a global per-instruction hook, which costs ~3x
    and is not worth paying just to keep a statistic warm.
    """
    m, ev, st, pc, inq, at = lr.build(path)
    base_n = st["n"]
    todo, saved = sorted(points), []

    def on_chunk(p, done):
        while todo and done >= todo[0]:
            todo.pop(0)
            out = "%s%dM.snap" % (prefix, (base_n + done) // 1_000_000)
            extra = {
                "n": base_n + done,
                "seen": sorted(st["seen"]),
                "tasks": {hex(k): v for k, v in st["task_create_hits"].items()},
                "seen_stale": True,
            }
            info = save(m, out, extra=extra)
            saved.append((out, base_n + done))
            print(
                "  [%dM] %s  pc=0x%08x  %d B  tasks_seen_since=%d"
                % (
                    (base_n + done) // 1_000_000,
                    out,
                    p,
                    info["bytes_on_disk"],
                    len(ev["tasks"]),
                ),
                flush=True,
            )

    pc, done, stop = lr.spin(m, pc, max(points), chunk, on_chunk=on_chunk)
    return saved, m, ev, stop


if __name__ == "__main__":
    import time

    cmd = sys.argv[1]
    if cmd == "make":
        pts = _points(sys.argv[2])
        prefix = sys.argv[3] if len(sys.argv) > 3 else "snapshots/boot"
        syx = sys.argv[4] if len(sys.argv) > 4 else None
        make(pts, prefix, syx)
    elif cmd == "extend":
        snap = sys.argv[2]
        pts = _points(sys.argv[3])
        prefix = sys.argv[4] if len(sys.argv) > 4 else "snapshots/ext"
        t0 = time.time()
        saved, m, ev, stop = extend(snap, pts, prefix)
        print(
            "extended %s by %dM in %.0fs, stop=%s"
            % (snap, max(pts) // 1_000_000, time.time() - t0, stop)
        )
        print("new tasks: %s" % ["0x%08x/p%d" % (e, p) for e, p, _ in ev["tasks"]])
        print("prints   : %r" % ev["prints"][:20])
    else:
        path = sys.argv[2]
        extra = (
            _integer(sys.argv[3], "instruction count")
            if len(sys.argv) > 3
            else 2_000_000
        )
        t0 = time.time()
        m, fresh, stop, n, st, ev = resume(path, extra)
        print(
            "resumed: ran %d instrs in %.1fs, %d NEW addrs, stop=%s pc=0x%08x"
            % (n, time.time() - t0, len(fresh), stop, m.uc.reg_read(UC_M68K_REG_PC))
        )
