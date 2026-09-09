#!/usr/bin/env python3
"""Deterministic boot classifier: did the firmware actually 'make it'?

Runs a firmware image (optionally resuming a snapshot) under the production
timer-deadline stepping, gates a basic-block profile on the intro handover,
captures guest output, and emits a single machine-readable verdict:

    PRE_INTRO | POST_INTRO_STALL | PARTIAL_MAIN_OS | MAIN_OS_RUNNING | CRASHED

The verdict plus a stable state digest turns the handover's acceptance
criteria into one reproducible command, and `--verify` runs two independent
arms and asserts they agree, so "deterministic" is checked, not assumed.

Usage:
    uv run python tools/bootcheck.py --syx Digitone_II_OS1.10E.syx \
        --snapshot snapshots/Digitone_II_OS1.10E/boot280M.snap \
        --post-intro 60000000 --json out.json
"""
import argparse, collections, hashlib, json, os, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from emu import config, symbols
from emu.longrun import build, spin
from emu.pit import Pits, intro_running, BASES as PIT_BASES
from emu.dtim import Dtims, Timers, BASES as DTIM_BASES

VEC208_SLOT = 0x40000340


def u32(m, a):
    try:
        return struct.unpack('>I', m.uc.mem_read(a, 4))[0]
    except Exception:
        return None


def u16(m, a):
    try:
        return struct.unpack('>H', m.uc.mem_read(a, 2))[0]
    except Exception:
        return None


def hx(v):
    return None if v is None else "0x%08x" % v


def run_arm(args, profile, main_img):
    """One independent emulation arm.  Returns the observation dict."""
    from unicorn import UC_HOOK_BLOCK

    m, ev, st, pc, inq, at = build(
        args.snapshot, syx=args.syx, unblock=True, softfloat=True,
        bitmap=True, dsp=True, slc=args.slc)

    intro = intro_running(m, profile.intro_pit3_isr)
    pits = Timers(Pits(m, hold=intro), Dtims(m, channels=(3,), hold=intro))

    mark = collections.Counter()
    phase = {"post_intro": not intro}

    # Block profile, reset at the intro handover so the profile describes the
    # phase we actually care about rather than the intro animation.
    blocks = collections.Counter()

    def on_block(uc, address, size, data):
        if phase["post_intro"]:
            blocks[address] += max(size // 2, 1)

    if args.profile:
        m.uc.hook_add(UC_HOOK_BLOCK, on_block)

    if intro and profile.intro_done is not None:
        def handover(uc, a, s_, d):
            pits.release()
            phase["post_intro"] = True
            blocks.clear()
            mark["intro_done"] += 1
        at(profile.intro_done, handover)

    for name in ("mainloop", "job_pump", "task_start", "display_start"):
        addr = getattr(profile, name, None)
        if addr is not None:
            at(addr, (lambda k: lambda uc, a, s_, d: mark.__setitem__(
                k, mark[k] + 1))(name))

    # Budget: run until the intro hands over, then a fixed post-intro window,
    # so the measured window is the same regardless of how long the intro took.
    total, post_at, done, pc_ = args.max_instrs, None, 0, pc
    stop = "limit"
    t0 = time.time()
    while done < total:
        pc_, executed, stop = spin(m, pc_, args.step, pits=pits)
        done += executed
        if phase["post_intro"] and post_at is None:
            post_at = done
        if post_at is not None and done - post_at >= args.post_intro:
            break
        if stop != "limit":
            break

    fired = pits.fired
    vec208 = u32(m, VEC208_SLOT)
    cur = u32(m, profile.current_tcb) if profile.current_tcb else None
    uart = bytes(ev["uart_out"])

    top = [{"block": hx(a), "instrs": n,
            "pct": round(100.0 * n / max(sum(blocks.values()), 1), 2)}
           for a, n in blocks.most_common(args.top)]

    return {
        "instrs": done,
        "post_intro_instrs": None if post_at is None else done - post_at,
        "stop": stop,
        "end_pc": hx(pc_),
        "marks": dict(mark),
        "pit_fired": {("PIT%d" % c): fired.get("PIT%d" % c, 0)
                      for c in (0, 2, 3)},
        "dtim3_fired": fired.get("DTIM3", 0),
        "vec208": hx(vec208),
        "vec208_is_intro_isr": vec208 == profile.intro_pit3_isr,
        "pit3_pcsr": hx(u16(m, PIT_BASES[3])),
        "dtim3_dtmr": hx(u16(m, DTIM_BASES[3])),
        "setpixel": ev.get("setpixel", 0),
        "current_tcb": hx(cur),
        "tasks_created": len(ev["tasks"]),
        "distinct_tasks_scheduled": len(ev["switch"]),
        "uart_bytes": len(uart),
        "uart_sha256": hashlib.sha256(uart).hexdigest(),
        "uart_tail": uart[-240:].decode("latin-1"),
        "prints_tail": [p for p in ev["prints"][-12:]],
        "top_blocks": top,
        "elapsed_s": round(time.time() - t0, 1),
    }


def classify(obs):
    """Map an observation onto a boot verdict plus the reasons for it."""
    reasons = []
    if obs["stop"] != "limit":
        return "CRASHED", ["stop reason %r" % obs["stop"]]

    marks = obs["marks"]
    if not marks.get("intro_done"):
        return "PRE_INTRO", ["intro_done never fired"]

    checks = {
        "mainloop entered": marks.get("mainloop", 0) > 0,
        "job pump running": marks.get("job_pump", 0) > 0,
        "PIT3 firing": obs["pit_fired"]["PIT3"] > 0,
        "DTIM3 firing": obs["dtim3_fired"] > 0,
        "vector 208 handed to display": not obs["vec208_is_intro_isr"],
    }
    for name, ok in checks.items():
        reasons.append(("ok: " if ok else "MISSING: ") + name)

    if all(checks.values()):
        return "MAIN_OS_RUNNING", reasons
    if not any(checks.values()):
        return "POST_INTRO_STALL", reasons
    return "PARTIAL_MAIN_OS", reasons


def digest(obs):
    """Stable digest of the observable end state, for determinism checking."""
    keyed = {k: obs[k] for k in (
        "instrs", "stop", "end_pc", "marks", "pit_fired", "dtim3_fired",
        "vec208", "setpixel", "current_tcb", "tasks_created",
        "distinct_tasks_scheduled", "uart_bytes", "uart_sha256")}
    return hashlib.sha256(
        json.dumps(keyed, sort_keys=True).encode()).hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--syx", required=True)
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--post-intro", type=int, default=60_000_000,
                    help="instructions to observe after the intro hands over")
    ap.add_argument("--max-instrs", type=int, default=400_000_000)
    ap.add_argument("--step", type=int, default=10_000_000)
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--slc", action="store_true", default=True)
    ap.add_argument("--no-profile", dest="profile", action="store_false",
                    default=True)
    ap.add_argument("--verify", action="store_true",
                    help="run two independent arms and require agreement")
    ap.add_argument("--json", help="write the full report here")
    args = ap.parse_args()

    main_img = open(config.main_image(), "rb").read()
    profile = symbols.resolve(main_img)

    arms = [run_arm(args, profile, main_img)]
    if args.verify:
        arms.append(run_arm(args, profile, main_img))

    verdict, reasons = classify(arms[0])
    report = {
        "snapshot": args.snapshot,
        "syx": args.syx,
        "verdict": verdict,
        "reasons": reasons,
        "digest": digest(arms[0]),
        "deterministic": (None if len(arms) < 2
                          else digest(arms[0]) == digest(arms[1])),
        "arms": arms,
    }
    if args.json:
        json.dump(report, open(args.json, "w"), indent=2)

    print(json.dumps({k: v for k, v in report.items() if k != "arms"}, indent=2))
    print("\n--- post-intro hot blocks ---")
    for b in arms[0]["top_blocks"]:
        print("  %s  %8d instrs  %5.2f%%" % (b["block"], b["instrs"], b["pct"]))
    print("\n--- guest output tail ---")
    print(arms[0]["uart_tail"] or "(none)")
    return 0 if verdict == "MAIN_OS_RUNNING" else 1


if __name__ == "__main__":
    sys.exit(main())
