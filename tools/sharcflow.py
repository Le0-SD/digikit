"""Mark the SHARC+ software call and return in a Ghidra program.

    uv run python tools/sharcflow.py REGION.bin [--base-sw 0x1c1338]
        [--lookback N] [--min-depth N] [--json OUT]
        [--program /dt2-1.16_SHARC [--project DIR --project-name NAME]
         [--cover] [--analyze] [--save]]

The DSP code calls a function with a push (`3c`), a store (`16a`, through
I7/M7, of the store's own short-word address + 2) and a goto (`25a_direct`),
sometimes with argument loads between the store and the goto, and returns
with an indirect jump (`9b_abs`) followed by `25c_rframe`. The generated
language models the goto as a plain branch, so Ghidra merges callees into
their callers and never disassembles the code after a call.

Without --program the tool only reports, from REGION.bin (raw code, 16-bit
little-endian words; --base-sw is the short-word address of its first word):

- calls: every aligned `25a_direct` (on the linear sweep of
  tools/sharcimm.py, with a decoded run of at least --min-depth instructions)
  with a `16a` among the --lookback instructions before it and no control
  transfer between them. "strict" marks the adjacent triple 3c, 16a, goto.
  "delta" is the goto's short-word address less the value the 16a stores;
- gotos: the other aligned `25a_direct`, left as branches;
- returns: aligned `9b_abs` followed within two instructions by `25c_rframe`.

With --program it opens that program and, per call site, disassembles the
goto if needed, sets FlowOverride.CALL on it, disassembles the fall-through
and the target, and creates a function at the target. A return whose jump
does not already have a terminal flow gets FlowOverride.RETURN. --cover then
disassembles, one instruction at a time, every aligned instruction Ghidra has
not reached (following flow stops at returns, indirect jumps and data), counts
those that clash with an existing instruction or data, and starts a function
after every return pair. Then it recomputes every function body, optionally
runs auto-analysis, and prints functions, instructions and call references
before and after. Nothing is saved without --save.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)

import sharcimm  # noqa: E402

DEFAULT_GHIDRA = '/opt/homebrew/Cellar/ghidra/12.1.3/libexec'
PUSH_R2 = 0x9FF2
RETURN_JUMP = 0x083F343F
TRANSFER_PREFIXES = ('8a', '9a', '9b', '11a', '25a', '25c')


def _value(fields, stem):
    """The value split across fields STEM[31:16] or STEM[23:16], and STEM[15:0]."""
    high = fields.get(stem + '[31:16]', fields.get(stem + '[23:16]'))
    return (high << 16) | fields[stem + '[15:0]']


def aligned(data: bytes, min_depth: int = 8):
    """Aligned instructions in address order: [(offset, Instruction)]."""
    table = sharcimm.decode_all(data)
    depth = sharcimm.depths(table, len(data))
    sweep = sharcimm.sweep_offsets(table, len(data))
    return [(off, table[off]) for off in sorted(sweep) if depth[off] >= min_depth]


def find_sites(data: bytes, base_sw: int, lookback: int = 3, min_depth: int = 8) -> dict:
    """calls, gotos and returns, plus 'aligned': [(sw, length in bytes)] of every
    aligned instruction."""
    insns = aligned(data, min_depth)
    calls, gotos, returns = [], [], []
    for n, (off, insn) in enumerate(insns):
        sw = base_sw + off // 2
        if insn.type_name == '25a_direct':
            target = _value(insn.fields, 'addr')
            store = None
            for back in range(1, lookback + 1):
                if n - back < 0:
                    break
                p_off, prev = insns[n - back]
                # the run back to the store must be contiguous and hold no transfer
                if p_off + prev.length_bytes != insns[n - back + 1][0]:
                    break
                # the call's store pushes, through I7/M7, its own address + 2
                if (prev.type_name == '16a' and prev.fields['i[2:0]'] == 7
                        and prev.fields['m[2:0]'] == 7
                        and _value(prev.fields, 'data') == base_sw + p_off // 2 + 2):
                    store = (n - back, p_off, prev)
                    break
                if prev.type_name.startswith(TRANSFER_PREFIXES):
                    break
            if store is None:
                gotos.append({'sw': sw, 'target': target})
                continue
            s_n, s_off, s_insn = store
            stored = _value(s_insn.fields, 'data')
            push = s_n > 0 and insns[s_n - 1][1].raw == PUSH_R2 \
                and insns[s_n - 1][0] + 2 == s_off
            calls.append({
                'sw': sw, 'target': target, 'store_sw': base_sw + s_off // 2,
                'stored': stored, 'delta': sw - stored,
                'between': n - s_n - 1, 'push': push,
                'strict': push and n - s_n == 1,
                'store_fields': {k: v for k, v in s_insn.fields.items() if not k.startswith('data')},
            })
        elif insn.type_name == '9b_abs' and insn.raw == RETURN_JUMP:
            for ahead in (1, 2):
                if n + ahead < len(insns) and insns[n + ahead][1].type_name == '25c_rframe':
                    returns.append({'sw': sw, 'rframe_sw': base_sw + insns[n + ahead][0] // 2})
                    break
    return {'calls': calls, 'gotos': gotos, 'returns': returns,
            'aligned': [(base_sw + off // 2, insn.length_bytes) for off, insn in insns]}


def summary(sites: dict) -> list:
    calls = sites['calls']
    lines = [
        f"calls {len(calls)} (strict triples {sum(c['strict'] for c in calls)}, "
        f"with push {sum(c['push'] for c in calls)}), "
        f"distinct targets {len({c['target'] for c in calls})}",
        f"other gotos {len(sites['gotos'])}, returns {len(sites['returns'])}",
        "instructions between store and goto: "
        + ", ".join(f"{k}:{v}" for k, v in sorted(collections.Counter(c['between'] for c in calls).items())),
        "goto sw - stored: "
        + ", ".join(f"{k}:{v}" for k, v in sorted(collections.Counter(c['delta'] for c in calls).items())),
        "store fields: "
        + ", ".join(f"{dict(k)}:{v}" for k, v in collections.Counter(
            tuple(sorted(c['store_fields'].items())) for c in calls).most_common(5)),
    ]
    return lines


# --- Ghidra -----------------------------------------------------------------

def _measure(program, lo_sw, hi_sw):
    from ghidra.program.model.address import AddressSet

    space = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()
    refs = program.getReferenceManager()
    main = AddressSet(space.getAddress(2 * lo_sw), space.getAddress(2 * hi_sw - 1))
    insn_all = listing.getNumInstructions()
    insn_main = calls_all = 0
    for insn in listing.getInstructions(True):
        in_main = main.contains(insn.getAddress())
        insn_main += in_main
        for ref in refs.getReferencesFrom(insn.getAddress()):
            if ref.getReferenceType().isCall():
                calls_all += 1
    fm = program.getFunctionManager()
    funcs_main = sum(1 for f in fm.getFunctions(True) if main.contains(f.getEntryPoint()))
    in_func_main = sum(1 for insn in listing.getInstructions(main, True)
                       if fm.getFunctionContaining(insn.getAddress()) is not None)
    return {'functions': fm.getFunctionCount(), 'functions_main': funcs_main,
            'instructions': insn_all, 'instructions_main': insn_main,
            'in_function_main': in_func_main, 'call_refs': calls_all}


def cover(program, sites, stats, lo_sw, hi_sw):
    """Disassemble every aligned instruction Ghidra has not reached, one
    instruction each, start a function after every return pair, then start a
    function at each run of main-program instructions no function holds."""
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.program.model.address import AddressSet
    from ghidra.util.task import TaskMonitor

    mon = TaskMonitor.DUMMY
    space = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()
    mem = program.getMemory()
    fm = program.getFunctionManager()

    for sw, nbytes in sites['aligned']:
        addr = space.getAddress(2 * sw)
        end = addr.add(nbytes - 1)
        if not (mem.contains(addr) and mem.contains(end)):
            stats['cover_outside_memory'] += 1
            continue
        have = listing.getInstructionContaining(addr)
        if have is not None:
            same = have.getAddress() == addr and have.getLength() == nbytes
            stats['cover_present' if same else 'cover_conflict'] += 1
            continue
        if listing.getInstructionContaining(end) is not None or \
                listing.getDefinedDataContaining(addr) is not None or \
                listing.getDefinedDataContaining(end) is not None:
            stats['cover_conflict'] += 1
            continue
        DisassembleCommand(addr, AddressSet(addr, end), False).applyTo(program, mon)
        got = listing.getInstructionAt(addr)
        if got is not None and got.getLength() == nbytes:
            stats['cover_disassembled'] += 1
        else:
            stats['cover_failed'] += 1

    for ret in sites['returns']:
        addr = space.getAddress(2 * (ret['rframe_sw'] + 1))
        if listing.getInstructionAt(addr) is None or fm.getFunctionContaining(addr) is not None:
            continue
        if CreateFunctionCmd(addr).applyTo(program, mon):
            stats['function_after_return'] += 1
        else:
            stats['function_after_return_failed'] += 1

    # Such a run follows a tail jump, a jump, a return or a gap, so it is code
    # no known flow reaches. Each new body can end before the next run, so
    # repeat until no run is left or no function can be made.
    main = AddressSet(space.getAddress(2 * lo_sw), space.getAddress(2 * hi_sw - 1))
    for _ in range(16):
        starts, prev_free, prev_end = [], False, None
        for insn in listing.getInstructions(main, True):
            addr = insn.getAddress()
            free = fm.getFunctionContaining(addr) is None
            if free and not (prev_free and prev_end == addr):
                starts.append(addr)
            prev_free, prev_end = free, insn.getMaxAddress().next()
        made = 0
        for addr in starts:
            if fm.getFunctionContaining(addr) is not None:
                continue
            if CreateFunctionCmd(addr).applyTo(program, mon):
                made += 1
            else:
                stats['function_run_start_failed'] += 1
        stats['function_run_start'] += made
        stats['function_run_rounds'] += 1
        if made == 0:
            break


def apply(program, sites, lo_sw, hi_sw, analyze, do_cover=False):
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.model.listing import FlowOverride
    from ghidra.util.task import TaskMonitor

    mon = TaskMonitor.DUMMY
    space = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()
    mem = program.getMemory()
    fm = program.getFunctionManager()
    stats = collections.Counter()

    def insn_at(sw):
        addr = space.getAddress(2 * sw)
        if not mem.contains(addr):
            return addr, None
        if listing.getInstructionAt(addr) is None:
            DisassembleCommand(addr, None, False).applyTo(program, mon)
        return addr, listing.getInstructionAt(addr)

    for call in sites['calls']:
        addr, insn = insn_at(call['sw'])
        if insn is None:
            stats['call_not_disassembled'] += 1
            continue
        flow = insn.getFlowType()
        if not (flow.isJump() and flow.isUnConditional()):
            stats[f'call_flow_{flow}'] += 1
            continue
        if insn.getFlowOverride() != FlowOverride.CALL:
            insn.setFlowOverride(FlowOverride.CALL)
            stats['call_override'] += 1
        DisassembleCommand(insn.getMaxAddress().next(), None, True).applyTo(program, mon)
        taddr = space.getAddress(2 * call['target'])
        if not mem.contains(taddr):
            stats['target_outside_memory'] += 1
            continue
        DisassembleCommand(taddr, None, True).applyTo(program, mon)
        if fm.getFunctionAt(taddr) is None:
            if CreateFunctionCmd(taddr).applyTo(program, mon):
                stats['function_created'] += 1
            else:
                stats['function_failed'] += 1

    for ret in sites['returns']:
        addr, insn = insn_at(ret['sw'])
        if insn is None:
            stats['return_not_disassembled'] += 1
            continue
        if insn.getFlowType().isTerminal():
            stats['return_already_terminal'] += 1
        else:
            insn.setFlowOverride(FlowOverride.RETURN)
            stats['return_override'] += 1

    if do_cover:
        cover(program, sites, stats, lo_sw, hi_sw)

    for func in list(fm.getFunctions(True)):
        CreateFunctionCmd.fixupFunctionBody(program, func, mon)

    if analyze:
        mgr = AutoAnalysisManager.getAnalysisManager(program)
        mgr.initializeOptions()
        mgr.reAnalyzeAll(None)
        mgr.startAnalysis(mon)
    return stats


def run_ghidra(args, sites, lo_sw, hi_sw):
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or '.') != _here]
    os.environ.setdefault('GHIDRA_INSTALL_DIR', DEFAULT_GHIDRA)
    import pyghidra
    pyghidra.start(verbose=False)
    from ghidra.base.project import GhidraProject

    project = GhidraProject.openProject(os.path.expanduser(args.project), args.project_name, False)
    folder, name = args.program.rsplit('/', 1)
    program = project.openProgram(folder or '/', name, False)
    try:
        before = _measure(program, lo_sw, hi_sw)
        tx = program.startTransaction('sharcflow: software calls and returns')
        try:
            stats = apply(program, sites, lo_sw, hi_sw, args.analyze, args.cover)
        finally:
            program.endTransaction(tx, True)
        after = _measure(program, lo_sw, hi_sw)
        if args.save:
            project.save(program)
    finally:
        project.close(program)
        project.close()
    return {'before': before, 'after': after, 'stats': dict(stats), 'saved': args.save}


def _int(text):
    return int(text, 0)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('region')
    ap.add_argument('--base-sw', type=_int, default=0x1C1338)
    ap.add_argument('--lookback', type=int, default=3,
                    help='instructions to search back from a goto for its 16a (default 3)')
    ap.add_argument('--min-depth', type=int, default=8)
    ap.add_argument('--json')
    ap.add_argument('--program', help='program path in the project, e.g. /dt2-1.16_SHARC')
    ap.add_argument('--project', default='~/ghidra-projects/elektron-sharc')
    ap.add_argument('--project-name', default='elektron-sharc')
    ap.add_argument('--cover', action='store_true',
                    help='also disassemble every aligned instruction and start functions after returns')
    ap.add_argument('--analyze', action='store_true', help='run auto-analysis after the overrides')
    ap.add_argument('--save', action='store_true', help='save the program (default: discard)')
    args = ap.parse_args(argv)

    with open(args.region, 'rb') as f:
        data = f.read()
    lo_sw, hi_sw = args.base_sw, args.base_sw + len(data) // 2
    sites = find_sites(data, args.base_sw, args.lookback, args.min_depth)
    for line in summary(sites):
        print(line)
    print(f"aligned instructions {len(sites['aligned'])}")
    result = {'region': args.region, 'base_sw': args.base_sw,
              **{k: v for k, v in sites.items() if k != 'aligned'}}
    if args.program:
        ghidra = run_ghidra(args, sites, lo_sw, hi_sw)
        for key in ('before', 'after'):
            print(key, ' '.join(f'{k}={v}' for k, v in ghidra[key].items()))
        print('actions', ' '.join(f'{k}={v}' for k, v in sorted(ghidra['stats'].items())))
        print('saved' if ghidra['saved'] else 'not saved')
        result['ghidra'] = ghidra
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(result, f, indent=1)
    return 0


if __name__ == '__main__':
    sys.exit(main())
