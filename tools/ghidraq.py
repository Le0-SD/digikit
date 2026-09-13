# fmt: off
"""Query an already-imported/analyzed Ghidra program over PyGhidra.

    GHIDRA_INSTALL_DIR=/opt/homebrew/Cellar/ghidra/12.1.3/libexec \
    uv run python tools/ghidraq.py PROGRAM strings 'Digisharc.*'
    uv run python tools/ghidraq.py PROGRAM xrefs 0x4022b20e
    uv run python tools/ghidraq.py PROGRAM func 0x40001622
    uv run python tools/ghidraq.py PROGRAM callers 0x40001622
    uv run python tools/ghidraq.py PROGRAM symbols 'rpc.*'
    uv run python tools/ghidraq.py PROGRAM range 0x402f9c14 0x40307f60

PROGRAM is the program's path inside the project ("section_3_MAIN_OS.bin"
for Digitakt II, "dn2_MAIN_OS.bin" for Digitone II; leading slash optional).

Read-only throughout: nothing opens a transaction, nothing is saved, and
the program on disk is untouched.

The JVM and project load cost ten-odd seconds, which dwarfs any single
query, so every subcommand takes MULTIPLE arguments and `--then` chains a
further subcommand into the same invocation:

    uv run python tools/ghidraq.py PROGRAM strings 'rpc' \
        --then xrefs 0x40123456 0x40123480 \
        --then decompile 0x40008000

Use --json for machine-readable output (one object per query, on stdout).

This exists because tools/ghidra/*.java need a full ghidra.sh launch per
run (minutes), and tools/decompile.py deliberately covers only decompile.
"""
import argparse
import json
import os
import re
import sys

# tools/ghidra/ is a plain directory of Java scripts that shadows the real
# `ghidra` Java-bridge namespace PyGhidra needs, once tools/ lands on
# sys.path -- which it does when this is run as `python tools/ghidraq.py`.
_here = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [p for p in sys.path if os.path.abspath(p or '.') != _here]

DEFAULT_PROJECT = os.path.expanduser('~/ghidra-projects/dt2')
DEFAULT_PROJECT_NAME = 'dt2'
DEFAULT_GHIDRA = '/opt/homebrew/Cellar/ghidra/12.1.3/libexec'
DECOMPILE_TIMEOUT = 60
SUBCOMMANDS = ('strings', 'symbols', 'xrefs', 'func', 'callers', 'decompile', 'read', 'range')


def _addr(program, value):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(value)


def q_strings(program, args, out):
    """Defined strings whose value matches any given regex (case-insensitive)."""
    from ghidra.program.model.data import StringDataType
    pats = [re.compile(a, re.I) for a in args]
    listing = program.getListing()
    hits = []
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        dt = d.getDataType()
        if not isinstance(dt, StringDataType) and 'string' not in dt.getName().lower():
            continue
        val = d.getValue()
        if val is None:
            continue
        val = str(val)
        if any(p.search(val) for p in pats):
            hits.append({'addr': '0x%x' % d.getAddress().getOffset(),
                         'len': d.getLength(), 'value': val})
    out('strings', {'patterns': args, 'count': len(hits), 'hits': hits})


def q_symbols(program, args, out):
    """Symbols (functions, labels, data) whose name matches any given regex."""
    pats = [re.compile(a, re.I) for a in args]
    hits = []
    for sym in program.getSymbolTable().getAllSymbols(True):
        name = sym.getName()
        if any(p.search(name) for p in pats):
            hits.append({'addr': '0x%x' % sym.getAddress().getOffset(),
                         'name': name, 'type': str(sym.getSymbolType()),
                         'namespace': str(sym.getParentNamespace().getName(True))})
    out('symbols', {'patterns': args, 'count': len(hits), 'hits': hits})


def q_xrefs(program, args, out):
    """Everything that references each given address, with the containing function."""
    fm = program.getFunctionManager()
    results = []
    for a in args:
        target = _addr(program, int(a, 16))
        refs = []
        for r in program.getReferenceManager().getReferencesTo(target):
            frm = r.getFromAddress()
            fn = fm.getFunctionContaining(frm)
            refs.append({'from': '0x%x' % frm.getOffset(),
                         'type': str(r.getReferenceType()),
                         'in_function': fn.getName() if fn else None,
                         'function_entry': '0x%x' % fn.getEntryPoint().getOffset() if fn else None})
        results.append({'addr': a, 'count': len(refs), 'refs': refs})
    out('xrefs', results)


def q_func(program, args, out):
    """The function containing each address: name, bounds, callers, callees."""
    fm = program.getFunctionManager()
    results = []
    for a in args:
        fn = fm.getFunctionContaining(_addr(program, int(a, 16)))
        if fn is None:
            results.append({'addr': a, 'function': None})
            continue
        body = fn.getBody()
        results.append({
            'addr': a,
            'function': fn.getName(),
            'entry': '0x%x' % fn.getEntryPoint().getOffset(),
            'size': body.getNumAddresses(),
            'signature': str(fn.getSignature()),
            'callers': sorted({f.getName() for f in fn.getCallingFunctions(None)}),
            'callees': sorted({f.getName() for f in fn.getCalledFunctions(None)}),
        })
    out('func', results)


def q_callers(program, args, out):
    """Just the callers of each address's function, with their entry points."""
    fm = program.getFunctionManager()
    results = []
    for a in args:
        fn = fm.getFunctionContaining(_addr(program, int(a, 16)))
        if fn is None:
            results.append({'addr': a, 'function': None, 'callers': []})
            continue
        callers = [{'name': f.getName(), 'entry': '0x%x' % f.getEntryPoint().getOffset()}
                   for f in fn.getCallingFunctions(None)]
        results.append({'addr': a, 'function': fn.getName(),
                        'count': len(callers),
                        'callers': sorted(callers, key=lambda c: c['entry'])})
    out('callers', results)


def q_decompile(program, args, out):
    """Decompiled C for the function containing each address."""
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    fm = program.getFunctionManager()
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(program)
    results = []
    try:
        for a in args:
            fn = fm.getFunctionContaining(_addr(program, int(a, 16)))
            if fn is None:
                results.append({'addr': a, 'function': None, 'c': None})
                continue
            res = ifc.decompileFunction(fn, DECOMPILE_TIMEOUT, None)
            results.append({'addr': a, 'function': fn.getName(),
                            'entry': '0x%x' % fn.getEntryPoint().getOffset(),
                            'c': res.getDecompiledFunction().getC() if res.decompileCompleted() else None,
                            'error': None if res.decompileCompleted() else str(res.getErrorMessage())})
    finally:
        ifc.dispose()
    out('decompile', results)


def q_read(program, args, out):
    """Hex + ASCII of bytes at ADDR:LEN (length defaults to 64)."""
    from jpype import JArray, JByte
    mem = program.getMemory()
    results = []
    for a in args:
        spec, _, n = a.partition(':')
        n = int(n, 0) if n else 64
        base = int(spec, 16)
        # Must be a real Java byte[]: JPype copies a Python bytearray into a
        # throwaway array, so getBytes() would fill that and we would read
        # back the zeros we started with.
        buf = JArray(JByte)(n)
        try:
            got = mem.getBytes(_addr(program, base), buf)
        except Exception as exc:
            results.append({'addr': spec, 'error': str(exc)})
            continue
        raw = bytes(bytearray(x & 0xFF for x in buf[:got]))
        results.append({'addr': spec, 'len': got, 'hex': raw.hex(),
                        'ascii': ''.join(chr(c) if 32 <= c < 127 else '.' for c in raw)})
    out('read', results)


def q_range(program, args, out):
    """Everything Ghidra knows about one or more address ranges: LO HI [LO HI ...].

    For each [LO, HI) range: memory block membership (and whether it is an
    uninitialised/bit block), defined data (address, type, label), defined
    instruction byte-count, symbols, and every address inside the range that
    is the *destination* of at least one reference, each with its referrers
    (from-address, type, containing function). This is the Ghidra-side
    counterpart to a static immediate scan (tools/refscan.py): it reports
    what Ghidra's own analysis -- which can follow some things a no-semantics
    disassembly sweep cannot, like relocations -- resolved as touching the
    range, not just what a fresh linear sweep can see.
    """
    if len(args) % 2 != 0:
        raise ValueError('range wants pairs of LO HI, got an odd number of args: %r' % (args,))
    listing = program.getListing()
    fm = program.getFunctionManager()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    refmgr = program.getReferenceManager()
    memory = program.getMemory()
    results = []
    for i in range(0, len(args), 2):
        lo, hi = int(args[i], 16), int(args[i + 1], 16)
        lo_addr, hi_addr = space.getAddress(lo), space.getAddress(hi - 1)
        addr_set = program.getAddressFactory().getAddressSet(lo_addr, hi_addr)

        blocks = []
        for blk in memory.getBlocks():
            if blk.getStart().getOffset() <= hi - 1 and blk.getEnd().getOffset() >= lo:
                blocks.append({'name': blk.getName(),
                               'start': '0x%x' % blk.getStart().getOffset(),
                               'end': '0x%x' % blk.getEnd().getOffset(),
                               'initialized': blk.isInitialized(),
                               'type': str(blk.getType())})

        data = []
        it = listing.getDefinedData(addr_set, True)
        while it.hasNext():
            d = it.next()
            data.append({'addr': '0x%x' % d.getAddress().getOffset(),
                        'type': d.getDataType().getName(),
                        'len': d.getLength(),
                        'label': d.getLabel()})

        insn_bytes = 0
        insn_count = 0
        it = listing.getInstructions(addr_set, True)
        while it.hasNext():
            ins = it.next()
            insn_bytes += ins.getLength()
            insn_count += 1

        symbols = []
        it = program.getSymbolTable().getSymbolIterator(lo_addr, True)
        while it.hasNext():
            sym = it.next()
            if sym.getAddress().getOffset() >= hi:
                break
            symbols.append({'addr': '0x%x' % sym.getAddress().getOffset(),
                            'name': sym.getName(), 'type': str(sym.getSymbolType())})

        referenced = []
        dit = refmgr.getReferenceDestinationIterator(addr_set, True)
        while dit.hasNext():
            dest = dit.next()
            refs = []
            for r in refmgr.getReferencesTo(dest):
                frm = r.getFromAddress()
                fn = fm.getFunctionContaining(frm)
                refs.append({'from': '0x%x' % frm.getOffset(),
                            'type': str(r.getReferenceType()),
                            'in_function': fn.getName() if fn else None})
            referenced.append({'addr': '0x%x' % dest.getOffset(), 'refs': refs})

        results.append({
            'lo': '0x%x' % lo, 'hi': '0x%x' % hi, 'size': hi - lo,
            'blocks': blocks, 'defined_data': data,
            'instruction_bytes': insn_bytes, 'instruction_count': insn_count,
            'symbols': symbols, 'referenced_addresses': referenced,
        })
    out('range', results)


HANDLERS = {'strings': q_strings, 'symbols': q_symbols, 'xrefs': q_xrefs,
            'func': q_func, 'callers': q_callers, 'decompile': q_decompile,
            'read': q_read, 'range': q_range}


def _print_text(kind, payload):
    print('=' * 72)
    print('## %s' % kind)
    if kind in ('strings', 'symbols'):
        print('%d hit(s) for %s' % (payload['count'], payload['patterns']))
        for h in payload['hits']:
            if kind == 'strings':
                print('  %s  (%d)  %r' % (h['addr'], h['len'], h['value']))
            else:
                ns = '' if h['namespace'] in ('Global', '') else h['namespace'] + '::'
                print('  %s  %-10s %s%s' % (h['addr'], h['type'], ns, h['name']))
        return
    for item in payload:
        if kind == 'xrefs':
            print('%s -- %d reference(s)' % (item['addr'], item['count']))
            for r in item['refs']:
                print('  from %s  %-14s %s' % (r['from'], r['type'], r['in_function'] or '(no function)'))
        elif kind in ('func', 'callers'):
            if item['function'] is None:
                print('%s -- no function' % item['addr']); continue
            if kind == 'func':
                print('%s -- %s @ %s  (%d bytes)' % (item['addr'], item['function'], item['entry'], item['size']))
                print('  sig:     %s' % item['signature'])
                print('  callers: %s' % (', '.join(item['callers']) or '(none)'))
                print('  callees: %s' % (', '.join(item['callees']) or '(none)'))
            else:
                print('%s -- %s, %d caller(s)' % (item['addr'], item['function'], item['count']))
                for c in item['callers']:
                    print('  %s  %s' % (c['entry'], c['name']))
        elif kind == 'decompile':
            if item['function'] is None:
                print('%s -- no function' % item['addr']); continue
            print('%s -- %s @ %s' % (item['addr'], item['function'], item['entry']))
            print(item['c'] or ('DECOMPILE FAILED: %s' % item['error']))
        elif kind == 'read':
            if 'error' in item:
                print('%s -- %s' % (item['addr'], item['error'])); continue
            print('%s (%d bytes)' % (item['addr'], item['len']))
            h = item['hex']
            for off in range(0, item['len'], 16):
                row = h[off * 2:off * 2 + 32]
                print('  %08x  %-32s  %s' % (int(item['addr'], 16) + off, row,
                                             item['ascii'][off:off + 16]))
        elif kind == 'range':
            print('%s-%s (%d bytes)' % (item['lo'], item['hi'], item['size']))
            for b in item['blocks']:
                print('  block %-16s %s-%s  initialized=%s  type=%s'
                     % (b['name'], b['start'], b['end'], b['initialized'], b['type']))
            print('  %d defined data item(s), %d instruction(s) (%d bytes), %d symbol(s)'
                 % (len(item['defined_data']), item['instruction_count'],
                    item['instruction_bytes'], len(item['symbols'])))
            for d in item['defined_data']:
                print('    data   %s  %-16s len=%-4d %s' % (d['addr'], d['type'], d['len'], d['label'] or ''))
            for s in item['symbols']:
                print('    symbol %s  %-10s %s' % (s['addr'], s['type'], s['name']))
            print('  %d referenced address(es) inside the range:' % len(item['referenced_addresses']))
            for r in item['referenced_addresses']:
                print('    %s  <- %d ref(s)' % (r['addr'], len(r['refs'])))
                for ref in r['refs']:
                    print('        from %s  %-14s %s' % (ref['from'], ref['type'], ref['in_function'] or '(no function)'))


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('program', help='program path inside the project')
    ap.add_argument('subcommand', choices=SUBCOMMANDS)
    ap.add_argument('args', nargs='+', help='arguments for the subcommand')
    ap.add_argument('--then', nargs='+', action='append', default=[],
                    metavar='SUBCOMMAND ARG',
                    help='another subcommand to run in the same JVM; repeatable')
    ap.add_argument('--project', default=DEFAULT_PROJECT)
    ap.add_argument('--project-name', default=DEFAULT_PROJECT_NAME)
    ap.add_argument('--json', action='store_true', help='emit JSON instead of text')
    args = ap.parse_args(argv)

    queries = [(args.subcommand, args.args)]
    for chain in args.then:
        if chain[0] not in SUBCOMMANDS:
            ap.error('--then wants a subcommand first, got %r (choose from %s)'
                     % (chain[0], ', '.join(SUBCOMMANDS)))
        if len(chain) < 2:
            ap.error('--then %s needs at least one argument' % chain[0])
        queries.append((chain[0], chain[1:]))

    os.environ.setdefault('GHIDRA_INSTALL_DIR', DEFAULT_GHIDRA)
    import pyghidra
    pyghidra.start(verbose=False)

    program_path = args.program if args.program.startswith('/') else '/' + args.program
    collected = []

    def out(kind, payload):
        if args.json:
            collected.append({'query': kind, 'result': payload})
        else:
            _print_text(kind, payload)

    project = pyghidra.open_project(args.project, args.project_name, create=False)
    try:
        with pyghidra.program_context(project, program_path) as program:
            for name, qargs in queries:
                HANDLERS[name](program, qargs, out)
    finally:
        project.close()

    if args.json:
        json.dump(collected, sys.stdout, indent=2)
        print()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
