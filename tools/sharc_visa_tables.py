"""SHARC+ instruction forms for tools/sharc_disasm.py, from tools/sharcspec/decode_table.json.

decode_table.json is built from the public ADI manuals: the SHARC+ Core
Programming Reference Rev 1.5, checked against the classic SHARC Programming
Reference Rev 2.4 (tools/sharcspec/README.md, docs/sharc/SOURCES.md). It
replaces this file's earlier transcription of Rev 1.4, whose `15b` entry
fixed 3 bits where the manual fixes 7.

Memory holds 16-bit little-endian words; a 32- or 48-bit instruction stores
its most significant word first. decode_table.json gives each form's mask and
value MSB-aligned in a 48-bit frame, frame = (w0 << 32) | (w1 << 16) | w2.
TYPES renumbers them onto each form's own width, so bit width-1 is the MSB of
the first word. decode() picks a form as tools/sharcspec/sharc_decode.py
does: among the matching forms, the longest run of fixed bits from bit 47
wins, then the most fixed bits; a tie is ambiguous.

TYPES entries: name (the form name without "Type", e.g. "15b", "8a_abs",
"5b_move"), bits, opcode_mask and opcode_value (own width), frame_mask and
frame_value (48-bit frame), fields {label: (hi, lo)} (own width), lead (fixed
bits from the top of the frame), fixed_bits, uncertain (the table marks some
fixed bits unconfirmed) and source.
"""

import json
import os
import re

TABLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sharcspec', 'decode_table.json')


def form_name(name):
    """'Type5b (move)' -> '5b_move'; 'Type8a_abs' -> '8a_abs'."""
    name = re.sub(r'^Type', '', name)
    return re.sub(r'\s*\((\w+)\)', r'_\1', name)


def _lead(mask):
    lead = 0
    for bit in range(47, -1, -1):
        if not (mask >> bit) & 1:
            break
        lead += 1
    return lead


def load(path=TABLE, mode='visa'):
    """-> TYPES for the VISA forms (mode 'visa') or the 48-bit ISA forms ('isa')."""
    with open(path) as f:
        forms = json.load(f)['forms']
    types = []
    for f in forms:
        if (mode == 'visa' and not f['visa']) or (mode == 'isa' and f['width'] != 48):
            continue
        shift = 48 - f['width']
        mask, value = int(f['mask'], 16), int(f['value'], 16)
        types.append({
            'name': form_name(f['name']), 'bits': f['width'],
            'opcode_mask': mask >> shift, 'opcode_value': value >> shift,
            'frame_mask': mask, 'frame_value': value,
            'fields': {fl['label']: (fl['hi'] - shift, fl['lo'] - shift) for fl in f['fields']},
            'lead': _lead(mask), 'fixed_bits': f['fixed_bits'],
            'uncertain': bool(f.get('unconfirmed_bits')), 'source': f.get('source'),
        })
    return types


TYPES = load()
_BY_NAME = {t['name']: t for t in TYPES}


def get_type(name):
    """-> the TYPES entry of that name, or None."""
    return _BY_NAME.get(name)


def frame_of(words):
    """-> the 48-bit frame of up to three words, most significant first, zero-padded."""
    frame = 0
    for i, word in enumerate(list(words)[:3]):
        frame |= (word & 0xFFFF) << (32 - 16 * i)
    return frame


def decode(words, types=None):
    """-> (entry or None, [candidate names]) for the instruction starting at words[0].

    The candidates are the forms that tie for the best match; the entry is None
    when no form matches or several tie."""
    frame = frame_of(words)
    hits = [t for t in (TYPES if types is None else types)
            if frame & t['frame_mask'] == t['frame_value']]
    if not hits:
        return None, []
    best = max(t['lead'] for t in hits)
    hits = [t for t in hits if t['lead'] == best]
    most = max(t['fixed_bits'] for t in hits)
    top = [t for t in hits if t['fixed_bits'] == most]
    return (top[0] if len(top) == 1 else None), [t['name'] for t in top]
