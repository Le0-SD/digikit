#!/usr/bin/env python3
"""Merge PRM figures and classic PGR tables into one instruction decode table.

Rules (see README "Findings"):
  * bit positions and field names come from the PRM figure;
  * fixed-bit VALUES come from the classic PGR wherever it has a table for the form,
    because several PRM figures carry stale template digits;
  * PRM-only forms (SHARC+ additions) take PRM values and are marked unconfirmed;
  * where the PRM draws a selector field over bits the PGR splits into two tables
    (e.g. Type 8a "r"), the field wins;
  * errata overrides are applied explicitly and listed in the output.

Frames are 48 bits, MSB aligned: a 16-bit form occupies bits 47..32, a 32-bit form
bits 47..16. VISA availability comes from the PRM headings ("ISA", "VISA", "ISA/VISA").
"""
import json
import re

prm = json.load(open("figures.json"))["figures"]
classic = json.load(open("classic.json"))

# PRM figure name -> classic table keys (a merged figure lists every classic variant).
PAIRS = {
    "Type1a": ["Type 1a"], "Type1b": ["Type 1b"], "Type2a": ["Type 2a"], "Type2b": ["Type 2b"], "Type2c": ["Type 2c"],
    "Type3a": ["Type 3a"], "Type3b": ["Type 3b"], "Type3c": ["Type 3c"], "Type4a": ["Type 4a"], "Type4b": ["Type 4b"],
    "Type5a_move": ["Type 5a"], "Type5a (swap)": ["Type 5a #2"], "Type5b (move)": ["Type 5b"], "Type5b (swap)": ["Type 5b #2"],
    # The PGR's second Type 6a table parses identically to the first, so the no-memory
    # form keeps its PRM fixed bits (see the "else" branch below).
    "Type6a (mem)": ["Type 6a"], "Type7a": ["Type 7a"], "Type7b": ["Type 7b"],
    # Type8a/9a/9b/10a are NOT merged via PAIRS -- see SPLIT_FORMS below: each
    # is a genuine absolute-or-indirect vs. PC-relative pair that must stay
    # two separate decode forms (merging them loses the addressing mode).
    "Type11a": ["Type 11a", "Type 11a #2"], "Type11c": ["Type 11c", "Type 11c #2"],
    "Type12a_imm": ["Type 12a"], "Type13a": ["Type 13a"], "Type14a": ["Type 14a"], "Type15a": ["Type 15a"], "Type15b": ["Type 15b"],
    "Type16a": ["Type 16a"], "Type16b": ["Type 16b"], "Type17a": ["Type 17a"], "Type17b": ["Type 17b"], "Type18a": ["Type 18a"],
    "Type19a": ["Type 19a"], "Type19a_bitrev": ["Type 19a #2"], "Type20a": ["Type 20a"], "Type21a": ["Type 21a"], "Type21c": ["Type 21c"],
    "Type22c": ["Type 22c"], "Type25a_direct": ["Type 25a"], "Type25a_pcrel": ["Type 25a #2"], "Type25c_rframe": ["Type 25c"],
}
ISA_ONLY = {"Type10a"}  # PRM heading "Type 10a ISA (...)"; every other form is ISA/VISA or VISA

# Forms where the PRM figure's fixed bits are correct and the PGR disagrees.
# Firmware decoding confirms the PRM value; the earlier "stale template digit"
# call against the PRM was wrong for these.
PRM_VALUE_WINS = {"Type2b"}

# Forms whose PRM figure prints a value for every bit: the instruction is the
# whole word, not a prefix. The classic PGR grid leaves the low bits blank, and
# the merge rule below treats a blank as "any value" -- which let Type21a match
# any first word 0x0000-0x007f and swallow the one or two short instructions
# after it (docs/FINDINGS.md, "Type21a is the all-zero word"). Figure 17-5
# draws Type21a as 48 zero bits and Figure 17-6 draws Type21c as 0x0001.
FULL_WORD = {
    "Type21a": (48, 0x000000000000),
    "Type21c": (16, 0x000100000000),
}

# Undocumented 16-bit instruction family, identified only from firmware.
# ADI's public PRM omits Type 23 and Type 24; the firmware contains a heavily-used
# 16-bit instruction with top-7 bits 0000001 and a 9-bit operand field (the word
# 0x023e alone occurs 329x in the DT2 image). No public figure documents it, so
# this entry carries a prefix and length only — no confirmed name or semantics.
# It exists so the decoder sizes these instructions correctly and stays in sync.
# Prefix width is deliberately a parameter so it can be re-tuned against the
# firmware; default top-7 bits = 0000001.
UNDOCUMENTED_16BIT = [
    {
        "name": "Type23p_undoc16",    # provisional; p = provisional
        "prefix_bits": "0000001",      # top bits, MSB-first, from bit47 down
        "note": "provisional, from firmware only (0x023e x329, top-7 0000001 "
                "family = 62% of unknowns)",
    },
    # The words Type21a used to swallow: with Type21a tightened to the all-zero
    # word, a first word whose top nine bits are zero and whose rest is not is
    # left over. 95% of the old Type21a matches are such words (859 of 904 in
    # Digitakt II 1.16), and treating them as one short instruction lands 86
    # more Type8a_rel branches on an instruction start. No public figure
    # documents them: prefix and length only, no name and no semantics.
    {
        "name": "Type21p_undoc16",
        "prefix_bits": "000000000",
        "note": "provisional, from firmware only (the old Type21a prefix; 95% "
                "of its matches are not the all-zero NOP word)",
    },
]

# ----------------------------------------------------------------------
# Absolute/PC-relative (or register-indirect/PC-relative) branch pairs.
# ----------------------------------------------------------------------
# classic.json (the classic PGR) keeps each of these as two SEPARATE tables
# (e.g. "Type 8a" and "Type 8a #2") that differ in exactly one selector bit
# ("r" for Type8a, "rel" for Type9a/9b/10a) plus, in the r=1/rel=1 table, a
# different meaning for one field. The PRM draws only ONE figure per type
# and shows that selector as an ordinary field, which is why the old PAIRS
# merge (see the generic loop below) collapsed both classic tables into a
# single decode form and lost the addressing-mode distinction: the merged
# "addr"/pmi+pmm field cannot represent both an absolute address and a
# signed PC-relative displacement. See FINDINGS.md / task report for the
# firmware evidence (branch-target landing rate) that this split is right.
#
#   shared_target=<label>  : Type8a only -- the merged figure's own field at
#                             that label literally means ADDR when the
#                             selector is 0 and RELADDR when it's 1 (same
#                             bit range either way), so the rel form is just
#                             the abs form's fields with that label renamed.
#   shared_target=None      : Type9a/9b/10a -- the merged figure only ever
#                             shows the selector=0 (register-indirect: PMI
#                             pointer register + PMM modify register)
#                             interpretation. The selector=1 form instead
#                             gets classic's own 6-bit RELADDR field, which
#                             occupies exactly the same bits as PMI+PMM
#                             (1 + 2 + 3 = 6 bits, confirmed against
#                             classic.json) but is unrelated to those
#                             registers -- it's a plain signed displacement.
SPLIT_FORMS = {
    "Type8a":  dict(abs_key="Type 8a", rel_key="Type 8a #2", selector="r", shared_target="addr"),
    "Type9a":  dict(abs_key="Type 9a", rel_key="Type 9a #2", selector="rel", shared_target=None),
    "Type9b":  dict(abs_key="Type 9b", rel_key="Type 9b #2", selector="rel", shared_target=None),
    "Type10a": dict(abs_key="Type 10a", rel_key="Type 10a #2", selector="rel", shared_target=None),
}
# Bit range of the register-indirect PMI/PMM fields in Type9a/9b/10a's merged
# PRM figure, which the rel=1 RELADDR field replaces (see shared_target=None
# above). Fixed across all three forms -- PMI/PMM always sit in the same
# frame-bit slot regardless of instruction width/type.
INDIRECT_REGISTER_LABELS = {"pmi[2:2]", "pmi[1:0]", "pmm[2:0]"}
RELADDR6_FIELDS = [{"label": "reladdr[5:5]", "hi": 32, "lo": 32}, {"label": "reladdr[4:0]", "hi": 31, "lo": 27}]


def fixed_bits_for(width, fields, keys):
    """Fixed-bit dict for a SINGLE classic.json table (`keys` has one entry):
    every bit position not claimed by a field, where that classic table
    marks a concrete 0/1 value. This is the same rule the generic multi-key
    merge below uses (a 1-element `variants` list trivially agrees with
    itself), factored out so split_branch_form can use it per variant."""
    variants = [rebase(classic[k]["pattern"], classic[k]["msb"]) for k in keys]
    field_bits = {b for fl in fields for b in range(fl["lo"], fl["hi"] + 1)}
    fixed = {}
    for b in range(47, 47 - width, -1):
        if b in field_bits:
            continue
        vals = {v.get(b) for v in variants}
        if len(vals) == 1 and vals <= {"0", "1"}:
            fixed[b] = int(vals.pop())
    return fixed


def make_form(name, width, fields, fixed, source):
    mask = sum(1 << b for b in fixed)
    value = sum(v << b for b, v in fixed.items())
    isa_only = name.split("_")[0] in ISA_ONLY
    return {
        "name": name, "width": width, "visa": not isa_only, "isa": width == 48,
        "mask": f"0x{mask:012x}", "value": f"0x{value:012x}", "fixed_bits": len(fixed),
        "fields": fields, "source": source, "unconfirmed_bits": 0,
    }


def split_branch_form(name, width, fields, cfg):
    """Split one PRM-merged branch figure into its classic-confirmed
    absolute-or-indirect (selector=0) and PC-relative (selector=1) forms.
    See SPLIT_FORMS above for the rationale."""
    common = [fl for fl in fields if fl["label"] != cfg["selector"]]

    if cfg["shared_target"]:
        base = cfg["shared_target"]
        abs_fields = common
        rel_fields = [
            dict(fl, label=fl["label"].replace(base, "reladdr", 1)) if fl["label"].startswith(base) else fl
            for fl in common
        ]
    else:
        abs_fields = common
        rel_fields = [fl for fl in common if fl["label"] not in INDIRECT_REGISTER_LABELS] + RELADDR6_FIELDS

    abs_fixed = fixed_bits_for(width, abs_fields, [cfg["abs_key"]])
    rel_fixed = fixed_bits_for(width, rel_fields, [cfg["rel_key"]])
    src = "pgr (split from merged PRM figure; see build_table.py SPLIT_FORMS)"
    return [
        make_form(f"{name}_abs", width, abs_fields, abs_fixed, src),
        make_form(f"{name}_rel", width, rel_fields, rel_fixed, src),
    ]


def prm_name(f):
    return re.sub(r"^Figure \d+-\d+:\s*", "", f["caption"]).replace(" Instruction", "").replace(" Opcode", "").replace(" Syntax", "").strip()


def rebase(pattern, msb):
    off = 47 - msb
    return {msb - i + off: ch for i, ch in enumerate(pattern)}


forms, notes = [], []
for f in prm:
    name = prm_name(f)
    if not name.startswith("Type"):
        continue
    width = f["width"]
    pb = rebase(f["pattern"], f["msb"])
    shift = 47 - f["msb"]
    fields = []
    for fl in f["fields"]:
        hi = fl["bits"][0] + shift
        lo = (fl["bits"][-1] if len(fl["bits"]) > 1 else fl["bits"][0]) + shift
        fields.append({"label": fl["label"], "hi": hi, "lo": lo})

    if name in SPLIT_FORMS:
        forms.extend(split_branch_form(name, width, fields, SPLIT_FORMS[name]))
        notes.append(f"{name}: split into {name}_abs/{name}_rel -- classic.json keeps these as "
                      "separate absolute-or-indirect/PC-relative tables; see SPLIT_FORMS")
        continue

    source = "prm"
    keys = PAIRS.get(name, [])

    # Errata overrides.
    if name == "Type3a":  # PRM figure is a copy of Type 1a
        c = classic["Type 3a"]
        pb = rebase(c["pattern"], c["msb"])
        fields = [{"label": cell["text"].lower().replace(" ", ""), "hi": cell["bits"][0], "lo": cell["bits"][1]}
                  for cell in c["cells"] if cell["kind"] == "field"]
        source, keys = "pgr (PRM figure is a copy of Type 1a)", []
        notes.append("Type3a: layout and values from PGR")
    if name == "Type25c_rframe":  # PRM figure is a copy of Type 25a rframe
        c = classic["Type 25c"]
        pb, width, fields = rebase(c["pattern"], c["msb"]), 16, []
        source, keys = "pgr (PRM figure is a copy of Type 25a rframe)", []
        notes.append("Type25c_rframe: 16-bit form from PGR")
    if name in PRM_VALUE_WINS:
        notes.append(f"{name}: fixed-bit values from PRM figure (overrides PGR; firmware-confirmed)")
    for fl in fields:
        if name == "Type4b" and fl["label"] == "dreg[6:0]":
            fl["label"] = "dreg[3:0]"
        if name == "Type17a" and fl["label"] == "i[2:0]":
            fl["label"] = "ureg[6:0]"
        fl["label"] = fl["label"].replace("data[5:5", "data[5:5]").replace("]]", "]")

    fixed = {}
    unconfirmed = []
    if keys and name not in PRM_VALUE_WINS:
        variants = [rebase(classic[k]["pattern"], classic[k]["msb"]) for k in keys]
        field_bits = {b for fl in fields for b in range(fl["lo"], fl["hi"] + 1)}
        for b in range(47, 47 - width, -1):
            vals = {v.get(b) for v in variants}
            if b in field_bits:
                continue
            if len(vals) == 1 and vals & {"0", "1"}:
                fixed[b] = int(vals.pop())
            elif pb.get(b) in ("0", "1") and vals <= {".", None}:
                # PRM shades a bit the PGR leaves blank: expected value, not used to match.
                pass
        source = "pgr values + prm layout"
    elif keys:  # PRM_VALUE_WINS: fixed bits from the PRM figure, not the PGR.
        field_bits = {b for fl in fields for b in range(fl["lo"], fl["hi"] + 1)}
        for b in range(47, 47 - width, -1):
            if b in field_bits:
                continue
            if pb.get(b) in ("0", "1"):
                fixed[b] = int(pb[b])
        source = "prm figure (overrides PGR; firmware-confirmed)"
    else:
        for b in range(47, 47 - width, -1):
            if pb.get(b) in ("0", "1"):
                fixed[b] = int(pb[b])
                if source == "prm":
                    unconfirmed.append(b)
    if name in FULL_WORD:
        full_width, word = FULL_WORD[name]
        fixed = {b: (word >> b) & 1 for b in range(48 - full_width, 48)}
        source = "prm figure (every bit printed; the PGR grid leaves them blank)"
    mask = sum(1 << b for b in fixed)
    value = sum(v << b for b, v in fixed.items())
    forms.append({
        "name": name, "width": width, "visa": name not in ISA_ONLY, "isa": width == 48,
        "mask": f"0x{mask:012x}", "value": f"0x{value:012x}", "fixed_bits": len(fixed),
        "fields": fields, "source": source, "unconfirmed_bits": len(unconfirmed),
    })

def undocumented_16bit_form(entry):
    prefix_bits = entry["prefix_bits"]
    mask = 0
    value = 0
    for i, ch in enumerate(prefix_bits):
        b = 47 - i
        mask |= 1 << b
        if ch == "1":
            value |= 1 << b
    fixed_bits = len(prefix_bits)
    fields = [{"label": f"operand[{15 - fixed_bits}:0]", "hi": 47 - fixed_bits, "lo": 32}]
    return {
        "name": entry["name"], "width": 16, "visa": True, "isa": False,
        "mask": f"0x{mask:012x}", "value": f"0x{value:012x}", "fixed_bits": fixed_bits,
        "fields": fields, "source": "firmware (undocumented; likely Type23/24; unconfirmed)",
        "unconfirmed_bits": fixed_bits,
    }


for entry in UNDOCUMENTED_16BIT:
    forms.append(undocumented_16bit_form(entry))
    notes.append(f"{entry['name']}: {entry['note']}")

json.dump({"forms": forms, "notes": notes}, open("decode_table.json", "w"), indent=1)
for fm in forms:
    flag = "  UNCONFIRMED" if fm["unconfirmed_bits"] else ""
    print(f"{fm['name']:18s} {fm['width']:2d}b visa={fm['visa']!s:5} mask {fm['mask']} value {fm['value']} ({fm['fixed_bits']} fixed) {fm['source']}{flag}")
