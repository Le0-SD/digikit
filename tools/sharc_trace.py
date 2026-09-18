"""Small, conservative delay-aware tracer for SHARC+ main-program code.

This intentionally follows exact short-word PCs, rather than discovering
functions or linearly sweeping unrelated bytes.  It is a first semantic slice:
unhandled forms stop a state instead of pretending to understand them.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Union

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from sharc_disasm import Instruction, decode_loaded_at, disassemble
from sharcimm import name_address
from sharcldr import SW_ALIAS_BASE, LoadedMemory, sw_to_byte

UREG_NAMES = tuple(
    [f"R{i}" for i in range(16)]
    + [f"I{i}" for i in range(16)]
    + [f"M{i}" for i in range(16)]
    + [f"L{i}" for i in range(16)]
    + [f"B{i}" for i in range(16)]
    + [f"S{i}" for i in range(16)]
    + [
        "FADDR",
        "DADDR",
        "UREG_RESERVED_62",
        "PC",
        "PCSTK",
        "PCSTKP",
        "LADDR",
        "CURLCNTR",
        "LCNTR",
        "EMUCLK",
        "EMUCLK2",
        "PX",
        "PX1",
        "PX2",
        "TPERIOD",
        "TCOUNT",
        "USTAT1",
        "USTAT2",
        "MODE1",
        "MMASK",
        "MODE2",
        "FLAGS",
        "ASTATX",
        "ASTATY",
        "STKYX",
        "STKYY",
        "IRPTL",
        "IMASK",
        "IMASKP",
        "MODE1STK",
        "USTAT3",
        "USTAT4",
    ]
)
UREG_CODES = {name: code for code, name in enumerate(UREG_NAMES)}

# Public SHARC+ register tables document these reset values.  Keep this list
# deliberately bounded to core state used by startup rather than treating
# every absent UREG as zero.
CORE_UREG_RESET_VALUES = {
    name: 0
    for name in (
        "MODE1",
        "MMASK",
        "MODE1STK",
        "MODE2",
        "PCSTK",
        "PCSTKP",
        "LADDR",
        "LCNTR",
        "CURLCNTR",
        "ASTATX",
        "ASTATY",
        "STKYX",
        "STKYY",
        "IRPTL",
        "IMASK",
        "IMASKP",
    )
}
CORE_MMR_RESET_VALUES = {
    0x30024: 0,  # CMMR_SYSCTL
    0x31400: 0,  # SHBTB_CFG
    0x31401: 0,  # SHBTB_LOCK_START
    0x31402: 0,  # SHBTB_LOCK_END
    0x3E000: 0,  # SHL1C_CFG
    0x3E002: 0,  # SHL1C_CFG2
}

# ADSP-2156x L1 block 3 aliases.  The normal-word window is the one used by
# the reset path's PM(...)=PX table read; the loader records the same physical
# storage through the short-word/system-byte view.
L1_BLOCK3_NW_BASE = 0x000E0000
L1_BLOCK3_NW_LIMIT = 0x000E8000
L1_BLOCK3_SW_BASE = 0x001C0000


@dataclass(frozen=True)
class Const:
    value: int

    def __post_init__(self):
        object.__setattr__(self, "value", self.value & 0xFFFFFFFF)


@dataclass(frozen=True)
class Affine:
    """A canonical 32-bit affine expression, constant plus named terms."""

    constant: int
    terms: tuple[tuple[str, int], ...]

    def __post_init__(self):
        coefficients: dict[str, int] = {}
        for name, coefficient in self.terms:
            if not _SYMBOL_RE.fullmatch(name):
                raise ValueError("invalid symbol name: " + repr(name))
            coefficients[name] = (coefficients.get(name, 0) + coefficient) & 0xFFFFFFFF
        object.__setattr__(self, "constant", self.constant & 0xFFFFFFFF)
        object.__setattr__(
            self,
            "terms",
            tuple(
                sorted(
                    (name, coefficient)
                    for name, coefficient in coefficients.items()
                    if coefficient
                )
            ),
        )


@dataclass(frozen=True)
class Unknown:
    reason: str


Value = Union[Const, Affine, Unknown]
_SYMBOL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _affine(constant: int, terms: tuple[tuple[str, int], ...]) -> Const | Affine:
    """Build a canonical affine value, collapsing a constant expression."""
    value = Affine(constant, terms)
    return Const(value.constant) if not value.terms else value


def symbol(name: str) -> Affine:
    """Return the named symbolic value NAME."""
    if not _SYMBOL_RE.fullmatch(name):
        raise ValueError("invalid symbol name: " + repr(name))
    return Affine(0, ((name, 1),))


@dataclass(frozen=True)
class Pending:
    # A None target marks the delay slots of a conditional transfer not taken.
    target: Optional[int]
    call: bool = False
    slots: int = 2
    return_from_call: bool = False
    return_sw: Optional[int] = None


@dataclass(frozen=True)
class Loop:
    start_sw: int
    end_sw: int
    remaining: int
    mode: int


@dataclass
class State:
    pc_sw: int
    uregs: Dict[int, Value] = field(default_factory=dict)
    trace: List[dict] = field(default_factory=list)
    pending: Optional[Pending] = None
    steps: int = 0
    stopped: Optional[str] = None
    # Concrete mode is deliberately loader-only.  OVERLAY is per path, so a
    # conditional fork cannot mutate another path or the immutable boot image.
    concrete: Optional[LoadedMemory] = None
    overlay: Dict[int, int] = field(default_factory=dict)
    base_sw: Optional[int] = None
    follow_loaded_calls: bool = False
    continue_external_calls: bool = False
    dossier_bytes: int = 0
    max_call_depth: int = 0
    call_stack: List[int] = field(default_factory=list)
    skip_provisional_entries: bool = False
    at_loaded_entry: bool = False
    assume_nw32: bool = False
    loops: List[Loop] = field(default_factory=list)
    status_stack: List[tuple[Value, Value, Value]] = field(default_factory=list)
    core_reset_state: bool = False
    mmrs: Dict[int, Value] = field(default_factory=dict)
    data_memory_tainted: bool = False


def _signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _field(f: Mapping[str, int], stem: str) -> int:
    for key, value in f.items():
        if key == stem or key.startswith(stem + "["):
            return value
    raise KeyError(stem)


def _wide(f: Mapping[str, int], stem: str) -> int:
    return (_field(f, stem + "[31:16]") << 16) | _field(f, stem + "[15:0]")


def _signed32(value: int) -> int:
    return _signed(value & 0xFFFFFFFF, 32)


def _render(value: Value | int) -> str:
    if isinstance(value, Const):
        return _render(value.value)
    if isinstance(value, Affine):
        parts: list[tuple[int, str]] = []
        for name, coefficient in value.terms:
            coefficient = _signed32(coefficient)
            magnitude = (
                name if abs(coefficient) == 1 else "%d*%s" % (abs(coefficient), name)
            )
            parts.append((coefficient, magnitude))
        constant = _signed32(value.constant)
        if constant:
            parts.append((constant, hex(abs(constant))))
        if not parts:
            return "0x0"
        first_sign, first = parts[0]
        rendered = ("-" if first_sign < 0 else "") + first
        for sign, magnitude in parts[1:]:
            rendered += (" - " if sign < 0 else " + ") + magnitude
        return rendered
    if isinstance(value, Unknown):
        return value.reason
    return ("-" if value < 0 else "") + hex(abs(value))


def _json_value(value: Value | int) -> int | dict:
    """Render tracer values without leaking internal dataclasses into CLI JSON."""
    if isinstance(value, Const):
        return value.value
    if isinstance(value, Affine):
        return {
            "affine": {
                "constant": value.constant,
                "terms": [list(term) for term in value.terms],
            }
        }
    if isinstance(value, Unknown):
        return {"unknown": value.reason}
    return value


def _event(state: State, insn: Instruction, action: str, **extra) -> None:
    for key in ("address", "value", "concrete_value"):
        if key in extra:
            extra[key] = _json_value(extra[key])
    state.trace.append(
        {"pc_sw": state.pc_sw, "form": insn.type_name, "action": action, **extra}
    )


def _stop(state: State, insn: Optional[Instruction], reason: str) -> State:
    form = insn.type_name if insn else None
    state.trace.append(
        {"pc_sw": state.pc_sw, "form": form, "action": "stop", "reason": reason}
    )
    state.stopped = reason
    return state


def _copy(state: State) -> State:
    return State(
        state.pc_sw,
        dict(state.uregs),
        [dict(event) for event in state.trace],
        state.pending,
        state.steps,
        state.stopped,
        state.concrete,
        dict(state.overlay),
        state.base_sw,
        state.follow_loaded_calls,
        state.continue_external_calls,
        state.dossier_bytes,
        state.max_call_depth,
        list(state.call_stack),
        state.skip_provisional_entries,
        state.at_loaded_entry,
        state.assume_nw32,
        list(state.loops),
        list(state.status_stack),
        state.core_reset_state,
        dict(state.mmrs),
        state.data_memory_tainted,
    )


def _concrete_address(value: Value | int) -> Optional[int]:
    return (
        value.value
        if isinstance(value, Const)
        else (value if isinstance(value, int) else None)
    )


def _canonical_dm_address(
    state: State, address: int, width: int, *, for_write: bool = False
) -> Optional[int]:
    """Resolve a DSP DM address to the loader's byte-address alias.

    Application code uses unaliased DM pointers such as ``0x26968c`` whereas
    the boot stream is keyed at ``SW_ALIAS_BASE + 0x26968c``.  Keep an already
    mapped direct address (notably external memory and MMRs) unchanged; only
    retry an unmapped low address through the alias.
    """
    concrete = state.concrete
    if concrete is None:
        return None

    def mapped(base: int) -> bool:
        return all(
            here in state.overlay or concrete.read(here, 1) is not None
            for here in range(base, base + width)
        )

    if mapped(address):
        return address
    if 0 <= address < SW_ALIAS_BASE:
        alias = SW_ALIAS_BASE + address
        if for_write or mapped(alias):
            return alias
    # Runtime RAM and MMR destinations need not have loader initializer bytes.
    # A concrete write creates those bytes in this path's overlay.
    return address if for_write else None


def _dm_read(
    state: State, address: Value | int, width: int, signed: bool = False
) -> Optional[Const]:
    """Read little-endian loader-backed DM bytes plus this path's overlay."""
    concrete = _concrete_address(address)
    if state.concrete is None or concrete is None or width not in (1, 2, 4, 8):
        return None
    fixed_width_mmr = (
        concrete in CORE_MMR_RESET_VALUES or name_address(concrete) is not None
    )
    if width == 4 and fixed_width_mmr and concrete in state.mmrs:
        value = state.mmrs[concrete]
        return value if isinstance(value, Const) else None
    if width == 4 and fixed_width_mmr and state.data_memory_tainted:
        return None
    if (
        width == 4
        and not state.assume_nw32
        and not fixed_width_mmr
        and not 0x30000000 <= concrete < 0x40000000
    ):
        # Internal normal-word width depends on runtime IMDWx state.  Reading
        # four loader bytes as one word is opt-in until that state is known.
        return None
    concrete = _canonical_dm_address(state, concrete, width)
    if concrete is None:
        return None
    if state.data_memory_tainted and not all(
        here in state.overlay for here in range(concrete, concrete + width)
    ):
        return None
    backing = state.concrete
    assert backing is not None
    raw = bytearray()
    for here in range(concrete, concrete + width):
        if here in state.overlay:
            raw.append(state.overlay[here])
        else:
            byte = backing.read(here, 1)
            assert byte is not None
            raw.append(byte[0])
    value = int.from_bytes(raw, "little", signed=signed)
    # A long word needs a register pair, which this tracer intentionally does
    # not model.  Do not truncate it into a false 32-bit value.
    return Const(value) if width <= 4 else None


def _read_px48(state: State, address: Value | int) -> Optional[tuple[Const, Const]]:
    """Read a loader-backed 48-bit normal word into the PX1/PX2 halves.

    A combined-PX DM or PM transfer without ``LW`` is 48 bits.  L1 block 3's
    normal-word alias packs those words in three 16-bit columns, while loader
    records use the short-word/system-byte view.  Each 48-bit word therefore
    consumes six loader bytes.  The three parcels are individually little-
    endian, but retain their architectural high-to-low order.
    """
    concrete = _concrete_address(address)
    if (
        state.concrete is None
        or concrete is None
        or not L1_BLOCK3_NW_BASE <= concrete < L1_BLOCK3_NW_LIMIT
    ):
        return None
    offset = concrete - L1_BLOCK3_NW_BASE
    byte_address = sw_to_byte(L1_BLOCK3_SW_BASE) + 6 * offset
    raw = state.concrete.read(byte_address, 6)
    if raw is None:
        return None
    high, middle, low = (
        int.from_bytes(raw[start : start + 2], "little") for start in (0, 2, 4)
    )
    px2 = Const((high << 16) | middle)
    px1 = Const(low << 16)
    return px1, px2


def _load_normal_ureg(
    state: State, space: str, address: Value | int, code: int
) -> Optional[Const | dict[str, int]]:
    """Load one normal-word UREG value, including combined-PX DM/PM reads."""
    if code == UREG_CODES["PX"]:
        halves = _read_px48(state, address)
        if halves is not None:
            px1, px2 = halves
            state.uregs[UREG_CODES["PX"]] = Unknown(
                "combined PX represented by PX1/PX2"
            )
            state.uregs[UREG_CODES["PX1"]] = px1
            state.uregs[UREG_CODES["PX2"]] = px2
            return {"PX1": px1.value, "PX2": px2.value}
        state.uregs[UREG_CODES["PX1"]] = Unknown("memory-address " + _render(address))
        state.uregs[UREG_CODES["PX2"]] = Unknown("memory-address " + _render(address))
    elif space == "DM":
        loaded = _dm_read(state, address, 4)
        state.uregs[code] = loaded or Unknown("memory-address " + _render(address))
        return loaded
    state.uregs[code] = Unknown("memory-address " + _render(address))
    return None


def _dm_write(state: State, address: Value | int, width: int, value: Value) -> bool:
    concrete = _concrete_address(address)
    if (
        state.concrete is None
        or concrete is None
        or not isinstance(value, Const)
        or width not in (1, 2, 4)
    ):
        return False
    fixed_width_mmr = (
        concrete in CORE_MMR_RESET_VALUES or name_address(concrete) is not None
    )
    if width == 4 and fixed_width_mmr:
        state.mmrs[concrete] = value
        return True
    if (
        width == 4
        and not state.assume_nw32
        and not fixed_width_mmr
        and not 0x30000000 <= concrete < 0x40000000
    ):
        return False
    concrete = _canonical_dm_address(state, concrete, width, for_write=True)
    if concrete is None:
        return False
    raw = (value.value & 0xFFFFFFFF).to_bytes(4, "little")[:width]
    state.overlay.update(zip(range(concrete, concrete + width), raw))
    return True


def _dossier(state: State, target: int, return_sw: int) -> dict:
    registers = {
        UREG_NAMES[k]: _json_value(v)
        for k, v in state.uregs.items()
        if isinstance(v, Const)
    }
    objects = []
    if state.concrete is not None and state.dossier_bytes:
        seen = set()
        for name, value in registers.items():
            if not isinstance(value, int) or value in seen:
                continue
            raw = bytearray()
            for offset in range(state.dossier_bytes):
                b = _dm_read(state, value + offset, 1)
                if b is None:
                    break
                raw.append(b.value)
            if raw:
                seen.add(value)
                objects.append(
                    {
                        "register": name,
                        "address": value,
                        "bytes": list(raw),
                        "words_le": [
                            int.from_bytes(raw[i : i + 4], "little")
                            for i in range(0, len(raw) - 3, 4)
                        ],
                    }
                )
    return {
        "target_sw": target,
        "return_sw": return_sw,
        "registers": registers,
        "objects": objects,
    }


def _ureg(values: Mapping[int, Value], code: int) -> Value:
    return values.get(code, Unknown("uninitialized " + UREG_NAMES[code]))


def _terms(value: Const | Affine) -> tuple[int, tuple[tuple[str, int], ...]]:
    return (
        (value.value, ()) if isinstance(value, Const) else (value.constant, value.terms)
    )


def _add(left: Value, right: Value, expression: str) -> Value:
    if isinstance(left, Unknown) or isinstance(right, Unknown):
        return Unknown(expression)
    constant, terms = _terms(left)
    other_constant, other_terms = _terms(right)
    return _affine(constant + other_constant, terms + other_terms)


def _negate(value: Value, expression: str) -> Value:
    if isinstance(value, Unknown):
        return Unknown(expression)
    constant, terms = _terms(value)
    return _affine(
        -constant, tuple((name, -coefficient) for name, coefficient in terms)
    )


def _subtract(left: Value, right: Value, expression: str) -> Value:
    return _add(left, _negate(right, expression), expression)


def _multiply(left: Value, right: Value, expression: str) -> Value:
    if isinstance(left, Unknown) or isinstance(right, Unknown):
        return Unknown(expression)
    if isinstance(left, Const) and isinstance(right, Const):
        return Const(left.value * right.value)
    if isinstance(left, Const):
        constant, terms = _terms(right)
        return _affine(
            left.value * constant,
            tuple((name, left.value * coefficient) for name, coefficient in terms),
        )
    if isinstance(right, Const):
        constant, terms = _terms(left)
        return _affine(
            right.value * constant,
            tuple((name, right.value * coefficient) for name, coefficient in terms),
        )
    return Unknown(expression + " (non-affine multiplication)")


def _access_modifier_scale(access_width: str, assume_nw32: bool) -> int:
    """Return SHARC+ byte-space scaled-address arithmetic width."""
    if access_width.startswith("short-word"):
        return 2
    if access_width == "long-word":
        return 8
    if access_width == "normal-word" and assume_nw32:
        return 4
    return 1


def _bitwise(left: Value, right: Value, expression: str, operation) -> Value:
    if isinstance(left, Const) and isinstance(right, Const):
        return Const(operation(left.value, right.value))
    return Unknown(expression)


def _sync_pc_stack(state: State) -> None:
    """Mirror the tracer's architectural PC stack into its public registers."""
    state.uregs[UREG_CODES["PCSTKP"]] = Const(len(state.call_stack))
    state.uregs[UREG_CODES["PCSTK"]] = (
        Const(state.call_stack[-1]) if state.call_stack else Const(0x7FFFFFFF)
    )
    stkyx_code = UREG_CODES["STKYX"]
    state.uregs[stkyx_code] = _bitwise(
        _ureg(state.uregs, stkyx_code),
        Const(1 << 22),
        "PC stack empty" if not state.call_stack else "PC stack nonempty",
        (lambda value, mask: value | mask)
        if not state.call_stack
        else (lambda value, mask: value & ~mask),
    )


def _shift_immediate(
    f: Mapping[str, int], values: Mapping[int, Value]
) -> tuple[int, Value, str]:
    """Execute the documented ShiftImm subset seen on qualifying paths."""
    field = (_field(f, "shiftimm[22:16]") << 16) | _field(f, "shiftimm[15:0]")
    opcode = (field >> 16) & 0x3F
    data8 = (field >> 8) & 0xFF
    rn, rx = (field >> 4) & 0xF, field & 0xF
    source = _ureg(values, rx)
    if opcode in (0x00, 0x01):
        amount = _signed(data8, 8)
        name = "lshift" if opcode == 0x00 else "ashift"
        if amount == 0:
            value = source
        elif not isinstance(source, Const):
            value = Unknown("%s R%d by %d" % (name, rx, amount))
        elif amount >= 32:
            value = Const(0)
        elif amount <= -32:
            value = (
                Const(0xFFFFFFFF)
                if opcode == 0x01 and source.value & 0x80000000
                else Const(0)
            )
        elif amount > 0:
            value = Const(source.value << amount)
        elif opcode == 0x01:
            value = Const(_signed32(source.value) >> -amount)
        else:
            value = Const(source.value >> -amount)
        operation = (
            "logical-shift-immediate"
            if opcode == 0x00
            else "arithmetic-shift-immediate"
        )
        return rn, value, operation
    if opcode == 0x10:
        position = data8 & 0x3F
        length = (_field(f, "dataex[3:0]") << 2) | (data8 >> 6)
        if length == 0:
            value = Const(0)
        elif not isinstance(source, Const):
            value = Unknown("fext R%d by %d:%d" % (rx, position, length))
        else:
            value = Const((source.value >> position) & ((1 << min(length, 32)) - 1))
        return rn, value, "field-extract-immediate"
    if opcode in (0x30, 0x31):
        position = data8
        if position > 31:
            value = source
        else:
            calculate = (
                (lambda a, b: a | b) if opcode == 0x30 else (lambda a, b: a & ~b)
            )
            name = "bset" if opcode == 0x30 else "bclr"
            value = _bitwise(
                source,
                Const(1 << position),
                "%s R%d by %d" % (name, rx, position),
                calculate,
            )
        operation = "bit-set-immediate" if opcode == 0x30 else "bit-clear-immediate"
        return rn, value, operation
    raise ValueError("unsupported ShiftImm opcode %#x" % opcode)


def _not(value: Value, expression: str) -> Value:
    return Const(~value.value) if isinstance(value, Const) else Unknown(expression)


def _compute(
    f: Mapping[str, int], short: bool, values: Mapping[int, Value]
) -> Optional[tuple[int, Value, str]]:
    """Decode the small public-table subset, reading every operand from VALUES."""
    field = (
        _field(f, "compute")
        if short
        else ((_field(f, "compute[22:16]") << 16) | _field(f, "compute[15:0]"))
    )
    if not short and field == 0:
        return None
    if short:
        opcode, rn, rx = (field >> 8) & 0xF, (field >> 4) & 0xF, field & 0xF
        left, right = _ureg(values, rn), _ureg(values, rx)
        operations = {
            0: ("add", lambda: _add(left, right, "R%d + R%d" % (rn, rx))),
            1: ("subtract", lambda: _subtract(left, right, "R%d - R%d" % (rn, rx))),
            2: ("pass", lambda: right),
            4: (
                "not",
                lambda: _not(right, "not R%d" % rx),
            ),
            5: ("increment", lambda: _add(right, Const(1), "R%d + 1" % rx)),
            6: ("decrement", lambda: _add(right, Const(-1), "R%d - 1" % rx)),
            7: (
                "multiply",
                lambda: _multiply(left, right, "R%d * R%d" % (rn, rx)),
            ),
            0xC: (
                "and",
                lambda: _bitwise(
                    left, right, "R%d and R%d" % (rn, rx), lambda a, b: a & b
                ),
            ),
            0xD: (
                "or",
                lambda: _bitwise(
                    left, right, "R%d or R%d" % (rn, rx), lambda a, b: a | b
                ),
            ),
            0xE: (
                "xor",
                lambda: _bitwise(
                    left, right, "R%d xor R%d" % (rn, rx), lambda a, b: a ^ b
                ),
            ),
        }
        if opcode == 3:
            return rn, left, "compare"
        if opcode not in operations:
            raise ValueError("unsupported short compute opcode %#x" % opcode)
        operation, calculate = operations[opcode]
        return rn, calculate(), operation
    cu, opcode = (field >> 20) & 3, (field >> 12) & 0xFF
    rn, rx, ry = (field >> 8) & 0xF, (field >> 4) & 0xF, field & 0xF
    left, right = _ureg(values, rx), _ureg(values, ry)
    # PRM Table 17-5: ALUOP 00000001/00000010 are add/subtract.
    if cu == 0 and opcode == 0x01:
        value = _add(left, right, "R%d + R%d" % (rx, ry))
        return rn, value, "add"
    if cu == 0 and opcode == 0x02:
        value = _subtract(left, right, "R%d - R%d" % (rx, ry))
        return rn, value, "subtract"
    # PRM Table 18-5: ALUOP 00001010 is signed comp(RX, RY). It updates
    # status only, so the tracer records the comparison without writing RN.
    if cu == 0 and opcode == 0x0A:
        return rn, left, "compare"
    if cu == 0 and opcode == 0x21:
        return rn, left, "pass"
    if cu == 0 and opcode == 0x29:
        return rn, _add(left, Const(1), "R%d + 1" % rx), "increment"
    # PRM Table 18-5 and p. 19-9: ALUOP 00101010 is RN = RX - 1.
    if cu == 0 and opcode == 0x2A:
        return rn, _add(left, Const(-1), "R%d - 1" % rx), "decrement"
    if cu == 1 and opcode == 0x70:
        value = _multiply(left, right, "R%d * R%d" % (rx, ry))
        return rn, value, "multiply"
    # PRM Table 17-9: SHIFTOP 00000000 is RN = LSHIFT RX by RY. The signed
    # low byte of RY selects a left (positive) or logical right (negative)
    # shift; magnitudes of 32 or more produce zero.
    if cu == 2 and opcode == 0x00:
        if not isinstance(right, Const):
            value = Unknown("lshift R%d by R%d" % (rx, ry))
        else:
            amount = _signed(right.value & 0xFF, 8)
            if amount == 0:
                value = left
            elif not isinstance(left, Const):
                value = Unknown("lshift R%d by %d" % (rx, amount))
            elif amount >= 32 or amount <= -32:
                value = Const(0)
            elif amount > 0:
                value = Const(left.value << amount)
            else:
                value = Const(left.value >> -amount)
        return rn, value, "logical-shift"
    # PRM Table 17-9: SHIFTOP 10001000 is RN = leftz RX.
    if cu == 2 and opcode == 0x88:
        value = (
            Const(32 if left.value == 0 else 32 - left.value.bit_length())
            if isinstance(left, Const)
            else Unknown("leftz R%d" % rx)
        )
        return rn, value, "leftz"
    # PRM Table 17-9 and p. 23-5: SHIFTOP 11001000 is
    # RN = btgl RX by RY.  Positions outside the 32-bit field leave RX
    # unchanged.
    if cu == 2 and opcode == 0xC8:
        if not isinstance(right, Const):
            value = Unknown("btgl R%d by R%d" % (rx, ry))
        elif right.value > 31:
            value = left
        else:
            value = _bitwise(
                left,
                Const(1 << right.value),
                "btgl R%d by R%d" % (rx, ry),
                lambda a, b: a ^ b,
            )
        return rn, value, "bit-toggle"
    # PRM Table 18-9 and pp. 24-5--24-6: SHIFTOP 11001100 is
    # btst RX by RY. It changes status flags only and has no RN result.
    if cu == 2 and opcode == 0xCC:
        return rn, left, "bit-test"
    raise ValueError("unsupported full compute cu=%#x opcode=%#x" % (cu, opcode))


def _apply_compute(
    state: State, insn: Instruction, result: tuple[int, Value, str]
) -> None:
    rn, value, operation = result
    if operation == "pass":
        astatx_code = UREG_CODES["ASTATX"]
        astatx = _ureg(state.uregs, astatx_code)
        if isinstance(value, Const) and isinstance(astatx, Const):
            # Fixed-point PASS updates the six ALU flags: AC/AI/AS/AV are
            # cleared, AN reflects bit 31, and AZ reflects a zero result.
            flags = (0x4 if value.value & 0x80000000 else 0) | (
                0x1 if value.value == 0 else 0
            )
            state.uregs[astatx_code] = Const((astatx.value & ~0x3F) | flags)
        else:
            state.uregs[astatx_code] = Unknown("pass ASTATX flags")
    elif operation == "compare":
        # The value result is sufficient for dataflow, but the tracer does not
        # yet model all subtraction flags. Do not let a stale AZ drive EQ/NE.
        state.uregs[UREG_CODES["ASTATX"]] = Unknown("compare ASTATX flags")
    if operation in ("compare", "bit-test"):
        _event(state, insn, "compute", operation=operation, status_only=True)
    else:
        _event(state, insn, "compute", operation=operation, result_register="R%d" % rn)
        state.uregs[rn] = value


def decode_at(
    data: bytes | LoadedMemory, base_sw: Optional[int], pc_sw: int
) -> Instruction:
    """Decode exactly at PC_SW from a flat image or loader-backed memory."""
    if isinstance(data, LoadedMemory):
        return decode_loaded_at(data, pc_sw)
    if base_sw is None:
        raise ValueError("base_sw is required for flat image decoding")
    offset = (pc_sw - base_sw) * 2
    if offset < 0 or offset >= len(data):
        return Instruction(
            offset, None, "unknown", kind="unknown", note="PC outside image"
        )
    return next(disassemble(data, start_offset=offset, count=1))


def _advance(state: State, insn: Instruction) -> List[State]:
    state.steps += 1
    if insn.length_bytes is None:
        raise ValueError("cannot advance an instruction without a decoded length")
    next_pc = state.pc_sw + insn.length_bytes // 2
    if state.pending is None:
        if state.loops and state.pc_sw == state.loops[-1].end_sw:
            loop = state.loops[-1]
            remaining = loop.remaining - 1
            state.uregs[UREG_CODES["CURLCNTR"]] = Const(max(remaining, 0))
            if remaining > 0:
                _event(
                    state,
                    insn,
                    "loop-back",
                    target_sw=loop.start_sw,
                    remaining=remaining,
                    mode=loop.mode,
                )
                state.loops[-1] = Loop(loop.start_sw, loop.end_sw, remaining, loop.mode)
                state.pc_sw = loop.start_sw
                return [state]
            _event(state, insn, "loop-exit", remaining=0, mode=loop.mode)
            state.loops.pop()
            if not state.call_stack or state.call_stack[-1] != loop.start_sw:
                return [_stop(state, insn, "loop PC-stack mismatch")]
            state.call_stack.pop()
            _sync_pc_stack(state)
            state.uregs[UREG_CODES["CURLCNTR"]] = (
                Const(state.loops[-1].remaining) if state.loops else Const(0xFFFFFFFF)
            )
            if not state.loops:
                stkyx_code = UREG_CODES["STKYX"]
                state.uregs[stkyx_code] = _bitwise(
                    _ureg(state.uregs, stkyx_code),
                    Const(1 << 26),
                    "loop stacks empty",
                    lambda a, b: a | b,
                )
        state.pc_sw = next_pc
        return [state]
    p = state.pending
    if p.slots == 1:
        if p.return_from_call:
            if not state.call_stack:
                return [_stop(state, insn, "return without followed call")]
            if state.loops and state.call_stack[-1] == state.loops[-1].start_sw:
                return [_stop(state, insn, "return reached loop PC-stack entry")]
            state.pc_sw = state.call_stack.pop()
            _sync_pc_stack(state)
            state.pending = None
            _event(state, insn, "loaded-call-return", return_sw=state.pc_sw)
            return [state]
        if p.call:
            if p.target is None:
                return [_stop(state, insn, "call without target")]
            target = p.target
            loaded = False
            if (
                state.follow_loaded_calls
                and state.concrete is not None
                and target is not None
                and target >= 0
            ):
                decoded = decode_at(state.concrete, None, target)
                loaded = decoded.kind != "unknown"
            if loaded:
                followed_depth = len(state.call_stack) - len(state.loops)
                if followed_depth >= state.max_call_depth:
                    return [_stop(state, insn, "max-call-depth")]
                return_sw = p.return_sw
                if return_sw is None:
                    return [_stop(state, insn, "call without architectural return")]
                state.call_stack.append(return_sw)
                _sync_pc_stack(state)
                state.pending = None
                state.pc_sw = target
                state.at_loaded_entry = True
                _event(
                    state,
                    insn,
                    "loaded-call-enter",
                    target_sw=target,
                    return_sw=return_sw,
                )
                return [state]
            return_sw = p.return_sw
            if return_sw is None:
                return [_stop(state, insn, "call without architectural return")]
            dossier = _dossier(state, target, return_sw)
            if not state.continue_external_calls:
                _stop(state, insn, "external-call")
                # The default endpoint remains the historical stop event; its
                # dossier explicitly labels the otherwise opaque boundary.
                state.trace[-1].update(dossier)
                state.trace[-1]["opaque_external_call"] = True
                return [state]
            _event(state, insn, "opaque-external-call", **dossier)
            # Conservative ABI boundary: results can be clobbered; memory and
            # pointer arguments are deliberately untouched.
            for code in range(16):
                state.uregs[code] = Unknown("opaque-external-call result")
            state.pending = None
            state.pc_sw = return_sw
            _event(
                state,
                insn,
                "external-call-continue",
                clobbered=["R%d" % n for n in range(16)],
            )
            return [state]
        state.pending = None
        state.pc_sw = next_pc if p.target is None else p.target
        return [state]
    state.pending = Pending(
        p.target, p.call, p.slots - 1, p.return_from_call, p.return_sw
    )
    state.pc_sw = next_pc
    return [state]


def _predicate(state: State, cond: int) -> Optional[bool]:
    if cond == 0x1F:
        return True
    if cond in (0x00, 0x10):
        # Conditional branches in SIMD mode combine the PEx/PEy conditions.
        # The tracer does not yet model the companion PASS, so only consume
        # AZ when execution is concretely SISD.
        mode1 = _ureg(state.uregs, UREG_CODES["MODE1"])
        astatx = _ureg(state.uregs, UREG_CODES["ASTATX"])
        if (
            not isinstance(mode1, Const)
            or mode1.value & (1 << 21)
            or not isinstance(astatx, Const)
        ):
            return None
        equal = bool(astatx.value & 1)
        return equal if cond == 0x00 else not equal
    if cond in (0x0D, 0x1D):
        astatx = _ureg(state.uregs, UREG_CODES["ASTATX"])
        if not isinstance(astatx, Const):
            return None
        bit_test = bool(astatx.value & (1 << 18))
        return bit_test if cond == 0x0D else not bit_test
    return None


def _transfer(
    state: State, insn: Instruction, target: int, call: bool, cond: Optional[bool]
) -> List[State]:
    if state.pending:
        return [_stop(state, insn, "nested delayed transfer")]
    if insn.length_bytes is None:
        raise ValueError("cannot transfer from an instruction without a decoded length")
    fall = state.pc_sw + insn.length_bytes // 2
    _event(state, insn, "call" if call else "branch", target_sw=target, predicate=cond)
    state.steps += 1
    if cond is False:
        state.pc_sw = fall
        return [state]
    # A delayed CALL always records the seventh short-word address after the
    # call as its return, independent of the widths of its two delay slots.
    return_sw = state.pc_sw + 7 if call else None
    if cond is True:
        state.pc_sw, state.pending = fall, Pending(target, call, return_sw=return_sw)
        return [state]
    taken, not_taken = _copy(state), _copy(state)
    taken.pc_sw, taken.pending = fall, Pending(target, call, return_sw=return_sw)
    not_taken.pc_sw, not_taken.pending = fall, Pending(None)
    not_taken.trace[-1]["action"] = "branch-not-taken"
    return [taken, not_taken]


def _immediate_transfer(
    state: State, insn: Instruction, target: int, call: bool, cond: Optional[bool]
) -> List[State]:
    """Execute a Type 8 transfer without the instruction's DB modifier."""
    if state.pending:
        return [_stop(state, insn, "nested delayed transfer")]
    if insn.length_bytes is None:
        raise ValueError("cannot transfer from an instruction without a decoded length")
    fall = state.pc_sw + insn.length_bytes // 2
    _event(state, insn, "call" if call else "branch", target_sw=target, predicate=cond)
    if cond is False:
        return _advance(state, insn)
    if cond is True:
        state.pending = Pending(target, call, slots=1, return_sw=fall if call else None)
        return _advance(state, insn)
    taken, not_taken = _copy(state), _copy(state)
    taken.pending = Pending(target, call, slots=1, return_sw=fall if call else None)
    not_taken.trace[-1]["action"] = "branch-not-taken"
    return _advance(taken, insn) + _advance(not_taken, insn)


def _return_transfer(
    state: State, insn: Instruction, predicate: Optional[bool], delayed: bool
) -> List[State]:
    """Execute a documented RTS against the tracer's followed-call stack."""
    if state.pending:
        return [_stop(state, insn, "nested delayed transfer")]
    if insn.length_bytes is None:
        raise ValueError("cannot return from an instruction without a decoded length")
    length_bytes = insn.length_bytes
    _event(state, insn, "return", predicate=predicate, delayed=delayed)
    if predicate is False:
        state.trace[-1]["action"] = "return-not-taken"
        return _advance(state, insn)

    def take_return(taken: State) -> List[State]:
        if not taken.call_stack:
            return [_stop(taken, insn, "return without followed call")]
        if taken.loops and taken.call_stack[-1] == taken.loops[-1].start_sw:
            return [_stop(taken, insn, "return reached loop PC-stack entry")]
        if delayed:
            taken.steps += 1
            taken.pc_sw += length_bytes // 2
            taken.pending = Pending(None, slots=2, return_from_call=True)
        else:
            taken.steps += 1
            taken.pc_sw = taken.call_stack.pop()
            _sync_pc_stack(taken)
            _event(taken, insn, "loaded-call-return", return_sw=taken.pc_sw)
        return [taken]

    if predicate is True:
        return take_return(state)
    taken, not_taken = _copy(state), _copy(state)
    not_taken.trace[-1]["action"] = "return-not-taken"
    return take_return(taken) + _advance(not_taken, insn)


def _start_counted_loop(state: State, insn: Instruction, count: int) -> List[State]:
    if count == 0:
        return [_stop(state, insn, "unsupported zero-count Type12a loop")]
    reladdr = (_field(insn.fields, "reladdr[22:16]") << 16) | _field(
        insn.fields, "reladdr[15:0]"
    )
    if insn.length_bytes is None:
        raise ValueError("cannot start a loop from an instruction without a length")
    end_sw = state.pc_sw + _signed(reladdr, 23)
    start_sw = state.pc_sw + insn.length_bytes // 2
    mode = _field(insn.fields, "mode")
    state.uregs[UREG_CODES["LCNTR"]] = Const(count)
    state.uregs[UREG_CODES["CURLCNTR"]] = Const(count)
    stkyx_code = UREG_CODES["STKYX"]
    state.uregs[stkyx_code] = _bitwise(
        _ureg(state.uregs, stkyx_code),
        Const(1 << 26),
        "loop stacks nonempty",
        lambda a, b: a & ~b,
    )
    state.loops.append(Loop(start_sw, end_sw, count, mode))
    state.call_stack.append(start_sw)
    _sync_pc_stack(state)
    _event(
        state,
        insn,
        "loop-setup",
        start_sw=start_sw,
        end_sw=end_sw,
        count=count,
        mode=mode,
    )
    return _advance(state, insn)


def _execute(state: State, insn: Instruction) -> List[State]:
    if insn.kind != "confident" or insn.length_bytes is None:
        return [_stop(state, insn, "uncertain or undecodable form: " + insn.note)]
    state.at_loaded_entry = False
    f, name = insn.fields, insn.type_name
    if name in ("21a", "21c"):
        return _advance(state, insn)
    if name == "6b_shiftimm":
        if _field(f, "cond") != 0x1F:
            return [_stop(state, insn, "unsupported Type6b predicate")]
        try:
            result = _shift_immediate(f, dict(state.uregs))
        except ValueError as error:
            return [_stop(state, insn, str(error))]
        _apply_compute(state, insn, result)
        return _advance(state, insn)
    if name == "18a":
        bop = _field(f, "bop")
        sreg = _field(f, "sreg")
        if bop in (4, 5):
            operation = "bit-test" if bop == 4 else "xor-test"
            code = UREG_CODES["USTAT1"] + sreg
            mask = _wide(f, "data")
            source = _ureg(state.uregs, code)
            if isinstance(source, Const):
                result = (
                    (source.value & mask) == mask if bop == 4 else source.value == mask
                )
            else:
                result = None
            mode1 = _ureg(state.uregs, UREG_CODES["MODE1"])
            simd = bool(mode1.value & (1 << 21)) if isinstance(mode1, Const) else None
            astatx_code = UREG_CODES["ASTATX"]
            astatx = _ureg(state.uregs, astatx_code)
            if result is None or not isinstance(astatx, Const):
                state.uregs[astatx_code] = Unknown(operation + " BTF")
            else:
                state.uregs[astatx_code] = Const(
                    (astatx.value & ~(1 << 18)) | ((1 << 18) if result else 0)
                )
            # In SIMD mode the complementary STKY/ASTAT pair is evaluated
            # independently.  Preserve that uncertainty unless both MODE1
            # and the complementary source are concrete.
            if sreg in (6, 7, 8, 9) and simd is not False:
                complement = {6: 7, 7: 6, 8: 9, 9: 8}[sreg]
                complement_source = _ureg(
                    state.uregs, UREG_CODES["USTAT1"] + complement
                )
                if simd is True and isinstance(complement_source, Const):
                    complement_result = (
                        (complement_source.value & mask) == mask
                        if bop == 4
                        else complement_source.value == mask
                    )
                else:
                    complement_result = None
                astaty_code = UREG_CODES["ASTATY"]
                astaty = _ureg(state.uregs, astaty_code)
                if complement_result is None or not isinstance(astaty, Const):
                    state.uregs[astaty_code] = Unknown(operation + " PEy BTF")
                else:
                    state.uregs[astaty_code] = Const(
                        (astaty.value & ~(1 << 18))
                        | ((1 << 18) if complement_result else 0)
                    )
            _event(
                state,
                insn,
                "system-bit-test",
                register=UREG_NAMES[code],
                operation=operation,
                mask=mask,
                result=result,
                simd=simd,
            )
            return _advance(state, insn)
        operations = {
            0: ("set", lambda a, b: a | b),
            1: ("clear", lambda a, b: a & ~b),
            2: ("toggle", lambda a, b: a ^ b),
        }
        if bop not in operations:
            return [_stop(state, insn, "unsupported Type18a BOP %#x" % bop)]
        # ASTATx/y and STKYx/y have implicit complementary-register behavior
        # in SIMD mode.  Stop rather than invent MODE1/PE state for those
        # register pairs; the other SYSREG selections have no companion.
        if sreg in (6, 7, 8, 9):
            return [
                _stop(
                    state,
                    insn,
                    "unsupported Type18a SIMD-sensitive system register",
                )
            ]
        code = UREG_CODES["USTAT1"] + sreg
        mask = _wide(f, "data")
        previous = _ureg(state.uregs, code)
        operation, calculate = operations[bop]
        value = _bitwise(
            previous,
            Const(mask),
            "%s %s %#x" % (operation, UREG_NAMES[code], mask),
            calculate,
        )
        state.uregs[code] = value
        _event(
            state,
            insn,
            "system-bit-op",
            register=UREG_NAMES[code],
            operation=operation,
            mask=mask,
            previous=_json_value(previous),
            value=value,
        )
        return _advance(state, insn)
    if name == "20a":
        push_fields = ("lpu", "spu", "ppu")
        pop_fields = ("lpo", "spo", "ppo")
        if any(_field(f, field) for field in push_fields) and any(
            _field(f, field) for field in pop_fields
        ):
            return [_stop(state, insn, "invalid Type20a mixed push and pop")]
        unsupported = [
            field
            for field in (
                "lpu",
                "ppu",
                "llii",
                "lldwb",
                "lldi",
                "llpwb",
                "llpi",
            )
            if _field(f, field)
        ]
        if unsupported:
            return [
                _stop(
                    state,
                    insn,
                    "unsupported Type20a operations: " + ", ".join(unsupported),
                )
            ]
        push_status = bool(_field(f, "spu"))
        pop_status = bool(_field(f, "spo"))
        pop_loop = bool(_field(f, "lpo"))
        pop_pc = bool(_field(f, "ppo"))
        flush_cache = bool(_field(f, "fc"))
        astatx_code = UREG_CODES["ASTATX"]
        astaty_code = UREG_CODES["ASTATY"]
        mode1_code = UREG_CODES["MODE1"]
        stkyx_code = UREG_CODES["STKYX"]
        if push_status:
            state.status_stack.append(
                (
                    _ureg(state.uregs, astatx_code),
                    _ureg(state.uregs, astaty_code),
                    _ureg(state.uregs, mode1_code),
                )
            )
            state.uregs[mode1_code] = _bitwise(
                _ureg(state.uregs, mode1_code),
                _ureg(state.uregs, UREG_CODES["MMASK"]),
                "MODE1 masked by PUSH STS",
                lambda mode1, mmask: mode1 & ~mmask,
            )
            state.uregs[stkyx_code] = _bitwise(
                _ureg(state.uregs, stkyx_code),
                Const(1 << 24),
                "status stack nonempty",
                lambda value, mask: value & ~mask,
            )
        if pop_status:
            if state.status_stack:
                astatx, astaty, mode1 = state.status_stack.pop()
                state.uregs[astatx_code] = astatx
                state.uregs[astaty_code] = astaty
                state.uregs[mode1_code] = mode1
            if not state.status_stack:
                state.uregs[stkyx_code] = _bitwise(
                    _ureg(state.uregs, stkyx_code),
                    Const(1 << 24),
                    "status stack empty",
                    lambda value, mask: value | mask,
                )
        if pop_loop:
            if state.loops:
                state.loops.pop()
            state.uregs[UREG_CODES["CURLCNTR"]] = (
                Const(state.loops[-1].remaining) if state.loops else Const(0xFFFFFFFF)
            )
            if not state.loops:
                state.uregs[stkyx_code] = _bitwise(
                    _ureg(state.uregs, stkyx_code),
                    Const(1 << 26),
                    "loop stacks empty",
                    lambda value, mask: value | mask,
                )
        if pop_pc:
            if state.call_stack:
                state.call_stack.pop()
            _sync_pc_stack(state)
        _event(
            state,
            insn,
            "stack-control",
            push_status=push_status,
            pop_status=pop_status,
            pop_loop=pop_loop,
            pop_pc=pop_pc,
            flush_cache=flush_cache,
            status_depth=len(state.status_stack),
        )
        return _advance(state, insn)
    if name == "12a_imm":
        count = (_field(f, "data[15:8]") << 8) | _field(f, "data[7:0]")
        return _start_counted_loop(state, insn, count)
    if name == "12a_ureg":
        count = _ureg(state.uregs, _field(f, "ureg"))
        if not isinstance(count, Const):
            return [_stop(state, insn, "nonconcrete Type12a UREG loop count")]
        return _start_counted_loop(state, insn, count.value)
    if state.pending and name in ("25a_direct", "25a_pcrel", "8a_abs", "8a_rel"):
        return [_stop(state, insn, "nested delayed transfer")]
    if name == "11c":
        if _field(f, "x"):
            return [_stop(state, insn, "unsupported Type11c RTI")]
        if _field(f, "lr"):
            return [_stop(state, insn, "unsupported Type11c loop reentry")]
        return _return_transfer(
            state,
            insn,
            _predicate(state, _field(f, "cond")),
            bool(_field(f, "j")),
        )
    # The verified compiler return is a TRUE 9b_abs jump through I4/M6,
    # with two delay slots, one of which is the confident 25c_rframe form.
    # Do not treat rframe alone, its provisional 48-bit sibling, or another
    # register-indirect jump as a return.
    if name == "9b_abs":
        pmi = (_field(f, "pmi[2:2]") << 2) | _field(f, "pmi[1:0]")
        pmm = _field(f, "pmm")
        if (
            _field(f, "b") == 0
            and _field(f, "cond") == 0x1F
            and pmi == 4
            and pmm == 6
            and _field(f, "j") == 1
        ):
            if not state.call_stack:
                return [_stop(state, insn, "return without followed call")]
            _event(state, insn, "return-branch", index="I4", modifier="M6")
            state.steps += 1
            state.pc_sw = state.pc_sw + insn.length_bytes // 2
            state.pending = Pending(None, slots=2, return_from_call=True)
            return [state]
        return [_stop(state, insn, "unsupported 9b_abs indirect transfer")]
    if name == "25c_rframe":
        if state.pending and state.pending.return_from_call:
            return _advance(state, insn)
        return [_stop(state, insn, "rframe outside verified return delay slots")]
    if name in ("17a", "17b"):
        value = (
            _wide(f, "data") if name == "17a" else _signed(_field(f, "data[15:0]"), 16)
        )
        code = _field(f, "ureg")
        state.uregs[code] = Const(value)
        _event(
            state, insn, "ureg-write", ureg=UREG_NAMES[code], value=value & 0xFFFFFFFF
        )
        return _advance(state, insn)
    if name == "7a":
        # Type 7a is MODIFY: the manual guarantees an index-register update
        # in parallel with its optional compute.  This decoder does not expose
        # the complete M-register selection, so retain that missing operand in
        # the value rather than inventing an address update.
        if _field(f, "cond") != 0x1F:
            return [_stop(state, insn, "unsupported Type7a predicate")]
        bank = 8 if _field(f, "g") else 0
        source_low = _field(f, "is[2:2]") << 2 | _field(f, "is[1:0]")
        destination_low = source_low ^ _field(f, "idis")
        source, destination = source_low + bank, destination_low + bank
        try:
            compute = _compute(f, False, dict(state.uregs))
        except ValueError as error:
            return [_stop(state, insn, str(error))]
        state.uregs[16 + destination] = Unknown(
            "Type7a MODIFY(I%d, unknown M register)" % source
        )
        _event(
            state,
            insn,
            "i-modify",
            source="I%d" % source,
            destination="I%d" % destination,
            modifier="unknown (decoder does not expose Type7a M selection)",
        )
        if compute is not None:
            _apply_compute(state, insn, compute)
        return _advance(state, insn)
    if name == "3a":
        # PRM Type 3a is a conditional compute plus one normal-word DM/PM
        # transfer.  Long-word pairs remain deliberately unsupported.
        if _field(f, "l"):
            return [_stop(state, insn, "unsupported Type3a long-word access")]
        cond = _field(f, "cond")
        if cond != 0x1F:
            return [_stop(state, insn, "unsupported Type3a predicate")]
        old = dict(state.uregs)
        compute_fields = dict(f)
        compute_field = _field(f, "compute")
        compute_fields["compute[22:16]"] = compute_field >> 16
        compute_fields["compute[15:0]"] = compute_field & 0xFFFF
        try:
            compute = _compute(compute_fields, False, old)
        except ValueError as error:
            return [_stop(state, insn, str(error))]
        bank = 8 if _field(f, "g") else 0
        index, modifier = _field(f, "i") + bank, _field(f, "m") + bank
        post_modify = bool(_field(f, "u"))
        space = "PM" if bank else "DM"
        iv, mv = _ureg(old, 16 + index), _ureg(old, 32 + modifier)
        address = iv if post_modify else _add(iv, mv, "I%d + M%d" % (index, modifier))
        ureg = _field(f, "ureg")
        if _field(f, "d"):
            value = _ureg(old, ureg)
            _event(
                state,
                insn,
                "store",
                space=space,
                ureg=UREG_NAMES[ureg],
                value=value,
                address=address,
                expression=_render(address),
                concrete_write=_dm_write(state, address, 4, value)
                if space == "DM"
                else False,
                addressing_mode="post-modify" if post_modify else "pre-modify",
                access_width="normal-word",
            )
        else:
            loaded = _load_normal_ureg(state, space, address, ureg)
            _event(
                state,
                insn,
                "load",
                space=space,
                ureg=UREG_NAMES[ureg],
                address=address,
                expression=_render(address),
                concrete_value=loaded,
                addressing_mode="post-modify" if post_modify else "pre-modify",
                access_width="normal-word",
            )
        if post_modify:
            state.uregs[16 + index] = _add(iv, mv, "I%d + M%d" % (index, modifier))
        if compute is not None:
            _apply_compute(state, insn, compute)
        return _advance(state, insn)
    if name == "14a":
        # Forced long-word Type 14a accesses use a neighboring data-register
        # pair.  Do not report them as a single-UREG transfer until the tracer
        # models that pair explicitly.
        if _field(f, "l"):
            return [_stop(state, insn, "unsupported Type14a long-word access")]
        address = _wide(f, "addr")
        rendered = _render(Const(address))
        code = _field(f, "ureg")
        space = "PM" if _field(f, "g") else "DM"
        if _field(f, "d"):
            _event(
                state,
                insn,
                "store",
                space=space,
                ureg=UREG_NAMES[code],
                value=_ureg(state.uregs, code),
                address=address,
                expression=rendered,
                simd_companion_possible=True,
                **(
                    {
                        "concrete_write": _dm_write(
                            state, address, 4, _ureg(state.uregs, code)
                        )
                    }
                    if space == "DM" and state.concrete is not None
                    else {}
                ),
            )
        else:
            loaded = _load_normal_ureg(state, space, address, code)
            _event(
                state,
                insn,
                "load",
                space=space,
                ureg=UREG_NAMES[code],
                address=address,
                expression=rendered,
                concrete_value=loaded,
                simd_companion_possible=True,
            )
        return _advance(state, insn)
    if name in ("5a_move", "5b_move"):
        cond = _field(f, "cond")
        old = dict(state.uregs)
        compute = None
        if name == "5a_move":
            try:
                compute = _compute(f, False, old)
            except ValueError as error:
                return [_stop(state, insn, str(error))]
        src = (
            _field(f, "srcureghigh") << 2
            | _field(f, "srcureglow[1:1]") << 1
            | _field(f, "srcureglow[0:0]")
        )
        dst = _field(f, "dstureg")
        copied = _ureg(old, src)
        predicate = _predicate(state, cond)
        if predicate is False:
            _event(
                state,
                insn,
                "ureg-copy-skipped",
                source=UREG_NAMES[src],
                destination=UREG_NAMES[dst],
                condition=cond,
                predicate_assumption=False,
            )
            return _advance(state, insn)
        executed = state if predicate is True else _copy(state)
        # The Type 5a data move and compute both consume the pre-instruction file.
        executed.uregs[dst] = copied
        if compute is not None:
            _apply_compute(executed, insn, compute)
        _event(
            executed,
            insn,
            "ureg-copy",
            source=UREG_NAMES[src],
            destination=UREG_NAMES[dst],
            condition=cond,
            predicate_assumption=True,
        )
        if predicate is True:
            return _advance(executed, insn)
        skipped = _copy(state)
        _event(
            skipped,
            insn,
            "ureg-copy-skipped",
            source=UREG_NAMES[src],
            destination=UREG_NAMES[dst],
            condition=cond,
            predicate_assumption=False,
        )
        return _advance(executed, insn) + _advance(skipped, insn)
    if name == "2c":
        try:
            compute = _compute(f, True, dict(state.uregs))
        except ValueError as error:
            return [_stop(state, insn, str(error))]
        if compute is None:
            return [_stop(state, insn, "empty short compute")]
        _apply_compute(state, insn, compute)
        return _advance(state, insn)
    if name == "2a":
        # Type 2a conditionally executes a full compute.  Decode against the
        # pre-instruction register file before either predicate assumption mutates it.
        try:
            compute = _compute(f, False, dict(state.uregs))
        except ValueError as error:
            return [_stop(state, insn, str(error))]
        if compute is None:
            return [_stop(state, insn, "empty full compute")]
        cond = _field(f, "cond")
        predicate = _predicate(state, cond)
        if predicate is True:
            _apply_compute(state, insn, compute)
            state.trace[-1].update(condition=cond, predicate_assumption=True)
            return _advance(state, insn)
        if predicate is False:
            _event(
                state,
                insn,
                "compute-skipped",
                condition=cond,
                predicate_assumption=False,
            )
            return _advance(state, insn)
        executed, skipped = _copy(state), _copy(state)
        _apply_compute(executed, insn, compute)
        executed.trace[-1].update(condition=cond, predicate_assumption=True)
        _event(
            skipped,
            insn,
            "compute-skipped",
            condition=cond,
            predicate_assumption=False,
        )
        return _advance(executed, insn) + _advance(skipped, insn)
    if name == "4a":
        if _field(f, "cond") != 0x1F:
            return [_stop(state, insn, "unsupported predicate")]
        old = dict(state.uregs)
        try:
            compute = _compute(f, False, old)
        except ValueError as error:
            return [_stop(state, insn, str(error))]
        index = _field(f, "i") + (8 if _field(f, "g") else 0)
        offset = _signed((_field(f, "data[5:5]") << 5) | _field(f, "data[4:0]"), 6)
        # The immediate modifier is in normal-word address units.  Only turn
        # it into a byte displacement when the caller has explicitly fixed
        # internal normal words at 32 bits.
        if state.assume_nw32:
            offset *= 4
        iv = _ureg(old, 16 + index)
        space = "PM" if _field(f, "g") else "DM"
        if _field(f, "u"):
            address, next_i = iv, _add(iv, Const(offset), "I%d + %d" % (index, offset))
        else:
            address, next_i = _add(iv, Const(offset), "I%d + %d" % (index, offset)), iv
        code = _field(f, "dreg")
        if _field(f, "d"):
            value = _ureg(old, code)
            _event(
                state,
                insn,
                "store",
                space=space,
                dreg="R%d" % code,
                value=value,
                address=address,
                expression=_render(address),
                concrete_write=_dm_write(state, address, 4, value)
                if space == "DM"
                else False,
            )
        else:
            loaded = _dm_read(state, address, 4) if space == "DM" else None
            state.uregs[code] = loaded or Unknown("memory-address " + _render(address))
            _event(
                state,
                insn,
                "load",
                space=space,
                dreg="R%d" % code,
                address=address,
                expression=_render(address),
                concrete_value=loaded,
            )
        state.uregs[16 + index] = next_i
        if compute is not None:
            _apply_compute(state, insn, compute)
        return _advance(state, insn)
    if name == "4b":
        # SHARC+ Core Programming Reference rev. 1.4, pp. 13-29--13-32:
        # conditional DM/PM transfer with a signed six-bit immediate modifier.
        width_fields = (_field(f, "l"), _field(f, "x"), _field(f, "w"))
        widths = {
            (1, 1, 1): ("normal-word", 4, False),
            (0, 0, 0): ("byte", 1, False),
            (1, 0, 0): ("short-word", 2, False),
            (0, 1, 0): ("byte-sign-extended", 1, True),
            (1, 1, 0): ("short-word-sign-extended", 2, True),
        }
        access_spec = widths.get(width_fields)
        if access_spec is None:
            return [_stop(state, insn, "unsupported Type4b access width")]
        access_width, width, signed = access_spec
        store = bool(_field(f, "d"))
        if store and signed:
            return [_stop(state, insn, "unsupported Type4b sign-extended store")]
        bank = 8 if _field(f, "g") else 0
        index = _field(f, "i") + bank
        offset = _signed((_field(f, "data[5:5]") << 5) | _field(f, "data[4:0]"), 6)
        offset *= _access_modifier_scale(access_width, state.assume_nw32)
        post_modify = bool(_field(f, "u"))
        space = "PM" if bank else "DM"
        code = _field(f, "dreg")
        cond = _field(f, "cond")

        def access_memory(executed: State) -> None:
            old = dict(executed.uregs)
            iv = _ureg(old, 16 + index)
            address = (
                iv
                if post_modify
                else _add(iv, Const(offset), "I%d + %d" % (index, offset))
            )
            if store:
                value = _ureg(old, code)
                _event(
                    executed,
                    insn,
                    "store",
                    space=space,
                    dreg="R%d" % code,
                    value=value,
                    address=address,
                    expression=_render(address),
                    concrete_write=_dm_write(executed, address, width, value)
                    if space == "DM"
                    else False,
                    addressing_mode="post-modify" if post_modify else "pre-modify",
                    access_width=access_width,
                    condition=cond,
                    predicate_assumption=True,
                )
            else:
                loaded = (
                    _dm_read(executed, address, width, signed)
                    if space == "DM"
                    else None
                )
                executed.uregs[code] = loaded or Unknown(
                    "memory-address " + _render(address)
                )
                _event(
                    executed,
                    insn,
                    "load",
                    space=space,
                    dreg="R%d" % code,
                    address=address,
                    expression=_render(address),
                    concrete_value=loaded,
                    addressing_mode="post-modify" if post_modify else "pre-modify",
                    access_width=access_width,
                    condition=cond,
                    predicate_assumption=True,
                )
            if post_modify:
                executed.uregs[16 + index] = _add(
                    iv, Const(offset), "I%d + %d" % (index, offset)
                )

        predicate = _predicate(state, cond)
        if predicate is True:
            access_memory(state)
            return _advance(state, insn)
        if predicate is False:
            _event(
                state,
                insn,
                "memory-access-skipped",
                condition=cond,
                predicate_assumption=False,
            )
            return _advance(state, insn)
        executed, skipped = _copy(state), _copy(state)
        access_memory(executed)
        _event(
            skipped,
            insn,
            "memory-access-skipped",
            condition=cond,
            predicate_assumption=False,
        )
        return _advance(executed, insn) + _advance(skipped, insn)
    if name == "3b":
        # SHARC+ Core Programming Reference rev. 1.4, pp. 13-16--13-19.
        # Validate and decode the complete access before making a predicate
        # assumption, so unsupported forms stop rather than creating paths.
        width_fields = (_field(f, "l"), _field(f, "x"), _field(f, "w"))
        widths = {
            (0, 1, 1): "normal-word",
            (0, 0, 0): "byte",
            (0, 1, 0): "byte-sign-extended",
            (1, 0, 0): "short-word",
            (1, 1, 0): "short-word-sign-extended",
            (1, 1, 1): "long-word",
        }
        access_width = widths.get(width_fields)
        if access_width is None:
            return [_stop(state, insn, "unsupported Type3b access width")]
        store = bool(_field(f, "d"))
        if store and access_width.endswith("sign-extended"):
            return [_stop(state, insn, "unsupported Type3b sign-extended store")]
        bank = 8 if _field(f, "g") else 0
        index, modifier = _field(f, "i") + bank, _field(f, "m") + bank
        post_modify = bool(_field(f, "u"))
        addressing_mode = "post-modify" if post_modify else "pre-modify"
        space = "PM" if bank else "DM"
        ureg = _field(f, "ureg")
        cond = _field(f, "cond")

        def access(executed: State) -> None:
            old = dict(executed.uregs)
            iv, mv = _ureg(old, 16 + index), _ureg(old, 32 + modifier)
            widths = {
                "normal-word": 4,
                "byte": 1,
                "byte-sign-extended": 1,
                "short-word": 2,
                "short-word-sign-extended": 2,
                "long-word": 8,
            }
            width = widths[access_width]
            scale = _access_modifier_scale(access_width, executed.assume_nw32)
            scaled_mv = _multiply(mv, Const(scale), f"M{modifier} * {scale}")
            address = (
                iv
                if post_modify
                else _add(iv, scaled_mv, f"I{index} + M{modifier} * {scale}")
            )
            if store:
                value = _ureg(old, ureg)
                _event(
                    executed,
                    insn,
                    "store",
                    space=space,
                    ureg=UREG_NAMES[ureg],
                    value=value,
                    address=address,
                    expression=_render(address),
                    concrete_write=_dm_write(executed, address, width, value)
                    if space == "DM"
                    else False,
                    addressing_mode=addressing_mode,
                    access_width=access_width,
                    condition=cond,
                    predicate_assumption=True,
                )
            else:
                if access_width == "normal-word":
                    loaded: Optional[Const | dict[str, int]] = _load_normal_ureg(
                        executed, space, address, ureg
                    )
                else:
                    scalar_loaded = (
                        _dm_read(
                            executed,
                            address,
                            width,
                            access_width.endswith("sign-extended"),
                        )
                        if space == "DM"
                        else None
                    )
                    executed.uregs[ureg] = scalar_loaded or Unknown(
                        "memory-address " + _render(address)
                    )
                    loaded = scalar_loaded
                _event(
                    executed,
                    insn,
                    "load",
                    space=space,
                    ureg=UREG_NAMES[ureg],
                    address=address,
                    expression=_render(address),
                    concrete_value=loaded,
                    addressing_mode=addressing_mode,
                    access_width=access_width,
                    condition=cond,
                    predicate_assumption=True,
                )
            if post_modify:
                executed.uregs[16 + index] = _add(
                    iv, scaled_mv, "I%d + M%d * %d" % (index, modifier, scale)
                )

        predicate = _predicate(state, cond)
        if predicate is True:
            access(state)
            return _advance(state, insn)
        executed, skipped = _copy(state), _copy(state)
        access(executed)
        _event(
            skipped,
            insn,
            "memory-access-skipped",
            space=space,
            ureg=UREG_NAMES[ureg],
            addressing_mode=addressing_mode,
            access_width=access_width,
            condition=cond,
            predicate_assumption=False,
        )
        return _advance(executed, insn) + _advance(skipped, insn)
    if name == "3c":
        index, modifier = _field(f, "dmi"), _field(f, "dmm")
        old = dict(state.uregs)
        iv, mv = _ureg(old, 16 + index), _ureg(old, 32 + modifier)
        address = iv
        state.uregs[16 + index] = _add(iv, mv, "I%d + M%d" % (index, modifier))
        code = _field(f, "dreg")
        if _field(f, "d"):
            value = _ureg(old, code)
            _event(
                state,
                insn,
                "store",
                space="DM",
                dreg="R%d" % code,
                value=value,
                address=address,
                expression=_render(address),
                concrete_write=_dm_write(state, address, 4, value),
            )
        else:
            loaded = _dm_read(state, address, 4)
            state.uregs[code] = loaded or Unknown("memory-address " + _render(address))
            _event(
                state,
                insn,
                "load",
                space="DM",
                dreg="R%d" % code,
                address=address,
                expression=_render(address),
                concrete_value=loaded,
            )
        return _advance(state, insn)
    if name == "16a":
        if _field(f, "by") or _field(f, "sl"):
            return [_stop(state, insn, "unsupported Type16a by/sl")]
        index, modifier = (
            _field(f, "i") + (8 if _field(f, "g") else 0),
            _field(f, "m") + (8 if _field(f, "g") else 0),
        )
        old = dict(state.uregs)
        iv, mv = _ureg(old, 16 + index), _ureg(old, 32 + modifier)
        address = iv
        _event(
            state,
            insn,
            "store",
            space="PM" if _field(f, "g") else "DM",
            address=address,
            expression=_render(address),
            value=_wide(f, "data"),
            by=_field(f, "by"),
            sl=_field(f, "sl"),
        )
        state.uregs[16 + index] = _add(iv, mv, "I%d + M%d" % (index, modifier))
        return _advance(state, insn)
    if name == "15b":
        index = _field(f, "i") + (8 if _field(f, "g") else 0)
        offset = _signed(_field(f, "data[6:0]"), 7)
        # Type 15b's immediate modifier follows the selected memory width.
        # The opt-in 32-bit normal-word interpretation therefore makes an
        # unqualified (non-LW) displacement four bytes wide.
        if state.assume_nw32 and not _field(f, "l"):
            offset *= 4
        iv = state.uregs.get(16 + index, Unknown("uninitialized I%d" % index))
        address = _add(iv, Const(offset), "I%d + %d" % (index, offset))
        code = _field(f, "ureg")
        width = 8 if _field(f, "l") else 4
        if _field(f, "d"):
            value = state.uregs.get(code, Unknown("uninitialized " + UREG_NAMES[code]))
            _event(
                state,
                insn,
                "store",
                ureg=UREG_NAMES[code],
                address=address,
                expression=_render(address),
                long_word=bool(_field(f, "l")),
                concrete_write=_dm_write(state, address, width, value),
            )
        else:
            loaded = _dm_read(state, address, width)
            state.uregs[code] = loaded or Unknown("memory-address " + _render(address))
            _event(
                state,
                insn,
                "load",
                ureg=UREG_NAMES[code],
                address=address,
                expression=_render(address),
                long_word=bool(_field(f, "l")),
                concrete_value=loaded,
            )
        return _advance(state, insn)
    if name in ("19a", "19a_scaled"):
        bank = 8 if _field(f, "g") else 0
        src_low = _field(f, "is")
        # PGR Type 19 encodes the destination as Id XOR Is, not as a direct
        # register number (Table 17-2 and Figure 17-2).
        dst_low = src_low ^ _field(f, "idis")
        src, dst = src_low + bank, dst_low + bank
        v = state.uregs.get(16 + src, Unknown("uninitialized I%d" % src))
        delta = _signed(_wide(f, "data"), 32)
        scale = 1
        scaled_width = None
        if name == "19a_scaled":
            scaled_width = "normal-word" if _field(f, "w") else "short-word"
            # The opt-in normal-word model represents the loaded program's
            # internal pointers in byte space. Enhanced MODIFY therefore
            # scales NW/SW immediates by four/two bytes respectively.
            if state.assume_nw32:
                scale = 4 if _field(f, "w") else 2
                delta *= scale

        result = _add(v, Const(delta), "I%d + %d" % (src, delta))
        circular = False
        wrapped = False
        if name == "19a_scaled":
            base = _ureg(state.uregs, UREG_CODES["B%d" % src])
            length = _ureg(state.uregs, UREG_CODES["L%d" % src])
            if isinstance(length, Const) and length.value == 0:
                pass
            elif (
                isinstance(v, Const)
                and isinstance(base, Const)
                and isinstance(length, Const)
            ):
                circular = True
                byte_length = length.value * scale
                if byte_length <= abs(delta):
                    result = Unknown("circular modifier is not smaller than L%d" % src)
                else:
                    candidate = (v.value + delta) & 0xFFFFFFFF
                    lower, upper = base.value, base.value + byte_length
                    if candidate < lower:
                        candidate += byte_length
                        wrapped = True
                    elif candidate >= upper:
                        candidate -= byte_length
                        wrapped = True
                    result = Const(candidate)
            else:
                result = Unknown("scaled circular modify I%d" % src)
        state.uregs[16 + dst] = result
        _event(
            state,
            insn,
            "i-add",
            source="I%d" % src,
            destination="I%d" % dst,
            offset=delta,
            scaled_width=scaled_width,
            circular=circular,
            wrapped=wrapped,
        )
        return _advance(state, insn)
    if name in ("25a_direct", "25a_pcrel", "8a_abs", "8a_rel"):
        stem = "addr" if name.endswith("direct") or name.endswith("abs") else "reladdr"
        raw = (_field(f, stem + "[23:16]") << 16) | _field(f, stem + "[15:0]")
        # The sequencer generates 24-bit short-word instruction addresses;
        # reduce a signed PC-relative sum to that architectural width.
        target = (
            raw
            if name.endswith(("direct", "abs"))
            else (state.pc_sw + _signed(raw, 24)) & 0xFFFFFF
        )
        call = name.startswith("25a") or bool(_field(f, "b"))
        cond = True if name.startswith("25a") else _predicate(state, _field(f, "cond"))
        delayed = name.startswith("25a") or bool(_field(f, "j"))
        transfer = _transfer if delayed else _immediate_transfer
        return transfer(state, insn, target, call, cond)
    return [_stop(state, insn, "unsupported form " + str(name))]


def _seed_value(value: int | Value | str) -> Value:
    if isinstance(value, (Const, Affine, Unknown)):
        return value
    if isinstance(value, int):
        return Const(value)
    if isinstance(value, str) and value.startswith("@"):
        return symbol(value[1:])
    raise ValueError("seed value must be an integer, Value, or @symbol")


def _seed_code(key: str | int) -> int:
    if isinstance(key, str):
        try:
            return UREG_CODES[key.upper()]
        except KeyError as error:
            raise ValueError("unknown UREG: " + key) from error
    if not 0 <= key < len(UREG_NAMES):
        raise ValueError("UREG code out of range: %d" % key)
    return key


def trace(
    data: bytes | LoadedMemory,
    base_sw: Optional[int],
    start: int,
    sets: Optional[Mapping[Union[str, int], int | Value | str]] = None,
    max_steps: int = 100,
    max_states: int = 32,
    *,
    concrete_memory: bool = False,
    follow_loaded_calls: bool = False,
    continue_external_calls: bool = False,
    dossier_bytes: int = 0,
    max_call_depth: int = 8,
    skip_provisional_entries: bool = False,
    assume_nw32: bool = False,
    core_reset_state: bool = False,
) -> List[State]:
    uregs: Dict[int, Value] = (
        {
            UREG_CODES[name]: Const(value)
            for name, value in CORE_UREG_RESET_VALUES.items()
        }
        if core_reset_state
        else {}
    )
    for key, value in (sets or {}).items():
        uregs[_seed_code(key)] = _seed_value(value)
    if concrete_memory and not isinstance(data, LoadedMemory):
        raise ValueError("concrete memory requires LoadedMemory")
    if not 0 <= max_steps <= 100_000:
        raise ValueError("max_steps must be between 0 and 100000")
    if not 1 <= max_states <= 1_024:
        raise ValueError("max_states must be between 1 and 1024")
    if dossier_bytes < 0 or dossier_bytes > 256:
        raise ValueError("dossier_bytes must be between 0 and 256")
    if max_call_depth < 1 or max_call_depth > 32:
        raise ValueError("max_call_depth must be between 1 and 32")
    concrete = data if isinstance(data, LoadedMemory) and concrete_memory else None
    mmrs: Dict[int, Value] = (
        {address: Const(value) for address, value in CORE_MMR_RESET_VALUES.items()}
        if core_reset_state
        else {}
    )
    active, done = (
        [
            State(
                start,
                uregs,
                concrete=concrete,
                base_sw=base_sw,
                follow_loaded_calls=follow_loaded_calls,
                continue_external_calls=continue_external_calls,
                dossier_bytes=dossier_bytes,
                max_call_depth=max_call_depth,
                skip_provisional_entries=skip_provisional_entries,
                at_loaded_entry=skip_provisional_entries,
                assume_nw32=assume_nw32,
                core_reset_state=core_reset_state,
                mmrs=mmrs,
            )
        ],
        [],
    )
    while active:
        state = active.pop(0)
        if state.steps >= max_steps:
            done.append(_stop(state, None, "max-steps"))
            continue
        out = _execute(state, decode_at(data, base_sw, state.pc_sw))
        for child in out:
            if child.stopped:
                done.append(child)
            elif len(active) + len(done) >= max_states:
                done.append(_stop(child, None, "max-states"))
            else:
                active.append(child)
    return done


def summarize(states: Sequence[State], start_sw: int) -> dict:
    """Return a bounded machine-readable runtime-probe summary."""
    summaries = []
    for state in states:
        peripheral_accesses = []
        loop_setups = []
        for event in state.trace:
            if event.get("action") == "loop-setup":
                loop_setups.append(
                    {
                        key: event[key]
                        for key in (
                            "pc_sw",
                            "start_sw",
                            "end_sw",
                            "count",
                            "mode",
                        )
                    }
                )
            if event.get("action") not in ("load", "store"):
                continue
            address = event.get("address")
            if not isinstance(address, int):
                continue
            peripheral = name_address(address)
            if peripheral is None:
                continue
            access = {
                "pc_sw": event["pc_sw"],
                "action": event["action"],
                "address": address,
                "peripheral": peripheral,
            }
            for key in ("value", "concrete_value", "access_width"):
                if key in event:
                    access[key] = event[key]
            peripheral_accesses.append(access)
        stop_event = state.trace[-1] if state.trace else {}
        summaries.append(
            {
                "stopped": state.stopped,
                "stop_pc_sw": stop_event.get("pc_sw", state.pc_sw),
                "stop_form": stop_event.get("form"),
                "steps": state.steps,
                "events": len(state.trace),
                "loaded_calls": sum(
                    event.get("action") == "loaded-call-enter" for event in state.trace
                ),
                "opaque_calls": sum(
                    event.get("action") == "opaque-external-call"
                    for event in state.trace
                ),
                "loop_setups": loop_setups,
                "peripheral_accesses": peripheral_accesses,
                "last_events": state.trace[-5:],
            }
        )
    return {"start_sw": start_sw, "states": summaries}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source")
    p.add_argument("--blob", action="store_true")
    p.add_argument("--base-sw", type=lambda x: int(x, 0))
    p.add_argument("--start", required=True, type=lambda x: int(x, 0))
    p.add_argument("--set", dest="sets", action="append", default=[])
    p.add_argument("--max-steps", type=int, default=100)
    p.add_argument("--max-states", type=int, default=32)
    p.add_argument(
        "--concrete-memory",
        action="store_true",
        help="read loader-backed DM bytes and keep a per-path write overlay",
    )
    p.add_argument("--follow-loaded-calls", action="store_true")
    p.add_argument(
        "--continue-external-calls",
        action="store_true",
        help="record dossier, clobber result registers, then continue",
    )
    p.add_argument("--dossier-bytes", type=int, default=0)
    p.add_argument("--max-call-depth", type=int, default=8)
    p.add_argument(
        "--skip-provisional-entries",
        action="store_true",
        help=(
            "legacy artifact-replay option; currently no-op because the former provisional "
            "Type19 entry is now documented"
        ),
    )
    p.add_argument(
        "--assume-32bit-normal-words",
        action="store_true",
        help="opt in to four-byte internal normal-word DM accesses (runtime IMDWx is otherwise unknown)",
    )
    p.add_argument(
        "--core-reset-state",
        action="store_true",
        help="seed only documented core-register and core-MMR reset values",
    )
    output = p.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true")
    output.add_argument(
        "--summary",
        action="store_true",
        help="print compact stop, loop and named-peripheral details",
    )
    p.add_argument(
        "--trace-json",
        metavar="PATH",
        help="also write the full JSON trace to PATH",
    )
    a = p.parse_args(argv)
    values = {}
    for item in a.sets:
        try:
            name, value = item.split("=", 1)
            values[name] = value if value.startswith("@") else int(value, 0)
            _seed_code(name)
            _seed_value(values[name])
        except ValueError:
            p.error("--set must be NAME=VALUE or NAME=@symbol")
    if a.concrete_memory and not a.blob:
        p.error("--concrete-memory requires --blob")
    if (a.follow_loaded_calls or a.continue_external_calls) and not a.concrete_memory:
        p.error("call following/continuation requires --concrete-memory")
    if a.skip_provisional_entries and not a.follow_loaded_calls:
        p.error("--skip-provisional-entries requires --follow-loaded-calls")
    if a.assume_32bit_normal_words and not a.concrete_memory:
        p.error("--assume-32bit-normal-words requires --concrete-memory")
    if not 0 <= a.max_steps <= 100_000:
        p.error("--max-steps must be between 0 and 100000")
    if not 1 <= a.max_states <= 1_024:
        p.error("--max-states must be between 1 and 1024")
    if not 0 <= a.dossier_bytes <= 256:
        p.error("--dossier-bytes must be between 0 and 256")
    if not 1 <= a.max_call_depth <= 32:
        p.error("--max-call-depth must be between 1 and 32")
    if a.blob and a.base_sw is not None:
        p.error("--base-sw is ambiguous with --blob")
    if not a.blob and a.base_sw is None:
        p.error("--base-sw is required unless --blob is used")
    try:
        with open(a.source, "rb") as fh:
            source = fh.read()
    except OSError as error:
        p.error(str(error))
    if a.blob:
        try:
            source = LoadedMemory.from_stream(source)
        except (TypeError, ValueError) as error:
            p.error("invalid loader stream: " + str(error))
        if not source.ranges():
            p.error("loader stream has no loaded ranges")
        if not source.blocks or "FINAL" not in source.blocks[-1].get("flags", ()):
            p.error("loader stream ended before a final marker")
    states = trace(
        source,
        a.base_sw,
        a.start,
        values,
        a.max_steps,
        a.max_states,
        concrete_memory=a.concrete_memory,
        follow_loaded_calls=a.follow_loaded_calls,
        continue_external_calls=a.continue_external_calls,
        dossier_bytes=a.dossier_bytes,
        max_call_depth=a.max_call_depth,
        skip_provisional_entries=a.skip_provisional_entries,
        assume_nw32=a.assume_32bit_normal_words,
        core_reset_state=a.core_reset_state,
    )
    result = [
        {
            "stopped": s.stopped,
            "steps": s.steps,
            "assumptions": (
                (["32-bit internal normal words"] if s.assume_nw32 else [])
                + (["documented core/MMR reset values"] if s.core_reset_state else [])
            ),
            "trace": s.trace,
        }
        for s in states
    ]
    if a.trace_json:
        try:
            with open(a.trace_json, "w") as fh:
                json.dump(result, fh, indent=2)
                fh.write("\n")
        except OSError as error:
            p.error("cannot write trace JSON: " + str(error))
    if a.summary:
        print(json.dumps(summarize(states, a.start), separators=(",", ":")))
    elif a.json:
        print(json.dumps(result, indent=2))
    else:
        for state in result:
            for event in state["trace"]:
                print(event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
