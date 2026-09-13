"""Write-side inverse of dt2/container.py: build an ELE3 container and a
.syx transport around it.

    NOT YET ACCEPTABLE TO A DEVICE. Do not flash output of rebuild(). Two
    fields cannot yet be computed and are only carried through / zeroed as
    placeholders (see below for exactly where):
      - the preamble's 32-bit content checksum (bytes 4..7 of the 8-byte
        preamble ahead of the ELE3 magic) -- algorithm not recovered;
      - the per-message byte-125 checksum inside each 128-byte SysEx
        message -- algorithm not recovered.

Layer cake, innermost first (mirrors dt2/container.py, in reverse):

  1. ELE3        -- magic, then a section table of 16-byte entries, built
                    by build_container(). Per-section storage quirks
                    (aPLib for 2/3/7, raw-with-header for 4, bare for 5)
                    are applied by store_for_section().
  2. preamble    -- 8 bytes ahead of the magic; carried through unchanged
                    by rebuild() (see the checksum warning above).
  3. 8-in-7      -- MIDI carries 7-bit bytes; encode_8in7() is the exact
                    inverse of the decode loop in dt2/container.py.
  4. MIDI SysEx  -- 128-byte messages, built by encode_syx(). The first
                    and last messages are the file's 16-byte framing
                    messages; those carry a 2-byte field whose rule is not
                    understood, so encode_syx() takes them as given rather
                    than building them.

rebuild() ties all of this together: decode a source .syx, substitute any
section content given in `replacements`, re-store and reassemble, and
re-encode -- reusing the source file's own framing messages, since this
module cannot build new ones.
"""
import struct

from dt2 import aplib
from dt2.container import MFR, COUNT_OFF, TABLE_OFF, ENTRY_SZ, decode_syx, sections

# The first data message's counter value; see the module docstring in
# dt2/container.py and the format facts this was built from.
FIRST_COUNTER = 242
CHUNK_SIZE = 101       # decoded bytes carried by one 128-byte message


def encode_8in7(data):
    """bytes -> 8-in-7 encoded bytes. Exact inverse of the decode loop in
    dt2/container.py:37-44: one marker byte per up-to-7 data bytes, holding
    their high bits MSB-first, followed by those bytes with the high bit
    stripped. A short final group is handled the same way as a full one."""
    out = bytearray()
    for start in range(0, len(data), 7):
        group = data[start:start + 7]
        marker = 0
        for n, b in enumerate(group):
            if b & 0x80:
                marker |= 1 << (6 - n)
        out.append(marker)
        out.extend(b & 0x7F for b in group)
    return bytes(out)


def store_for_section(section_id, data):
    """Decompressed section bytes -> stored bytes, applying the per-section
    storage rule dt2/container.py and emu/extract.py already document.
    Raises on an unknown section id rather than guessing its rule."""
    if section_id in (2, 3, 7):
        return aplib.pack_section(data)
    if section_id == 4:
        # 8-byte header present, but byte_sum is 0 and the payload is raw.
        return struct.pack('>II', len(data), 0) + bytes(data)
    if section_id == 5:
        return bytes(data)
    raise ValueError('no known storage rule for section id %d' % section_id)


def build_container(header, entries):
    """(header, [(id, dest, stored_bytes), ...]) -> container bytes.

    `header` is the 0x1C-byte block placed at the very start (magic, the
    observed u32, the 16-byte product string, four zero bytes) -- normally
    copied verbatim from a source container. Payloads are laid out starting
    at 0x80, 16-byte aligned between sections, matching the observed layout
    in dt2/container.py's module docstring / the format facts this was
    built from. The section count is written at 0x1C, the table at 0x20.
    """
    if len(header) != COUNT_OFF:
        raise ValueError('header must be exactly %d bytes' % COUNT_OFF)
    n = len(entries)
    if TABLE_OFF + n * ENTRY_SZ > 0x80:
        raise ValueError('too many sections for the 0x80 table area')

    table = []
    body = bytearray()
    offset = 0x80
    for i, (sid, dest, data) in enumerate(entries):
        table.append((sid, offset, len(data), dest))
        body += data
        end = offset + len(data)
        if i != n - 1:
            pad = (-end) % 16
            body += bytes(pad)
            offset = end + pad
        else:
            offset = end

    out = bytearray(0x80)
    out[:COUNT_OFF] = header
    struct.pack_into('>I', out, COUNT_OFF, n)
    for i, (sid, off, clen, dest) in enumerate(table):
        struct.pack_into('>IIII', out, TABLE_OFF + i * ENTRY_SZ, sid, off, clen, dest)
    out += body
    return bytes(out)


def encode_syx(stream, device_id, framing_start, framing_end, checksum=lambda body: 0):
    """Decoded byte stream -> .syx bytes.

    Chunks `stream` into CHUNK_SIZE (101)-byte pieces -- the amount one
    128-byte message carries, structurally, regardless of content -- 8-in-7
    encodes each into a 116-byte payload, and wraps each in the 9-byte
    header (constant fields, plus a 21-bit base-128 counter starting at
    FIRST_COUNTER) and a checksum byte, then F0/F7. `framing_start` and
    `framing_end` are the complete 16-byte messages to emit first and last;
    the caller supplies them because the 2-byte variable field inside them
    is not understood, so this module cannot build its own.

    The final chunk may be short: it is zero-padded to CHUNK_SIZE bytes.
    That padding value is an inference -- no sample file has a partial
    final chunk to confirm it against.

    `checksum(body)` computes byte 125 from the 125-byte header+payload
    that precedes it; the real algorithm is not recovered, so the default
    is a placeholder that always returns 0. Do not treat its output as
    valid for a device -- see the module docstring.
    """
    out = bytearray()
    out += framing_start
    counter = FIRST_COUNTER
    for start in range(0, len(stream), CHUNK_SIZE):
        chunk = stream[start:start + CHUNK_SIZE]
        if len(chunk) < CHUNK_SIZE:
            chunk = chunk + bytes(CHUNK_SIZE - len(chunk))  # placeholder pad; see above
        payload = encode_8in7(chunk)
        b6 = (counter >> 14) & 0x7F
        b7 = (counter >> 7) & 0x7F
        b8 = counter & 0x7F
        body = MFR + bytes([device_id, 0x00, 0x7E, b6, b7, b8]) + payload
        body += bytes([checksum(body) & 0x7F])  # placeholder checksum; see module docstring
        out.append(0xF0)
        out += body
        out.append(0xF7)
        counter += 1
    out += framing_end
    return bytes(out)


def _source_framing(raw_syx):
    """Raw .syx bytes -> (first_message, last_message), each the complete
    16-byte F0..F7 message. Used by rebuild() to reuse the source's own
    framing rather than build new ones (see encode_syx's docstring)."""
    messages = []
    i = 0
    while i < len(raw_syx):
        if raw_syx[i] != 0xF0:
            raise ValueError('expected F0 at offset %d' % i)
        j = raw_syx.index(0xF7, i)
        messages.append(raw_syx[i:j + 1])
        i = j + 1
    if len(messages) < 2 or len(messages[0]) != 16 or len(messages[-1]) != 16:
        raise ValueError('source .syx is missing its 16-byte framing messages')
    return messages[0], messages[-1]


def rebuild(syx_path, replacements=None, checksum=None):
    """Source .syx path -> rebuilt .syx bytes.

    Decodes the source, takes its container header, preamble, section
    order and destinations, substitutes any section whose id appears in
    `replacements` (a dict of id -> DECOMPRESSED bytes) and decompresses
    every other section via the same device-verified depacker
    emu/extract.py uses, re-stores every section with store_for_section(),
    rebuilds the container, reattaches the source preamble unchanged (see
    the checksum warning in the module docstring), and re-encodes to .syx
    reusing the source's own first and last framing messages.

    `checksum`, if given, is passed through to encode_syx() as its
    per-message checksum function; the default leaves it at encode_syx's
    own placeholder (always 0).
    """
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from emu.extract import classify, updater_image, depack

    replacements = replacements or {}

    dec = decode_syx(syx_path)
    off = dec.find(b'ELE3')
    if off < 0:
        raise ValueError('no ELE3 magic; unsupported container')
    preamble = dec[off - 8:off]                # placeholder: checksum inside not recomputed
    header = dec[off:off + COUNT_OFF]

    c, secs = sections(syx_path)
    img = updater_image(c, secs)

    entries = []
    for sid, s_off, clen, dest in secs:
        raw = bytes(c[s_off:s_off + clen])
        if sid in replacements:
            decompressed = replacements[sid]
        else:
            kind, payload = classify(raw)
            decompressed = depack(img, payload) if kind == 'packed' else payload
        entries.append((sid, dest, store_for_section(sid, decompressed)))

    new_container = build_container(header, entries)
    stream = preamble + new_container

    with open(syx_path, 'rb') as fh:
        raw_syx = fh.read()
    framing_start, framing_end = _source_framing(raw_syx)
    device_id = framing_start[1:-1][3]

    checksum_fn = checksum if checksum is not None else (lambda body: 0)
    return encode_syx(stream, device_id, framing_start, framing_end, checksum=checksum_fn)


def _self_test():
    """Offline checks, runnable without Unicorn or any firmware."""
    import os

    for n in (0, 1, 6, 7, 8, 13, 14, 15, 101, 116, 250):
        data = os.urandom(n)
        encoded = encode_8in7(data)
        # Decode with the exact loop from dt2/container.py, to check
        # encode_8in7 against that logic rather than against itself.
        decoded = bytearray()
        k = 0
        while k < len(encoded):
            marker = encoded[k]
            k += 1
            for m in range(7):
                if k >= len(encoded):
                    break
                decoded.append(encoded[k] | (0x80 if (marker >> (6 - m)) & 1 else 0))
                k += 1
        assert bytes(decoded) == data, n

    header = (b'ELE3' + struct.pack('>I', 0x2b)
              + b'0071       1.15C'[:16].ljust(16, b'\x00') + bytes(4))
    entries = [
        (5, 0x0, b'X' * 15),
        (2, 0x2000000, b'Y' * 200),
        (3, 0x40000400, b'Z' * 50),
    ]
    cont = build_container(header, entries)

    framing = bytes([0xF0]) + bytes(14) + bytes([0xF7])
    syx_bytes = encode_syx(cont, device_id=0x14, framing_start=framing, framing_end=framing)

    import tempfile
    from dt2 import container as containermod
    fd, path = tempfile.mkstemp(suffix='.syx')
    os.close(fd)
    try:
        with open(path, 'wb') as fh:
            fh.write(syx_bytes)
        c, secs = containermod.sections(path)
        assert len(secs) == len(entries)
        for (sid, off, clen, dest), (esid, edest, edata) in zip(secs, entries):
            assert (sid, clen, dest) == (esid, len(edata), edest)
            assert c[off:off + clen] == edata
    finally:
        os.remove(path)

    print('build self_test OK')


USAGE = """usage: uv run python -m dt2.build firmware.syx

Rebuilds a .syx from itself (no replacements) and prints each section's
original and new stored length. Output is NOT acceptable to a device --
see the module docstring."""


if __name__ == '__main__':
    import sys

    _self_test()

    if len(sys.argv) < 2 or '--help' in sys.argv or '-h' in sys.argv:
        print(USAGE)
        raise SystemExit(0 if len(sys.argv) < 2 else 1)

    syx_path = sys.argv[1]
    c, secs = sections(syx_path)
    orig_lens = {sid: clen for sid, off, clen, dest in secs}

    new_bytes = rebuild(syx_path)

    import os
    import tempfile
    from dt2 import container as containermod
    fd, tmp_path = tempfile.mkstemp(suffix='.syx')
    os.close(fd)
    with open(tmp_path, 'wb') as fh:
        fh.write(new_bytes)
    try:
        _, new_secs = containermod.sections(tmp_path)
        print('%-6s %14s %14s' % ('id', 'orig stored', 'new stored'))
        for sid, off, clen, dest in new_secs:
            print('%-6d %14d %14d' % (sid, orig_lens.get(sid, -1), clen))
    finally:
        os.remove(tmp_path)
