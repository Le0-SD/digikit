# What remains: new machines, and a patching framework

Status review, 2026-09-13. Two goals are in play and they are **not** equally
blocked, so they are costed separately:

- **Goal A — a patching framework**: select patches, apply them to an existing
  firmware, repack, emit a flashable `.syx`. Tractable. Mostly engineering, with
  three genuine reverse-engineering gaps, all small and all located.
- **Goal B — new machines on DT2 and DN2**: blocked behind reading SHARC+ code.
  One specific, cheap-to-attempt defect currently gates the entire approach.

Everything below that is a measurement was measured on this branch, not
inherited from earlier docs. Claims inherited from earlier docs are marked.

---

## Goal A — the patching framework

### A.1 What already exists

| Step | Tool | State |
|---|---|---|
| `.syx` → 8-in-7 decode → ELE3 → section table | `dt2/container.py` | works |
| sections → decompressed blobs | `emu/extract.py` (runs the device's own aPLib depacker under Unicorn) | works |
| byte-exact, length-preserving edit of a decompressed section | `tools/patchimg.py` | works; validates old bytes, refuses overlaps, enforces `len(old)==len(new)` |
| CRC-32 oracle (`0x80001bd0`) | `emu/oracle.py` | works, byte-exact vs zlib |
| depack oracle (`0x80000432`) | `emu/oracle.py` | works |
| boot the patched image to a rendered UI | `emu/run.py` | works (DT2; DN2 does not boot) |

So the *inbound* half of the pipeline is finished and the acceptance check for
"did my edit break the image" exists in emulation.

### A.2 What is missing, in pipeline order

The outbound half — patched sections back to a flashable `.syx` — **does not
exist at all**. No repacker is in this repo. Earlier docs describe a verified
round trip, but that was performed by an external tool
(`mischa85/elektron-firmware-tool`), which **is not present on this machine**
and which this repo never shows a pack invocation for. Treat "repacking is
solved" as unverified.

Ordered checklist. `[W]` = write it, algorithm fully known; `[R]` = needs
reverse engineering first.

1. `[W]` **aPLib compressor.** None exists anywhere — not in the repo, not in
   the venv, not on PyPI (the `aplib` package's `pack()` is
   `raise NotImplementedError`). Crucially this is *cheap*: earlier work
   established that byte-exact packing is unnecessary, since the device's own
   depacker accepts any valid stream. A **store-only encoder** — tag bit `0` +
   literal byte, per the documented tag-bit format, plus the end code — is a few
   dozen lines and needs no LZ77 matching at all. Sections grow; nothing checks
   that. Do this first and defer a real packer indefinitely.
2. `[W]` **Per-section 8-byte header**: big-endian `[u32 compressed_len][u32 byte_sum]`.
   The reader is `dt2/container.py:70` / `emu/extract.py:59`; only the writer is
   missing. Note §4 (updater) is stored raw with sum 0 and §5 (meta) has no
   header — preserve both quirks.
3. `[W]` **ELE3 section-table writer**: magic, count at `0x1C`, 16-byte entries
   `(id, offset, comp_len, dest)` from `0x20`. Reader at `dt2/container.py:16,57`;
   the writer is a direct inverse.
4. `[R]` **32-bit content checksum** at `0x40003ca6`, written into preamble
   bytes 4..8. Described as "word-sum, each word XORed with its index" — but
   word size, endianness, start index and the exact covered range are all
   unpinned. Nobody has traced the routine. This is a short trace under the
   existing Unicorn harness, in the style of how the CRC-32 oracle was built.
5. `[R]` **HMAC-SHA256 trailer** at `0x80005e2a`. The key *material* is
   confirmed present in `sections/section_2_DSP.bin`: anchor
   `be f9 a3 f7 c6 71 78 f2` at `+0x6bf4`, then `"Master Overdrive\0"`, then a
   32-byte constant beginning `69 5d 82 bc`. What is **not** known is the
   derivation — whether the key is that constant verbatim, or a hash over
   label‖constant, or something folding in the anchor. Same fix: trace the
   routine and mirror it in `emu/oracle.py`.
6. `[W]` **8-in-7 re-encoding.** Direct inverse of `dt2/container.py:38-44`.
   No ambiguity.
7. `[R]` **Per-packet SysEx checksum.** This is the quietest gap. `decode_syx()`
   slices `body[9:125]` and *discards* byte 125 without ever computing or
   checking it — so the per-packet checksum algorithm has never been recovered,
   and it is not documented anywhere in `docs/`. Needed for the MIDI-DIN upgrade
   path. Recover it by checking the decoder against the two `.syx` files we have
   (13,346 packets of known-good data is a generous oracle for guessing a
   one-byte checksum).
8. `[W]` **Round-trip gate.** Repack → re-extract with `emu/oracle.py` → assert
   all five sections are byte-identical to what went in. Cheap, and it is the
   thing that makes flashing defensible.

### A.3 What "framework" means, and what is there today

There is no patch framework — only a good single-shot CLI. `tools/patchimg.py`
takes `--str ADDR=OLD:NEW` / `--bytes ADDR=OLDHEX:NEWHEX` on the command line
and *emits* a JSON manifest for audit, but nothing ever *reads* a manifest back.
There is no patch file format, no named-patch catalogue, no versioning of a
patch against a firmware hash, and no selection mechanism. `patches/` is
unrelated — it holds a source patch for Unicorn's m68k translator.

For the stated goal, what is needed on top of the repack chain:

- a patch description format (one file per patch: id, description, target
  device + firmware SHA-256, section id, and a list of length-preserving edits);
- a loader/selector that takes a set of patch ids, checks them against the
  firmware's SHA-256, and refuses to apply two patches that overlap;
- `apply` as the inverse of the manifest `patchimg.py` already writes — this is
  a small refactor of existing, working code, not new logic;
- device parameterisation. `emu/device.py` + `devices/*.toml` already do this
  properly for the **panel**, but every container/address constant is hardcoded
  DT2-1.15C (`emu/oracle.py` says so in its own header). Addresses must move
  into the device TOMLs before DN2 can be patched at all.

**Estimate for Goal A:** the `[W]` items are a day or two of ordinary work. The
three `[R]` items are each a bounded trace under a harness that already exists
and has already been used to do exactly this twice (CRC-32, depacker). None of
them is a research risk. Goal A is achievable.

---

## Goal B — new machines

### B.1 Where machines actually live

Settled, and it is the uncomfortable answer: **machines are only labels and
parameter IDs on the ColdFire; the audio runs on the SHARC+.** The MAIN OS holds
parameter state under a `Digisharc` namespace and RPCs changes across. So the
ColdFire side — which is the side this project can read, boot, and patch — can
rename a machine and reshape its parameter pages, but cannot make a new sound.

What is located on the ColdFire side: a string table at `0x4022b20e` with the
machine and filter names (`WERP`, `STRETCH`, `REPITCH`, `SLICED SMP`, `SVAR`,
`LP4`, `COMB±`, …). No machine-ID enum, no per-machine parameter-page
descriptor, no dispatch structure has been found.

On the SHARC side (container §7) `tools/sharcscan.py` finds, by literal
pattern-matching two cjump encodings, candidate indirect-call tables. Reproduced
on this branch:

- **Digitakt**: 11-entry ascending, 100%-indirect table at `0x0034fc`
  (`0x1c3c3e, 0x1c3c4f, 0x1c3c72, 0x1c3c95, …`). DT2 exposes 5 source machines +
  6 filters = 11.
- **Digitone**: structurally parallel 6-entry table at `0x003a94`.

That 11 is a striking coincidence and it is *still* only a coincidence. The tool
says so itself and it is right to: confirming it means disassembling the code
that indexes the table, which needs a working VISA decoder.

### B.2 The VISA decoder: measured, then fixed

The repo's SHARC tooling had only synthetic self-tests; nobody had run it
against firmware. Measured on this branch, both blobs, past the shared
11,248-byte ADI loader prologue, 2,000 evenly spaced 2-byte-aligned starts per
device, with a random-bytes control run through the same code:

| | Digitakt | Digitone | random control |
|---|---|---|---|
| median instrs before stall | 20 | 145 | 15 / 13 |
| max | 550 | 33,515 | 165 / 211 |
| stalls on `GROUP_5A_5B_MOVE` | 88.5% | 93.0% | ~68% |

Digitakt real firmware decoded only **1.33×** further than literal noise. The
decoder was not tracking code.

The stalls were concentrated in one place: `GROUP_5A_5B_MOVE`, the unresolved
48-bit-vs-32-bit length ambiguity for the Type5 register-move pair. The
transcription's own note said the likely cause was a missed gray bit in one PDF
figure crop.

**It was.** Figure 13-15 (PRM PDF p340, Type5b_move), re-rendered at 400 DPI,
has **eight** gray cells in its second word — bit 30, and bits 22:16 — where the
revision-2 transcription recorded none. Figure 13-13 (p337, Type5a_move) shows
those same bits 22:16 as `compute[22:16]`, white and variable. That is the
discriminator, and it is unambiguous:

| second word, bits 22:16 | type | length |
|---|---|---|
| all zero | `5b_move` | 32-bit |
| non-zero | `5a_move` | 48-bit |

The same re-read caught a second, independent error: `srcureglow[0:0]` sits at
source bit 31 in both figures, but was recorded at own-bit 23 (`5a_move`) and
own-bit 7 (`5b_move`) — in each case colliding with `dstureg`'s range. That
affects operand extraction, not length.

### B.3 Result after the fix — measured, with a control

| | Digitakt | Digitone |
|---|---|---|
| median instrs, before → after | 20 → **632** | 145 → **1,850** |
| max, before → after | 550 → 9,758 | 33,515 → 68,144 |
| stalls on `GROUP_5A_5B_MOVE` | 88.5% → **0%** | 93.0% → **0%** |
| random-bytes control median | 15 → 45 | 13 → 44 |
| **real ÷ control** | 1.33× → **14.1×** | 11.2× → **42.1×** |

The control matters: a more permissive grammar walks further through noise too.
It improved ~3×. Real firmware improved 13–32×. The signal-to-noise ratio grew
10.5× on Digitakt and 3.8× on Digitone, so this is not grammar loosening.

One further consistency check, which is the most convincing part: targeted walks
that were *already* stalling on "no pattern matches" before the fix are
**byte-for-byte unchanged** — same instruction count, same stall offset. Only
walks that had been hitting the Type5 ambiguity moved, by 3.6–105×. A blanket
loosening would have shifted everything.

The dominant stall reason is now "no pattern in TYPES matches word0 at all"
(99.6–99.9%), which is the honest remaining gap rather than a known defect.
Behind it sit `Type3a` and `Type25c_rframe`, both with `opcode_mask=0` (never
match) because their PRM figures are confirmed pixel-duplicates of other types'
figures. Given that revision 2's "missed gray cell" hypothesis has now been
proven right once, those two figures are worth re-rendering at 400 DPI before
anything more exotic is attempted.

**Goal B is no longer gated on the decoder.** With a 632-instruction median run
on Digitakt, disassembling the code that indexes the candidate dispatch table at
`0x0034fc` is now a reasonable thing to attempt — which is precisely the test
that would confirm or kill the 11-entry coincidence.

### B.4 The SHARC load map is now exact, not inferred

`tools/sharcldr.py` had `FILL_BIT = 12`. In the ADI boot-stream flag set that
bit is `BFLAG_IGNORE`; `BFLAG_FILL` is bit 8 (`0x100`). A FILL block has no
payload in the stream, so treating one as if it did desynchronised the parse at
the fourth block. That is the whole reason 309,532 of 320,780 bytes were
recorded as "a format this tool does not decode".

With the right bit, **the entire image parses as one unbroken block chain**:

| | blocks | bytes consumed | entry point |
|---|---|---|---|
| Digitakt II 1.15C | 104 | 320,780 / 320,780 (100%) | `0x1c1338` |
| Digitone II 1.10E | 96 | 833,060 / 833,060 (100%) | `0x1c12e2` |

The final block in each carries `BFLAG_FINAL` with `byte_count` 0, and its
target address is the image entry point.

This replaces the fitted affine constants with a real map. The loader writes
payload to byte addresses in the `0x28xxxxxx` / `0x80xxxxxx` spaces, while the
core executes at short-word addresses in `0x1cxxxx` / `0x12xxxx`. The relation
is a width alias:

    byte_address = 2 * short_word_address + 0x28000000

Two independent confirmations, neither of them a fit: the declared entry point
`0x1c1338` maps to byte `0x28382670`, which is *exactly* a loaded block's
target address; and the base `0x28000000` is a round region base rather than a
derived residual. `tools/sharcldr.py` now exposes this as `sw_to_byte()`,
`byte_to_sw()`, `offset_for_address()`, `address_for_offset()` and a
`--addr` / `--addr-space` CLI.

A consequence worth noting: the float-vs-other region heuristic in the old
output is now obsolete for locating code. Block targets are ground truth.

### B.5 The dispatch table is real, and it is an RPC dispatcher

The 11-entry table at file offset `0x0034fc` is no longer a lead. Immediately
after its last entry, at `0x3528`, the firmware carries its own label:

    000034fc: 3e3c 1c00 4f3c 1c00 722c 1c00 953c 1c00   (11 entries, 44 bytes)
    ...
    0000351c: 023e 1c00 c73e 1c00 163f 1c00 5250 4320   ....RPC
    0000352c: 6469 7370 6174 6368 6572 0000             dispatcher..

The ADI block header at `0x34ec` targets byte `0x282577c4` with `byte_count`
60 — exactly the 44-byte table plus the 16-byte label. `"RPC"` and
`"dispatch"` each occur exactly once in the whole 320,780-byte blob, both here.

**This reframes the finding, and not entirely in our favour.** It is a named
dispatch table, read directly out of the bytes rather than inferred — but it
dispatches *RPC messages*, not necessarily machines. The 11 = 5 machines + 6
filters arithmetic is still only arithmetic. There are no machine or filter
name strings anywhere in the SHARC blob to check it against, and Digitone's
blob contains no such label at all (its build appears to have stripped the
string), so the convention could not be cross-validated there.

Structure of the 11 targets, from disassembly:
- Entries 1 and 2 are genuine parallel twins: identical 12-instruction type
  sequence, 54 bytes each, differing at 6 of 54 bytes — all inside two embedded
  constants. Entries 4 and 9 share an opening prefix the same way.
- Entries 3–8 all terminate their linear decode at the same file offset with
  progressively shorter runs, i.e. they are successive entry points into one
  shared stream rather than six independent functions. No return instruction
  was found in that span, which our no-semantics decoder cannot resolve.
- Several entries converge on two common absolute jump targets, suggesting a
  shared engine routine.

That shape — thin per-entry stubs differing only in a constant, falling into a
common body — is what a table of similar-signature handlers looks like. It is
consistent with machines. It is equally consistent with eleven unrelated RPC
operations.

The runtime code that indexes the table was *not* found. The earlier search
failed because it looked for the table's address in the `0x12`/`0x1c`/`0xb8`
code spaces; the table actually lives at byte `0x282577c4`. That search is now
worth redoing against the correct address.

### B.6 Where this actually leads

"RPC dispatcher" is the most useful thing found this session, because it names
the seam between the two processors — and the *other* side of that seam is
fully readable. `docs/FINDINGS.md` already records `Digisharc::rpcMsgHeader_t`
among the shared structs in MAIN OS, on the ColdFire, where Capstone works, the
emulator boots, and symbol-ish string tables exist.

So the tractable path is not more SHARC archaeology. It is:

1. Find the ColdFire code that constructs and sends RPC messages.
2. Recover the message-type enum from it — that is a small integer space.
3. Match those message types against these 11 handlers, in order.

If the enum has 11 entries and its names are machine-shaped, the question is
answered from the readable side of the chip. If it has 11 entries that are
plainly protocol operations (set-param, load-kit, note-on), then the machine
dispatch is one level deeper and we will know where to look next. Either
outcome is decisive, and the work happens on the processor this project already
understands.

### B.4 Honest cost of Goal B

Even with a working decoder, adding a machine needs, in order: read the dispatch
table's indexing code; understand the per-machine algorithm's calling
convention, parameter-block layout and RPC contract; write SHARC+ code; fit it
into §7 (of which only 178,796 of 320,780 bytes are loaded by the ADI stream,
with unloaded gaps of 46/52/80/337/691 KB whose purpose is unknown); and repack.
And there is **no SHARC emulator**, so every iteration is flash-and-listen on
real hardware, with no acceptance oracle of the kind Goal A enjoys.

Goal B is not architecturally closed. The hour of figure-reading is spent and it
paid; what remains is the substantial, genuinely hard work above, and the
flash-and-listen iteration loop is still the thing that makes it expensive.

---

## Recommended order

1. ~~Re-read the Type5b_move figure crop.~~ **Done — see B.2/B.3.** The decoder
   now runs 14–42x further on real firmware than on noise.
2. ~~Disassemble the code indexing the SHARC dispatch table.~~ **Partly done —
   see B.4/B.5.** The table is confirmed and self-labelled "RPC dispatcher";
   the load map is now exact; the indexing code was not found, but the search
   used the wrong address space and is worth redoing against byte `0x282577c4`.
3. **Recover the RPC message-type enum from the ColdFire side** (see B.6). This
   is the highest-value next step and it runs on the processor we can already
   read, boot and instrument.
4. Re-render the `Type3a` and `Type25c_rframe` figures at 400 DPI. Same defect
   class as the Type5b_move one just fixed; they are now the top stall cause.
5. Build the repack chain, `[W]` items first, store-only aPLib packer included.
6. Trace the content checksum, then the HMAC derivation, then the packet
   checksum — same method as the CRC-32 oracle.
7. Move DT2-specific addresses into `devices/*.toml`; make the patcher
   device-parameterised.
8. Turn `patchimg.py`'s audit manifest into a readable patch format and add
   selection + overlap checking.
9. Gate the whole thing on a repack → re-extract → byte-identical round trip
   before anything touches hardware.

Steps 5–9 deliver the patching framework for both devices. Steps 2–3 decide
whether machines are reachable at all; steps 1–2 are done and moved the
question from "can we read any SHARC code" to "which RPC message is which",
which is a much better problem to have.
