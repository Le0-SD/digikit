# Handover — 2026-09-13, SHARC readability and the repack chain

Separate thread from `HANDOVER-2026-09-13.md`, which covers the front panel.
Nothing here supersedes that file. Branch: `dsp-re-review`, 13 commits, none
merged. Read **Retractions** before trusting anything you remember.

## Retractions — things this repo believed that are wrong

1. **`0x40128c7c` is not the ColdFire→SHARC transport.** It is a blocking
   `usleep` backed by DMA Timer 1; Ghidra names `0xFC074000`/`0xFC074004` as
   `DTIM1_DTMR`/`DTIM1_DTRR`, and all seven callers pass a bare microsecond
   count. `emu/dspboot.py`'s body always said the argument was a timeout; its
   title said "transport", and the title is what propagated. The real path is
   `FUN_400cf4a8` → the `0x8C000000` FlexBus port, under `FUN_400cfd40`.
2. **`sharcldr.py`'s FILL bit was wrong** (12, should be 8), which is the only
   reason 309,532 of 320,780 bytes were ever called "a format this tool does
   not decode". Confirmed since against Table 40-27 of the ADSP-2156x HWR.
3. **The entry point does not come from the BFLAG_FINAL block.** Table 40-30
   gives FINAL no target_address semantics; Table 40-29 puts the application
   start in BFLAG_FIRST. These streams carry two applications.
4. **`BFLAG_QUICKBOOT` does not exist.** Bit 9 is Reserved. Bit 4 is
   BFLAG_SAVE, not "SAFE". Both were invented here.
5. **"Only 178,796 of 320,780 bytes are loaded, with gaps of unknown purpose"**
   was an artefact of the truncated parse. All 320,780 bytes are accounted for.
6. **The public aPLib format does not describe this device.** See below.
7. **"The per-packet checksum resisted an exhaustive search" was a search in
   the wrong family.** It is recovered, and it is not a CRC, a Fletcher or a
   multiplicative hash — it folds the byte's own index in:
   `(K + sum(body[6+i] ^ (i+K) for i in 0..118)) & 0x7F`. The black-box search
   never tried index-XOR constructions, so 30,603 pairs at chance proved only
   that the tried families were wrong. Read the code next time: the answer was
   ~20 instructions in a section we already had.
8. **`0x40003ca6` for the content checksum is a transcription slip** for
   `0x80003ca6`, in the bootstrap's own address space. Propagated into
   `docs/FINDINGS.md` and `docs/REMAINING.md`.
9. **Section 4 is not the SysEx receiver.** It shares no strings or constants
   with the bootstrap; the receive path is in section 2. Section 4 is most
   consistent with being the flash-programming stub (inferred — its own code
   was not traced).
10. **"Only two fields block a flashable image" undercounted.** There is a
    third, a 32-byte HMAC-SHA256 trailer, which no previous handover records
    at all. It is now recovered too — but nothing had noticed it was there.

## What is now established

**The SHARC image parses completely.** 104 blocks Digitakt, 96 Digitone, 100%
of both files. Addressing is `byte = 2 * short_word + 0x28000000`, confirmed
because the entry point lands exactly on a loaded block's target address.
`tools/sharcldr.py` exposes `sw_to_byte`, `byte_to_sw`, `offset_for_address`,
`address_for_offset`, `entry_points`, and a `--addr` CLI.

**The VISA decoder works.** One misread PRM figure (Type5b_move, eight gray
cells recorded as none) was suppressing 88-93% of all walks. Median run on
real firmware went 20 → 632 instructions (Digitakt), against a random-bytes
control that only moved 15 → 45. Independent check: PC-relative branch targets
land back inside the code region 92-99% of the time versus 0.4-3.6% for noise.

**SHARC is in Ghidra.** `tools/sharc_import.py` builds memory from the loader's
own block targets and reaches 291 functions. Auto-analysis alone finds nothing
— seeds are required. The SLEIGH generator now emits control-flow p-code for
8a/9a/9b/11a as well as 25a_direct/25a_pcrel. `cond` 31 means "always" (31 is
unencodable for 11a, whose unconditional form is 30 — the opcode fixes bit 32,
the low bit of its own cond field).

**The image is fully authenticated, and every field is now computed.** All
three were recovered from the bootstrap by disassembly and confirmed
byte-exact against all four firmwares in the repo root:

| field | where | algorithm |
|---|---|---|
| content checksum | preamble bytes 4-7 | `sum((i ^ word_i))` over 1-based big-endian u32 words of the whole container, trailer included |
| HMAC trailer | container's last 32 bytes | HMAC-SHA256 over `container[:total_len-32]` |
| per-packet checksum | message byte 125 | `(K + sum(body[6+i] ^ (i+K), i=0..118)) & 0x7F` |

The HMAC key is **derived, not stored** — same code at `0x80005d90` in both
devices, only the data differs:

    key[i] = CONST[i] ^ sha256(STRING)[i] ^ sha256(STRING[::-1])[i]

    Digitakt II   STRING="Master Overdrive" @0x80006ff8, CONST @0x80007009
    Digitone II   STRING="Multiplier"       @0x8000706c, CONST @0x80007077

    dt2 key  50fadce1e6c0b93e132d9f8fef2e0c9624eafb392b45439f9d292814f44bcfda
    dn2 key  a4986c2b68f382800b2dd7cfcace6fe2e73e643be62db32cd6a09cb30775d364

Note the earlier docs' "32-byte constant beginning `69 5d 82 bc`" is only one
of the three XOR operands, not the key.

Both the HMAC and the content checksum are **real gates**: `FUN_80003c9c`
branches on each, and failure lands in `FUN_80003bfc`, which prints
"UPGRADE ABORTED" / "PLEASE REBOOT" and hangs in an infinite loop that never
returns — the erase/write loop after it is unreachable. The per-packet
checksum is different: its mismatch flag `_DAT_80008e3c` is written in six
places and **read in none**, so a bad byte 125 silently resets the receive
state machine.

`K` is not a device constant baked into our code — it is byte 7 of the
16-byte framing message (`0x0F` Digitakt II, `0x10` Digitone II). Framing body
bytes 11..13 are the **data-message count** as a 21-bit base-128 value, which
retires the last "unknown rule" in the transport: nothing is copied from the
source file any more. Proof: blanking the framing counts and discarding the
source preamble, re-encoding reproduces all four firmwares **byte-identically**.

**The staging path imposes no size limit.** Each message's 101 decoded bytes
go to `0x40000000 + seq*101`; the message count comes from the framing message
with no bound check, and the erase/write loop caps nothing. Flash target is
offset `0x80000`, which independently matches the known container location. So
the 3x image is not refused by any software check — the open question is purely
the physical DDR and NOR capacities, which this repo has never established.

**Memory occupancy**, which decides whether new code has anywhere to live:

| | L1 (640 KB) | L2 (~1 MB) | DDR |
|---|---|---|---|
| Digitakt | 192 KB loaded + 211 KB filled | 107 KB | 12 KB + 38 MB cleared |
| Digitone | 222 KB loaded + 205 KB filled | 541 KB | 339 KB + 5 MB cleared |

So roughly 237 KB of free L1 on Digitakt, and its L2 is nearly empty —
Digitone uses 5x more, which is what proves the headroom is usable rather than
reserved.

**A machine, on the ColdFire, is a `machineType_t` selecting one shared
`synthParams_t`** — from the mangled signature
`MachineListView(int, Digisharc::trackID_enum, Digisharc::machineType_t,
Digisharc::synthParams_t, ...)`. Not five distinct per-machine structs. The
static initialiser `FUN_401ac1be` (reached from the global-constructor table at
`0x402f9b00`) writes, per named UI choice, a `std::string` display name plus a
40-byte descriptor of seven literal IDs and a tag of 10. All six filters share
literals 45,46,47,48 and a trailing 49 — concrete evidence they are
parameterised instances of one framework, not six algorithms.

## Dead ends — do not re-derive these

- **The RPC dispatcher table's address is never loaded as an immediate.**
  Scanned at 99.5% instruction coverage on Digitakt and 99.8% on Digitone,
  41,341 and 85,257 absolute immediates; zero hits for the table address and
  zero for any of the 11 handler addresses. It is reached by a computed or
  load-time-relocated pointer. Another address search is wasted effort.
- **The machine descriptor table is write-only to static analysis.** All ~42
  entries at `0x42923540`-`0x429237f8` have exactly one reference each, a write
  from `FUN_401ac1be`, and no readers anywhere. Reading them throws
  `MemoryAccessException` — uninitialised bss. Consumers reach them through
  runtime pointers and vtables Ghidra cannot follow.
- **The SHARC transport chain is machine-agnostic.** Every path to
  `FUN_400cfd40` (`FUN_40146148`, `4014653c`, `401465a4`, `401465fe`,
  `40146ada`, `40146d6c`, `4004ade0`, `4004de82`, `4014666c`, `4014684a`,
  `40146f54`) is indexed by voice slot `< 0x400` and does sample cache load,
  reset or PCM streaming. No machine-type comparison in any of them.

The conclusion those three share: **static analysis cannot answer the machine
dispatch question.** The next instrument is the emulator — hook reads of
`0x42923540`-`0x429237f8` during a boot to the UI and see who reads them.
`Machine.install_mmio_trace` and `tools/addrtrace.py` already exist.


- ~~**The per-packet SysEx checksum (byte 125) resisted an exhaustive search.**~~
  **SOLVED — see Retractions 7.** Kept here as a cautionary tale:
  Tested against 30,603 message/checksum pairs across two devices: every
  contiguous byte range as sum and as XOR, raw and 8-in-7-decoded, with
  constant offsets; every CRC-7 and CRC-8 polynomial with both init values,
  both bit orders and all xorouts, byte-at-a-time and 7-bit-symbol-at-a-time,
  per-message and running; Fletcher variants mod 127 and 128; multiplicative
  hashes for all 128 multipliers. All at chance (~1/128). Two real clues did
  come out: it is **not a pure function of the payload** — identical payloads
  carry different checksums, so the counter or header is folded in — and its
  **low bit is exactly the parity of the low bits of `body[0:125]`**, for 100%
  of messages in both files, which is the signature of an arithmetic
  carry-bearing construction rather than a CRC.

## Goal A — the repack chain

**It works end to end.** A rebuilt Digitakt II 1.15C, re-decoded and
re-extracted with the device's own depacker at `0x80000432`, returns all five
sections byte-identical, the 3.1 MB MAIN OS and the SHARC blob included:

    sec 5  META     raw            15B  OK
    sec 2  DSP      packed      30302B  OK
    sec 3  MAIN_OS  packed    3177312B  OK
    sec 4  UPDATER  raw         32768B  OK
    sec 7  BLOB     packed     320780B  OK
    ROUND-TRIP GATE: PASS

`dt2/aplib.py` — store-only packer plus `pack_section()`, which adds the
big-endian `[u32 compressed_len][u32 byte_sum]` header. Output grows ~9/8.

**The public aPLib format is not what the device implements.** A literal is
tag bit 1, not 0. The gamma2 stop bit is inverted. There is no "first byte is
always a literal" case. End-of-stream is a `cmpi.l #$2ff` comparison the
normal encodings cannot reach, so the packer gets there by 32-bit wraparound
— verified against the real depacker every time, but whether Elektron's own
encoder does the same is unknown. Implementing from the published spec, which
is what `docs/REMAINING.md` proposed, would have failed.

`dt2/build.py` — the write side: `encode_8in7()`, `build_container()`,
`store_for_section()`, `encode_syx()`, and `rebuild(syx, replacements)` which
goes from a source `.syx` plus a dict of `id -> decompressed bytes` to a new
`.syx`. Pass every section in `replacements` to skip the Unicorn depack, or it
takes ~45s per compressed section.

**The transport is fully specified**, established over 64,053 messages across
four firmwares and proven by re-encoding both source files byte-identically:
- 9-byte header: `00 20 3c`, device id (`0x14` Digitakt II, `0x15` Digitone
  II), `0x00`, command `0x7e`, then a 21-bit big-endian base-128 counter —
  `b6*16384 + b7*128 + b8` — starting at **242** and incrementing by 1.
- Each 116-byte payload is 14 full 8-in-7 groups plus a partial group of
  1 marker + 3 data bytes, so **every message carries exactly 101 decoded
  bytes**, independent of content.
- The file is bracketed by two 16-byte messages using command `0x7f`, seq
  `01` and `02`. Their 6 decoded bytes are 4 constant device-magic bytes plus
  a 2-byte value that varies with firmware content by an unknown rule.
  `build.rebuild()` copies them from the source rather than deriving them.

### What still blocks flashing

Everything in this section's previous version is resolved. What is left:

1. **Nothing has been flashed.** The chain is complete and self-consistent,
   and a rebuilt image satisfies both of the device's own gates — but that has
   only ever been checked by our code against our code. Items 1 and 2 of
   Suggested order below are the real next step.
2. **The final chunk's zero padding is still an inference.** No sample file
   has a partial final chunk, so there is nothing to confirm it against. Our
   rebuilds do produce one.
3. **Image size, narrowed but not closed.** Store-only packing gives 5.07 MB
   against the original 1.71 MB (2.97x). No *software* check refuses it (see
   above). Physical DDR at `0x40000000` and NOR capacity from offset `0x80000`
   are unestablished — a datasheet or a probe question, not a static-analysis
   one. If either is short, that is what forces a real LZ77 packer.
4. ~~`tools/patchimg.py` does not enforce "never touch sections 2 or 4"~~ —
   done. It now identifies the image by sha256 against the pristine
   extractions, with a content-signature fallback that survives an
   already-patched image, and refuses sections 2 and 4 unconditionally.
   `--force` does not override it and the guard runs before `--dry-run`
   returns. Verified: exit 1, no output file written.

The gate itself is `tools/roundtrip.py`. Run it after any change to the write
path:

    uv run python tools/roundtrip.py Digitakt_II_OS1.15C.syx          # ~90s
    uv run python tools/roundtrip.py Digitakt_II_OS1.15C.syx --quick  # seconds

It verifies with the device's own depacker rather than our packer's inverse,
which is why it is slow and why it is worth anything. Exits non-zero on
mismatch, and refuses to run when `sections/.source-sha256` does not match the
firmware argument.

## Goal B — what a new machine still needs

1. ~~Somewhere to put it~~ — resolved both sides. ColdFire has a runtime-verified
   58,188-byte cave at `0x402f9c14` with a proven trampoline recipe
   (`docs/PATCHING.md`); SHARC has ~237 KB free L1.
2. The dispatch mechanism — open, and now a runtime question, not a static one.
3. Calling convention — half-answered by `machineType_t` + `synthParams_t`.
4. **Writing SHARC code — open, and the deepest.** There is no assembler and no
   semantic model, only length decoding and field extraction.
5. Flashing — the container chain is **done, gated and fully authenticated**.
   Both checksums and the HMAC are recovered and computed; what remains is
   physically flashing one, and the image-size question. See Goal A above.

**The cheapest first machine avoids (4) entirely**: a 12th descriptor entry
registered from the ColdFire cave, mapping to an existing DSP mode with
different parameter defaults or ranges. Not a new algorithm, but a new machine
in the UI, testable in the emulator first, and its failure mode is a UI entry
that does not work rather than silence.

## Tools added this session

    tools/ghidraq.py      query either MAIN OS program: strings, symbols,
                          xrefs, func, callers, decompile, read. Chain with
                          --then; one JVM load serves the whole chain.
    tools/sharc_import.py import section 7 into Ghidra at its real addresses.
                          --seed-calls is required for useful coverage.
    dt2/aplib.py          the packer. `uv run python -m dt2.aplib` re-verifies
                          against the device depacker.
    dt2/build.py          the write side of the container and transport.
                          `uv run python -m dt2.build <firmware.syx>` runs its
                          self-test and prints old vs new stored lengths.
    tools/roundtrip.py    the acceptance gate. Rebuilds and proves every
                          section comes back byte-identical through the
                          device's own depacker, and now also verifies the
                          preamble checksum, the HMAC trailer, the framing
                          message count and every byte-125 checksum.
                          --quick skips MAIN OS.
    dt2/authcode.py       the HMAC trailer: key derivation, compute, verify,
                          seal. tools/content_hmac.py is its CLI.

Ghidra project `~/ghidra-projects/dt2` holds `section_3_MAIN_OS.bin`,
`dn2_MAIN_OS.bin` and now `dt2_SHARC`. Ghidra's decompiler fails with
"Response buffer size exceeded" on the very large functions
(`FUN_401ac1be`, `FUN_400d6b68`, `FUN_4011ae06`) — fall back to `read` plus
Capstone.

## Suggested order

The first three items of the previous list are done. What is left, cheapest
first:

1. **Prove recovery on hardware while healthy** — hold FUNC at power-on,
   STARTUP menu, MIDI DIN only, no version check. The repo still flags "a
   corrupt MAIN OS still lets the menu come up" as inference. Demonstrate it
   before you need it, because everything after this point can brick.
2. **Flash an unmodified rebuild.** It should change nothing, and it is the
   only way to separate "my patch was wrong" from "my repacker was wrong"
   later. This is now a genuinely viable step rather than a blocked one.
3. **Establish DDR and NOR capacity** — settles blocker 3 above, and can be
   done before or alongside 2.
4. **Emulator read-watch on `0x42923540`-`0x429237f8`** during a boot to the
   UI, to name the machine descriptor consumer. This is the one that reopens
   Goal B, and static analysis has been ruled out for it.

A note on method, since this session produced three results the previous one
had recorded as hard or impossible: all three came from **reading the
bootstrap's code**, not from black-box search against the data. Section 2 was
in the repo the whole time. When a field resists analysis, import the code
that validates it before searching the space of algorithms that might produce
it.

`Digitakt_II_OS1.16.syx` and `Digitone_II_OS1.11.syx` are now in the repo root
and were used in the transport analysis, so the header and counter rules hold
across four firmwares. Diffing their memory occupancy against 1.15C/1.10E
would show how much headroom Elektron themselves consumed adding Outbox 8
support — direct evidence about how much is genuinely available for a machine.
