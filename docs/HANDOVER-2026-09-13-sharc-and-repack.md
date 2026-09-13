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


- **The per-packet SysEx checksum (byte 125) resisted an exhaustive search.**
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

1. **The content checksum** at `0x40003ca6`, preamble bytes 4-7. Not traced.
   Word size, endianness, start index and covered range all unpinned. Same
   method as the CRC-32 and depacker oracles.
2. **The per-packet checksum**, message byte 125. See Dead ends — it resisted
   an exhaustive search. The cheaper question first: does the device even
   check it? The bootstrap's SysEx receive code is in section 2, which we
   have; it is not yet in the Ghidra project but importing it is easy.
3. **Image size.** Store-only packing makes the image **5.07 MB against the
   original 1.71 MB**. The device has to stage the compressed image somewhere
   before depacking, and whether its buffer accepts 3x is unknown. If it does
   not, that is what forces a real LZ77 packer. Answerable statically by
   finding the receive buffer in the bootstrap — do this before the first
   flash, not after.
4. **`tools/patchimg.py` does not enforce "never touch sections 2 or 4".**
   The docs state it as a rule for the operator; the code is a generic byte
   patcher with no section awareness. Section 2 holds the bootstrap version
   word gating the only irreversible operation. Make it code.

The round-trip gate is currently an ad-hoc script, not a tool. It is the
acceptance test everything else depends on and should live under `tools/`.

## Goal B — what a new machine still needs

1. ~~Somewhere to put it~~ — resolved both sides. ColdFire has a runtime-verified
   58,188-byte cave at `0x402f9c14` with a proven trampoline recipe
   (`docs/PATCHING.md`); SHARC has ~237 KB free L1.
2. The dispatch mechanism — open, and now a runtime question, not a static one.
3. Calling convention — half-answered by `machineType_t` + `synthParams_t`.
4. **Writing SHARC code — open, and the deepest.** There is no assembler and no
   semantic model, only length decoding and field extraction.
5. Flashing — the container chain is **done and gated**; what remains is the
   two checksums and the image-size question, all in Goal A above.

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

Ghidra project `~/ghidra-projects/dt2` holds `section_3_MAIN_OS.bin`,
`dn2_MAIN_OS.bin` and now `dt2_SHARC`. Ghidra's decompiler fails with
"Response buffer size exceeded" on the very large functions
(`FUN_401ac1be`, `FUN_400d6b68`, `FUN_4011ae06`) — fall back to `read` plus
Capstone.

## Suggested order

1. Make `patchimg.py` refuse sections 2 and 4. Cheapest, and it is a safety
   gate for everything after it.
2. Find the bootstrap's SysEx receive buffer and its size — settles both
   whether byte 125 is checked at all and whether a 5 MB image can be staged.
   Import `sections/section_4_UPDATER.bin` (stored raw) into the Ghidra
   project; it carries the same code as the bootstrap.
3. Trace the content checksum at `0x40003ca6`.
4. Promote the round-trip gate to `tools/`.
5. Emulator read-watch on `0x42923540`-`0x429237f8` during a boot to the UI,
   to name the machine descriptor consumer. This is the one that reopens
   Goal B, and static analysis has been ruled out for it.
6. Prove recovery on hardware while healthy — hold FUNC at power-on, STARTUP
   menu, MIDI DIN only, no version check. The repo flags "a corrupt MAIN OS
   still lets the menu come up" as inference, not demonstrated, so demonstrate
   it before you need it.
7. Flash an unmodified rebuild. It should change nothing, and it is the only
   way to separate "my patch was wrong" from "my repacker was wrong" later.

`Digitakt_II_OS1.16.syx` and `Digitone_II_OS1.11.syx` are now in the repo root
and were used in the transport analysis, so the header and counter rules hold
across four firmwares. Diffing their memory occupancy against 1.15C/1.10E
would show how much headroom Elektron themselves consumed adding Outbox 8
support — direct evidence about how much is genuinely available for a machine.
