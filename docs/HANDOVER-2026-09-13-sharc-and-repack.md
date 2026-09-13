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

## Goal A — the repack chain

Done this session:
- `dt2/aplib.py` — store-only packer, plus `pack_section()` which adds the
  big-endian `[u32 compressed_len][u32 byte_sum]` header. All five sections
  round-trip byte-identical through the device's own depacker at `0x80000432`,
  including the 3.1 MB MAIN OS. Output grows ~9/8; that is fine, nothing in
  the acceptance path hashes compressed bytes.

  **The public aPLib format is not what the device implements.** A literal is
  tag bit 1, not 0. The gamma2 stop bit is inverted. There is no "first byte is
  always a literal" case. End-of-stream is reached by a `cmpi.l #$2ff`
  comparison the normal encodings cannot hit, so the packer gets there by
  32-bit wraparound — verified against the real depacker every time, but
  whether Elektron's encoder does the same is unknown.

Still to write, both direct inverses of readers in `dt2/container.py`:
- ELE3 section-table writer: magic, count at `0x1C`, 16-byte big-endian
  entries `(id, offset, comp_len, dest)` from `0x20`. Preserve the quirks —
  section 4 carries the header with sum 0 and a raw payload, section 5 has no
  header at all.
- 8-in-7 encoder: inverse of `dt2/container.py:37-44`, MSB-first, one marker
  byte per seven data bytes.

Then the round-trip gate: repack → re-extract with `emu/oracle.py` → assert all
five sections byte-identical. Build it before the three traces, not after.

Still needing a trace, same method that produced the CRC-32 and depacker
oracles byte-exact:
- content checksum at `0x40003ca6` (word size, endianness, start index and
  covered range all unpinned)
- HMAC key *derivation* at `0x80005e2a` — the key material is confirmed at
  `sections/section_2_DSP.bin` +0x6bf4 (anchor `be f9 a3 f7 c6 71 78 f2`, then
  `"Master Overdrive\0"`, then a 32-byte constant from `69 5d 82 bc`), but how
  they combine is unknown
- the per-packet SysEx checksum, which has never been recovered because
  `decode_syx()` discards byte 125

**Safety gap to close before anything is flashed:** `tools/patchimg.py` does
not enforce "never touch sections 2 or 4". The docs state it as a rule for the
operator; the code is a generic byte patcher with no section awareness. Section
2 holds the bootstrap version word that gates the only irreversible operation.
Make it code.

## Goal B — what a new machine still needs

1. ~~Somewhere to put it~~ — resolved both sides. ColdFire has a runtime-verified
   58,188-byte cave at `0x402f9c14` with a proven trampoline recipe
   (`docs/PATCHING.md`); SHARC has ~237 KB free L1.
2. The dispatch mechanism — open, and now a runtime question, not a static one.
3. Calling convention — half-answered by `machineType_t` + `synthParams_t`.
4. **Writing SHARC code — open, and the deepest.** There is no assembler and no
   semantic model, only length decoding and field extraction.
5. Flashing — two trivial writers and three traces away.

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

Ghidra project `~/ghidra-projects/dt2` holds `section_3_MAIN_OS.bin`,
`dn2_MAIN_OS.bin` and now `dt2_SHARC`. Ghidra's decompiler fails with
"Response buffer size exceeded" on the very large functions
(`FUN_401ac1be`, `FUN_400d6b68`, `FUN_4011ae06`) — fall back to `read` plus
Capstone.

## Suggested order

1. ELE3 writer and 8-in-7 encoder, then the round-trip gate.
2. Make `patchimg.py` refuse sections 2 and 4.
3. The three traces.
4. Emulator read-watch on the descriptor table, to name the machine consumer.
5. Prove recovery on hardware while healthy, then flash an unmodified rebuild
   before anything modified.

Not yet examined: Digitakt II 1.16 and Digitone II 1.11, released with Outbox 8
support. Diffing memory occupancy against 1.15C/1.10E would show how much
headroom Elektron themselves consumed, which is direct evidence about how much
is genuinely available.
