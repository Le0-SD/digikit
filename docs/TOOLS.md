# Reverse-engineering tools

This repository includes small, purpose-built tools for extracting firmware,
querying Ghidra, measuring the emulator, and analysing the SHARC+ program.
This page is the index: use each tool's `--help` and module docstring for its
full command line.

## Generated-file rule

Firmware and anything derived from it must stay out of git. This includes
`.syx` files, extracted `sections/`, snapshots, Ghidra dumps, measurement
databases, disassembly reports, and mapped string output. Put repeatable
results under `out/`; commit the tool and synthetic tests, not its output.

Before trusting an emulator run, confirm that `sections/.source-sha256`
matches the source `.syx`. Bound emulator runs with an instruction limit.

The full test suite is:

```sh
uv run --with pytest python -m pytest tests -q
```

## Firmware and container tools

| Tool | Purpose |
| --- | --- |
| `python -m emu.extract` | Extract all sections from a supplied `.syx`. This is the normal entry point. |
| `tools/roundtrip.py` | Rebuild and re-extract a container as an acceptance gate for the repack chain. |
| `tools/content_hmac.py` | Inspect or calculate the container's content-authentication trailer. |
| `tools/patchimg.py` | Apply byte-exact, preconditioned patches to an extracted section image. |
| `tools/ddr_geometry.py` | Derive DDR geometry from the bootstrap's initialization sequence. |

Never patch the bootstrap or updater sections. See
[`PATCHING.md`](PATCHING.md) before producing an image intended for hardware.

## ColdFire static analysis and Ghidra

| Tool | Purpose |
| --- | --- |
| `tools/ghidradump.py` | Export an analysed Ghidra program into grep-friendly disassembly/decompilation plus SQLite indexes. |
| `tools/ghidraq.py` | Run read-only PyGhidra queries for functions, callers, references, strings, ranges, and decompilation. Queries can be chained with `--then` so one JVM answers several questions. |
| `tools/refscan.py` | Exhaustively scan a raw ColdFire image for direct references into an address range. Use this to check Ghidra's incomplete reference tables. |
| `tools/codeseeds.py` | Recover likely function entries from vectors, calls, and code pointers. |
| `tools/ghidraapply.py` | Apply code seeds or RTTI discoveries to a Ghidra project. |
| `tools/rttiscan.py` | Locate GCC RTTI, vtables, and class/method strings in a ColdFire image. |
| `tools/ghidravt.py` | Run and export Ghidra Version Tracking matches between two programs. |
| `tools/vtcheck.py` | Check Version Tracking matches against the images and analysis dumps. |
| `tools/export-profile.py` / `tools/apply-profile.py` | Export resolved firmware symbols and apply them as Ghidra labels. |
| `tools/entryhist.py` | Summarise discovered function entries over known code ranges. |

An empty Ghidra caller or reference list is not proof of absence. Confirm raw
references with `tools/refscan.py`, especially for trampolines and code outside
recognised functions.

Typical read-only query:

```sh
uv run python tools/ghidraq.py /section_3_MAIN_OS.bin callers 0xADDRESS \
  --project ~/ghidra-projects/dt2-emac --project-name dt2-emac
```

## Emulator measurement tools

| Tool | Purpose |
| --- | --- |
| `tools/bootcheck.py` | Deterministically classify whether a bounded boot reached its expected milestones. |
| `tools/addrtrace.py` | Instrument the addresses used by `bootcheck.py`. |
| `tools/bootwatch.py` | Watch selected guest writes during cold boot. |
| `tools/memdump.py` / `tools/memfind.py` | Dump or search mapped memory after resuming a snapshot. |
| `tools/snapdiff.py` | Compare guest memory between snapshots. |
| `tools/mmiotrace.py` | Find MMIO addresses touched periodically by the running OS. |
| `tools/steptrace.py` | Explain the instruction accounting of repeated emulator `spin` calls. |
| `tools/panelsweep.py` | Map front-panel code through recorded queue events. |
| `tools/inputlag.py` | Measure latency from a panel event to firmware response. |
| `tools/guirun.py` | Reproduce the GUI worker configuration without opening the GUI. |
| `tools/uidrive.py` | Watch for and optionally drive the experimental machine-list UI path. |

## Machine and frame-link tools

| Tool | Purpose |
| --- | --- |
| `tools/machineprofile.py` | Identify a known MAIN OS by hash and report its machine-related anchors and preconditions. |
| `tools/machinecommit.py` | Test whether an in-memory machine-type change reaches the DSP frame. |
| `tools/machinepatch.py` | Experimental, build-specific live relocation of the UI machine table. |
| `tools/framelink.py` | Describe the ColdFire-to-SHARC frame layout for known images. |
| `tools/sharcframe.py` | Capture the frame sent by the ColdFire from an emulator snapshot. |
| `tools/dspmap.py` | Find ColdFire instructions that reference frame-link tables. |

`machineprofile.py` is the guardrail for the patching tools: do not carry an
address from one firmware image into another without a matching profile and
byte preconditions.

## SHARC+ loader and memory map

The DSP firmware is a loader stream containing multiple writes to mapped
memory, not one flat executable. The address mapping and last-write order are
important.

| Tool | Purpose |
| --- | --- |
| `tools/sharcldr.py` | Parse loader records, validate headers, map file offsets to loaded addresses, dump selected blocks, and extract the final main-program region. |
| `tools/sharc_import.py` | Import the complete loader memory map into Ghidra, replaying writes in stream order. |
| `tools/sharcscan.py` | Recover direct calls and candidate dispatch tables across the loader stream. |
| `tools/sharcstrings.py` | Map bounded printable runs to their loader blocks and loaded addresses, with optional SQLite-reference correlation. This is an orientation aid, not semantic evidence. |

Examples:

```sh
uv run python tools/sharcldr.py out/sections/dt2-1.16/section_7_BLOB.bin --align

uv run python tools/sharcstrings.py \
  out/sections/dt2-1.16/section_7_BLOB.bin \
  --grep 'frame|buffer' --limit 100 --json
```

Mapped-string JSON is firmware-derived and belongs under `out/`, never in a
commit. Printable instruction bytes also look like strings; require a real
data reference before treating a hit as a label.

## SHARC+ decoding and control flow

| Tool | Purpose |
| --- | --- |
| `tools/sharc_disasm.py` | Decode variable-width VISA instructions from the public-manual-derived tables. Unknown or ambiguous instructions stop rather than silently desynchronising. |
| `tools/sharcflow.py` | Recover delayed calls and returns, measure coverage, and optionally seed/repair Ghidra functions. |
| `tools/sharcimm.py` | Search decoded instruction fields, or every loaded block's words, for immediate values and peripheral addresses. |
| `tools/sharcfields.py` | Report per-form decoded-field distributions across main programs. |
| `tools/sharccompare.py` | Compare the generated decoder against the independent specification decoder. |
| `tools/sharcpcode.py` | Build and measure the generated Ghidra language, record decoder/Ghidra views in SQLite, and compare two measurement runs. |
| `tools/sharc_seeddecode.py` | Decode exact Ghidra instruction-start seeds from every loader-mapped region and report form, field, length, and confidence agreement without sweeping data blocks. |

Language changes should be measured before and after:

```sh
uv run python tools/sharcpcode.py measure --out out/sharcpcode/new --ghidra
uv run python tools/sharcpcode.py compare out/sharcpcode/old out/sharcpcode/new
```

Use `tools/sharcpcode.sql` and the generated SQLite files for questions the
measurement already records; avoid starting another Ghidra JVM just to repeat
a query.

To inspect a non-main function through the loader map:

```sh
uv run python tools/sharc_seeddecode.py \
  out/sections/dt2-1.16/section_7_BLOB.bin \
  out/sharcpcode/new/dt2-1.16.sqlite \
  --function 0xFUNCTION --only-problems
```

The SQLite instruction starts are boundary evidence; the tool never performs
a linear sweep over loader regions that may contain data.

## Targeted SHARC+ data flow

These tools are deliberately narrow. They are faster and safer than pretending
the incomplete SHARC+ language can decompile an entire receive path.

### `tools/sharc_trace.py`

A bounded, delay-aware abstract interpreter starting at an exact short-word
PC. It currently models a proved subset of register moves, integer compute,
DAG address updates, memory accesses, and two independent delay slots.
Unsupported or provisional forms stop the state explicitly.

The default mode reads a flat extracted region and therefore requires
`--base-sw`. `--blob` instead decodes exact PCs directly from the complete
section-7 loader memory map, including non-main and cross-block code.

Seeds can be concrete or symbolic:

```sh
uv run python tools/sharc_trace.py out/sharc/dt2-1.16-main.bin \
  --base-sw 0x1c1338 --start 0xSTART \
  --set I2=@receive_words --set R4=@track_index \
  --max-steps 100 --max-states 32 --json

uv run python tools/sharc_trace.py \
  out/sections/dt2-1.16/section_7_BLOB.bin \
  --blob --start 0xSTART --max-steps 100 --json
```

Symbolic arithmetic is affine, so expressions such as
`receive_buffer + 0x94 + 2*track_index` survive copies, addition, subtraction,
and multiplication by a constant. Non-affine operations become `Unknown`.

### `tools/sharc_candidates.py`

Ranks exact Type19a address-adjust hypotheses in a `sharcpcode` SQLite file.
It checks byte and word forms of an offset, finds the nearest source writer,
and classifies the adjusted index register as consumed, overwritten, or
blocked by uncertain/control flow.

```sh
uv run python tools/sharc_candidates.py \
  out/sharcpcode/new/dt2-1.16.sqlite \
  --offset 0x94 --word-bytes 2 --window 64 --json
```

A candidate is a hypothesis, not a finding. Confirm its base-pointer
provenance and the consuming memory operation with the tracer and image bytes.

## Reference manuals

`tools/refstext.py` extracts supplied public manuals into searchable,
page-addressable text under `out/refs/`; `--render PDF PAGE` creates a PNG for
figures. Read the extracted text rather than repeatedly processing PDFs.

Only public SHARC+ references belong in documentation and generated language
sources.

## Choosing the fastest tool

| Question | Start with |
| --- | --- |
| What does this loader offset become in DSP memory? | `sharcldr.py` |
| Where is a known constant or peripheral address used? | `sharcimm.py`, then SQLite |
| Which exact offset calculations are plausible readers? | `sharc_candidates.py` |
| Which non-main instructions disagree with the decoder? | `sharc_seeddecode.py --only-problems` |
| Does a pointer remain `base + stride*index + offset`? | `sharc_trace.py` |
| Did Ghidra miss a ColdFire reference? | `refscan.py` |
| Did a language change regress decoding or analysis? | `sharcpcode.py compare` |
| Can a diagnostic string identify a subsystem? | `sharcstrings.py`, then require a real reference |
| Does an emulator observation hold across snapshots? | `snapdiff.py`, `memdump.py`, or a focused probe |

Record verified results in [`FINDINGS.md`](FINDINGS.md), not in this tool
guide. Keep current state and next steps in the newest handover.
