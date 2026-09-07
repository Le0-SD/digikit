# Digitakt II OS 1.15C — findings

Target SHA-256 `62d588456e47194bd56dfee9568fb9dd4521c4ff1e8b5427eb461355532e8c6c`
(matches the target of `lalzart/digitakt-ii-firmware-research-public`).

Evidence classes used below:
**[V]** verified by running it here · **[D]** documented by prior research, not
re-checked · **[O]** open / nobody has established this.

## Container

`.syx` → SysEx transport (13,346 × 128-byte messages, `F0 00 20 3C 14 00 …`)
→ 8-in-7 bit decode → 8-byte preamble (content checksum at +4) → ELE3
container, 1,347,728 bytes, five aPLib-compressed sections. Nothing encrypted. **[V]**

| id | name | decoded | dest / meaning | what it is |
|---|---|---|---|---|
| 5 | meta | 15 | — | build stamp `250910 15:18:30` |
| 2 | "DSP" | 30,302 | `0x0200` = **version**, loads `0x80000400` | **the bootstrap** — misnamed in the tool |
| 3 | MAIN OS | 3,177,312 | `0x40000400` | the C++ application |
| 4 | updater | 32,776 | `0x80000400` | stored raw, not compressed |
| 7 | blob | 320,780 | — | SHARC ADI loader records |

Section 2's `dest` is not a load address. All 101 absolute call targets in it
land in `0x8000____`; solving for the base that makes its pointer table hit real
string starts gives `0x80000400` with 96 hits. **[V]**

## Integrity — not a barrier to patching

- Per-packet transport checksum; 32-bit content checksum; **HMAC-SHA256** trailer.
- No RSA/ECDSA anywhere. The HMAC **key is derived from material inside the
  firmware itself** — anchor `be f9 a3 f7 c6 71 78 f2` at section 2 +`0x6BF4`,
  followed by `"Master Overdrive\0"` and a 32-byte constant. **[V]**
- Round-trip is lossless: extract → rebuild → re-extract returns all five
  sections byte-identical, checksums and HMAC verifying. The rebuilt `.syx` is
  *not* byte-identical (the tool's aPLib packer beats Elektron's by 80,880
  bytes) and **that does not matter** — see below. **[V]**

## Byte-identical packing is unnecessary

The device's own depacker at `0x80000432`, run under Unicorn, decompresses both
Elektron's original streams and the tool's repacked ones to **identical
SHA-256**, all three compressed sections including the full 3.1 MB MAIN OS.
Nothing in the acceptance path hashes the original compressed bytes. **[V]**

Reproduce: `./venv/bin/python emu/oracle.py`

## The version gate

Upgrade routine begins `0x80001c48`. The gate is at the top, before anything is
displayed or written:

```
80001c66  mvz.w  -$4(a6), d3        ; INCOMING bootstrap version
80001c6a  mvz.w  $80000408.l, d0    ; RUNNING bootstrap version (= 0x0200)
80001c70  cmp.l  d3, d0
80001c72  bcc.w  $800021dc          ; current >= incoming -> EXIT, no upgrade
```

`bcc` is unsigned ≥, so BOOTSTRAP UPGRADE runs **only** when the incoming
version is strictly greater. Re-flashing 1.15C over 1.15C never triggers it. **[V]**

`0x71F9` is `mvz.w`, a ColdFire-only opcode Capstone cannot decode — a naive
sweep desynchronises directly on top of this instruction and reads the gate as
garbage. Use Ghidra's `68000:BE:32:Coldfire` or `dt2/coldfire.py`.

The later "VERSION CHECK" screen at `0x80001e52` is a milder equality check that
the decompressed image declares the version its header claimed. **[V]**

## Recovery

The bootstrap owns the STARTUP menu (`0x8000650d`), the factory test mode, and
`READY TO RECEIVE` (`0x80006603`) — the legacy MIDI-DIN upgrade path. It is
independent of MAIN OS and validates only:

1. content checksum — word-sum, each word XORed with its index (`0x40003ca6`)
2. HMAC-SHA256 trailer (`0x80005e2a`; SHA-256 H0 at `0x800058bc`, K-table at `0x80006ef8`)

**No version comparison on this path.** On failure: "UPGRADE ABORTED" and a spin
loop, nothing written. **[V]** That a corrupt MAIN OS still lets the menu come up
is a strong inference from the code layout, not demonstrated. **[O]**

## What is patchable

MAIN OS holds parameter state and RPCs it to the SHARC — shared structs appear
under a `Digisharc` namespace (`sound_struct`, `fx_setup_struct`,
`logicalParamID_t`, `modTarget_t`, `rpcMsgHeader_t`, `kitStorage_v*`). Machines
and filters are labels and parameter IDs on the ColdFire; audio runs on the DSP. **[V]**

- **247,996 bytes (7.8% of MAIN OS) in 1,392 contiguous string tables.** Machine
  and filter names (table at `0x4022b20e`: `WERP`, `STRETCH`, `REPITCH`,
  `SLICED SMP`/`SLIC`, `STATE VARIABLE`/`SVAR`, `LOWPASS 4`/`LP4`, `EQUALIZER`,
  `COMB-`/`COMB+`, `LEGACY LP/HP`), 24 KB of factory sample paths, mod sources,
  song sections, the random-project-name word list. Same-length editable. **[V]**
- Constants, ranges, defaults; size-preserving ColdFire logic.
- **Adding a new machine**: not architecturally closed, but expensive and
  unverifiable. Section 7 is a real ADI loader stream (32 blocks, only 178,796
  of 320,780 bytes actually loaded, with unloaded gaps of 46/52/80/337/691 KB —
  unloaded is not the same as free). ADI's CCES compiler is a free download. The
  real blocker is that there is **no SHARC emulator or disassembler module**, so
  every DSP iteration is flash-and-listen on hardware. **[V]/[O]**

## Emulation

Function-level works well and is the practical path. Full boot was pushed as far
as it would go; four blockers were cleared, **two of them Unicorn defects**:

| # | blocker | nature | distinct addrs after |
|---|---|---|---|
| 0 | no exception dispatch / `rte` / interrupts | emulator | 444 |
| 1 | `FF1.L` at `0x401112de` — undecodable by Capstone, unimplemented in Unicorn | **emulator** | **36,474** |
| 2 | `USR8` bit 2 (TXRDY) poll, `0xEC070004` — **UART8** | hardware | 37,395 |
| 3 | `movec d0,Rc=0x009` at `0x400cf7e4` — aborts the Unicorn process (SIGABRT) | **emulator** | — |
| 4 | `DSPI0_SR` RXCTR poll, `0xFC05C02C` — **DSPI0** | hardware | 38,193 |

Peripherals identified from NXP *MCF54418RM* Rev. 5 (Table 1-4; ch. 40 §40.3.4–
40.3.7; ch. 41). Only eight distinct peripheral registers are read in the whole
boot, and peripheral setup is read-modify-write that works fine against zeros. **[V]**

### The SPI flash needs no physical dump — correction

An earlier reading of stall 4 concluded the firmware wanted "real bytes off an
SPI device we have no image of", implying a hardware dump was required. **That
was wrong.**

`0x401296fe` is the SPI NOR read routine, signature `read(offset, len, dest)` —
confirmed by `0x84020003 -> DSPI0_PUSHR`, whose low byte `0x03` is the NOR READ
command. Its callers scan the ELE3 section table at flash offset `0x80020`. The
flash content it wants at boot **is the staged OS container**, which is exactly
what `dt2.container` decodes out of the `.syx` we already have.

High-level-emulating that one function and backing it with the container (see
`emu/flashboot.py`) makes boot progress immediately, and the reads it issues
confirm the model is right: **[V]**

```
off=0x080000 len=32      -> 0x44e4d67c    ELE3 header, into the exact address
                                           MAIN OS compares at 0x40128b8c
off=0x080020 len=16  x5                    the five section-table entries
off=0x19be60 len=184844  -> 0x45020a90    section 7 = the SHARC DSP blob
```

Coverage 36,483 -> 37,627 distinct addresses, and the firmware is now loading the
DSP image. The next frontier is the ColdFire<->SHARC link (DSPI2/eDMA), not
another storage problem.

Note the UI draws into a `Bitmap` object (`SoundBrowser::drawMain(Bitmap&)`),
so rendering the screen is a matter of locating that buffer once boot gets far
enough — not of reverse-engineering a display controller. **[O]**

What a physical dump *would* still be needed for: the +Drive contents (samples,
projects), which live elsewhere in flash and are not required to boot.

Also unresolved: `m68k` `SR` must be written **before** `A7`, or the stack
pointer lands in the banked register the CPU is about to stop using. Cost an
hour; noted in `emu/harness.py`.

## Open questions

- Does MAIN OS's USB upgrade path reject a same-version image? It carries
  "Downgrade not possible" (error code 6, formatter at `0x400fb524`) but never
  reads the container version string at an absolute address, so the comparison
  was not located. **[O]**
- Is the bootstrap rewrite atomic once triggered? **[O]**
- Sample/project/preset on-flash layout. `MmcFs`, `/factory`, and the manager
  classes are visible; the partition and directory format is not mapped. **[O]**
- `ERROR_headerVersion_wrong` and friends in MAIN OS are the **LZ4 frame error
  enum**, not OS versioning — a false lead worth recording.

## Display

The panel is **128 x 64, 8 bits per pixel**, read straight out of the firmware's
own structures rather than guessed. **[V]**

`intro_dither::px_copy_to_bitmap(PixelData&, Bitmap&)` at `0x400d315e` — the
binary carries the *demangled* signature as an assert string at `0x401f7ef0`,
which makes it an unusually good anchor. From its argument handling and copy
loop:

```
Bitmap      +0x04  width
            +0x08  height
            +0x0C  stride -- 32-bit words per COLUMN
            +0x10  pixel data pointer
PixelData   +0x00  width
            +0x04  height
            +0x08  8bpp row-major source buffer
```

Pixels are **column-major, 1 bit per pixel**, 32 rows packed per big-endian
word, MSB = lowest y:

    word_index = x * stride + (y >> 5)      bit = 0x80000000 >> (y & 31)

recovered from `Bitmap::setPixel` at `0x40104eb4`. An earlier draft of this
document called `+0x0C` a setPixel function pointer; that was wrong -- it came
from a different routine at `0x400d3244` where the register did not hold a
Bitmap. The panel is 1bpp, not 8bpp: the 8bpp `PixelData` is a greyscale source
thresholded on the way in.

The intro's `PixelData` instance lives at `0x4028ae98` and reads
`width=128, height=64, buffer=0x43139290`. The loop bound `cmpi.l #$2000`
(8192 = 128x64) at `0x400d3640` corroborates it, as does the runtime struct,
which reads back `0x80, 0x40, 0x43139290` under emulation.

**Not yet captured: actual pixels.** The buffer is allocated at runtime and is
still all zeros after 80M instructions — boot parks in DSP init before the intro
renders. Two ways forward, neither attempted:

1. Progress boot past the ColdFire<->SHARC handshake so the UI runs naturally.
2. Call the intro renderer at `0x400d3372` directly. It has no direct callers
   (`jsr (a2)`, `jsr (a5)` — invoked via lambda/vtable), so a harness would have
   to supply the allocator and callback registers. **[O]**

Note the drawing path is pure ColdFire — `MainScreenView`, `SoundBrowser::drawMain(Bitmap&)`,
and ~140 item-renderer lambdas of shape `(int, Bitmap&, int, int, bool)`. Nothing
in it needs the DSP, so route 2 should not require the SHARC at all.

### Rendering firmware graphics without booting **[V]**

`emu/screen.py` runs the device's own drawing code and captures the output. The
mechanism, and one correction to the note above:

`px_copy_to_bitmap` does **not** dispatch through `Bitmap+0x0C`. It loads a
fixed address into `a4` and calls that: `0x40104eb4` is the real
`Bitmap::setPixel(Bitmap*, x, y, value)`. Intercepting that address captures
every pixel without needing to know how `Bitmap` stores them. (`+0x0C` is used
by a *different* renderer at `0x400d3220`, so the harness intercepts both.)

The source is thresholded to 1 bit on this path — `cmpi.l #$80` then `shi.b` at
`0x400d31d8` — so an 8bpp greyscale `PixelData` becomes a monochrome Bitmap.

Validated against ground truth rather than by eye: feed a synthetic 40x16 source
through the firmware routine and the captured pixels match the thresholded input
exactly, 640 setPixel calls for 640 pixels. `./venv/bin/python emu/screen.py selftest`

This matters because a wrong `PixelData` renders as *plausible dither* rather
than failing — several structs found by heuristic scanning are false positives.
Locating genuine static image assets is still open. **[O]**

### Text rendering — still open **[O]**

Not found yet, and the obvious routes came up empty:

- 27 distinct functions call `setPixel`; **none walk a string** (no `move.b (aN)+`
  over a char buffer), so text must go through a glyph blitter one character at
  a time, called from a higher-level loop.
- No standard 5x7 or 6x8 bitmap font table is present (searched for the
  distinctive `'!'` glyph `00 00 5F 00 00` and variants).
- `PopupWindow(const Bitmap*, ...)` and `VerticalMenuView(const char*, int,
  std::string, const Bitmap*, int)` show `Bitmap` is used as an icon type, but
  scanning for static instances in the recovered layout finds none - icons are
  constructed at runtime, so the glyph/icon data is probably stored compressed
  or generated.

The rendering harness itself is done and verified, so once a text routine is
located it can be driven immediately.
