# SHARC engine and startup

The bounded SHARC startup probe, the frontier sprint, the machine-type consumer on the SHARC side, and the audio engine's located ingredients.

## The apparent stream-activation lead is USB, not the SSI/DSP peer **[C][V]**

The earlier interpretation of `FUN_40005ff6`, vector 134 and logical channels
3/7 as a possible missing DSP-peer stream was wrong. `FUN_40005ff6` is a USB
Chapter 9 setup-request dispatcher: `0x80060000` is setup bytes `80 06`
(`GET_DESCRIPTOR`), while `0x010b0000` is `01 0b` (`SET_INTERFACE`). The code
returns device/string descriptors and configures endpoint queues under the
MCF5441x USBOTG register block at `0xfc0b0000`; SSI0 is separately based at
`0xfc0bc000`. Vector 134 consumes the USB setup packet and dispatches endpoint
completion work. **[V]**

Consequently `_DAT_40965a60 == 6`, the `SET_INTERFACE` alternate-setting
branch, and the USB endpoint queues do not explain the observed A2 refresh.
The trigger trace instead reaches `FUN_4002d438` through vector 191 after
local record construction in `FUN_40139878`; no evidence here connects the
USB control dispatcher or its endpoint configuration to that refresh.
`FUN_40003376` remains unclassified by this correction. USB endpoint transfer
type also remains unlabelled until its endpoint descriptor attributes are
decoded. **[C]**

## Bounded static marker and cadence gates remain blocked **[V][O]**

Two bounded, independently reviewed gates closed their specified A2 slices
without relaxing the evidence rules. Neither passed, so a natural SSI peer
model and final qualification must not be implemented from the current
evidence. This result did not by itself prove that every possible static or
emulator experiment had been exhausted. **[V]**

The DMA10 marker gate found only immutable SPORT record `0x0a` at DM
`0x26968c` (loader alias `0x2826968c`), containing SPORT4A `0x31002400` and
DMA10 `0x31023000`. The supported calibrated consumer slice loads these words
at `0x1ca6c1` and `0x1ca6c3` and copies them into an object whose address and
ownership remain unknown. It then stops at aligned provisional words
`0x1ca6e9: 3e02` (`Type23p_undoc16`) and `0x1ca6ea: 3100`
(`Type21p_undoc16`). No supported path establishes DMA direction, descriptor
counts, application buffer, a writer of `0x007fffff`, or placement at stream
word `0 mod 512`. The loader contains no other direct DMA10-window word, the
SHARC main contains none, and normalized reference/immediate queries found no
producer edge. The nine `0x7fffffff` immediates remain unrelated. **[V][O]**

The PCG-C cadence gate confirmed table `0x2d7158` contains only the four
handler pointers. Handler `0xb8b706` reaches a CTLC0 load at `0xb8b70e`, then
immediately stops at aligned `0xb8b711: 3e02`. The known stores to SYNC2,
CTLC1, CTLC0 and PW2 prove reachability only: no supported dataflow supplies
executed values, source selection, or source frequency. The only justified
relation remains symbolic:

```
SSI request rate = bit clock / (24 * 8) = bit clock / 192
64 requests * 32 bytes = 0x800 bytes per major loop
```

It does not justify a numeric rate. Consequently 1,000 Hz, 48,000 Hz, or any
other convenient value remains disqualifying for final A2. **[V][O]**

The gate artifacts are under workflow
`296e0a13-5d01-4406-b5a6-451d30905086`. Final A2 is now blocked on a newly
approved supported observation source: for example, runtime PCG-C register and
edge/request timing plus DMA10 descriptor/application-buffer observation, or
public documentation that supplies the currently unsupported semantics. Broad
ISA expansion, guessed marker conversion, and guessed cadence are rejected
pivots. **[O]**

### A target-backed descriptor slice reaches the marker candidate **[C][V][O]**

The earlier statement that all nine `0x7fffffff` immediates were unrelated is
superseded. Address-aware decoding and a bounded replay now establish an exact
store from one of them into a buffer named by a concrete descriptor-list
template. This
does not yet establish that the list belongs to DMA10, nor that the serial
boundary converts the value to the ColdFire's `0x007fffff`. **[C][V][O]**

At the aligned, even-register Type-14a forced-long-word DM sites used here, the
documented form writes the explicit UREG and its next neighbor at `address` and
`address+4`. (The tracer conservatively stops on odd explicit registers; these
sites do not use them.) With that form modeled, four bounded setup slices
reconstruct cyclic two-descriptor templates and pass their heads in `R8` to
`0x1ca7e4`: **[V]**

| list head | descriptors | start buffers | `CFG, XCNT, XMOD, YCNT, YMOD` | bytes/buffer |
|---:|---|---|---|---:|
| `0x2620c8` | `0x2620c8` ↔ `0x2620e4` | `0x261cc8`, `0x261dc8` | `0x100000, 64, 4, 0, 0` | `0x100` |
| `0x262100` | `0x262100` ↔ `0x26211c` | `0x261ec8`, `0x261fc8` | `0x100000, 64, 4, 0, 0` | `0x100` |
| `0x264138` | `0x264138` ↔ `0x264154` | `0x262138`, `0x262938` | `0x100000, 512, 4, 0, 0` | `0x800` |
| `0x264170` | `0x264170` ↔ `0x26418c` | `0x263138`, `0x263938` | `0x100000, 512, 4, 0, 0` | `0x800` |

All four slices calibrate `R11=0` across an unresolved caller path; lists 2 and
4 additionally seed register values written before unresolved call boundaries.
Their rows are verified calibrated reconstructions, not proof that intervening
calls preserve the registers or that natural execution constructs the same
result. All four probe records disclose common and slice-specific seeds and
remain `qualifying: false`. **[V][O]**

The field names above follow the public descriptor-list register order:
`DSCPTR_NXT`, `ADDRSTART`, `CFG`, `XCNT`, `XMOD`, `YCNT`, `YMOD`. The two
large list geometries exactly match one ColdFire eDMA48/50 `0x800`-byte major
loop, but equal byte counts are not physical ownership or wiring evidence.
The same setup family has four candidate software objects and global slots;
the runtime join from any one object through the three-level SPORT/DMA chain
to record `0x0a` and DMA10 remains unproved. `0x1ca7e4` may also transform the
templates before any hardware fetch, so these are not live DMA descriptors.
**[V][O]**

The first large list does have a byte-backed producer for its first word.
At `0x1c7578` the code loads selector word `DM(0x25f780)` into `R1`;
`0x1c757b` computes `R2 = LSHIFT R1 by 11`; `0x1c757e` copies that byte
offset to `I4`; `0x1c7580` loads exact constant `0x7fffffff` into `I12`;
`0x1c7583` adds base `0x262138`; and `0x1c7586` stores `I12` through
`DM(I4,M5)`. Global setup writes `M5=0` at `0x1c0f44`. With the loader's
zero selector, the calibrated replay therefore writes `0x7fffffff` at
`0x262138`; selector value one would address peer buffer `0x262938`. Those
are exactly the two `ADDRSTART` words in descriptor list `0x264138`.
This is an application-buffer/descriptor-template join, not yet a DMA10/object
join. The instruction path and conditional address expression were checked
independently against the image bytes; the replay is direct-entry and therefore
non-qualifying. **[V][O]**

No exact supported path currently changes `0x7fffffff` into
`0x007fffff`. ColdFire SSI0 is configured for 24-bit words, but the executed
SPORT4A control value, transmitted word length, bit selection, and ownership
of list `0x264138` are still missing. Inferring truncation from the matching
low 24 bits would violate the evidence gate. The smallest useful natural
breakpoint set is now: `0x1c7588` after the marker store, watching
`0x25f780`, `0x262138`, and `0x262938`; `0x1ca7e4` on descriptor submission,
recording `R4/R8`; and `0x1ca6d6` on DMA-base installation, recording the
full `P/L1/L2/L3` chain. A qualifying join needs one natural run to correlate
those observations and the eventual DMA10 register writer. **[O]**

The deterministic report is
`out/experiments/sharc-interface-reader/dma-descriptors-001.json`. Each
calibrated slice is marked `qualifying: false`; its exact bytes, descriptor
words, complete seed disclosure and classification, and residual ownership
gaps are included.
**[V]**

The two concrete static hypotheses left after reopening that conclusion were
then tested. First, a documented 32- or 48-bit predecessor does **not** consume
the aligned `0x023e` parcel. At all four PCG-C sites in each of DT2 1.15C, DT2
1.16 and DN2 1.11, documented 48-bit `Type14a` bytes
`02100c3100a3` end immediately before `3e02`; the parcel then falls through to
documented 48-bit `Type1a` bytes `103822800211`. At the SPORT homolog in each
image, documented 32-bit `Type15b` bytes `0896060a` end immediately before the
same parcel. Identical direct branches target those `Type15b` starts, fixing
their alignment independently. Every apparent documented covering decode
starts inside one of those established predecessors. Thus `0x023e` is a
standalone unsupported parcel at these sites, not a width error; its execution
semantics remain unknown. **[V][O]**

Second, fresh loaded-L2 measurements were made in separate JVM runs under
`out/sharcpcode/l2-cross-002/`. The independently located four-pointer tables
are:

```
DT2 1.15C  DM 0x2d7148: b8b12a b8b3d7 b8b698 b8b945
DT2 1.16   DM 0x2d7158: b8b198 b8b445 b8b706 b8b9b3
DN2 1.11   DM 0x2dd3d0: b8d01a b8d2c7 b8d588 b8d835
```

After relocation, ordered decoded bytes for each table target are identical in
all three images. Their byte lengths and SHA-256 hashes are respectively:

```
148  2e88738b0453ce1f840e267b1b62a3b2b16ed16440ecb1a6ce23e9ac15889dca
  2  15c69a0025b994074ea78f06a5e2f3101b78bc193aaa6f6d044e4e5f679727fc
150  2ba282e3e830b6e631df4a3e832065b2b69680379dcbc5267897206139d5ca0a
158  99752fd431c399854488bb1946158048ce9172c33c89a016cf28d649dacb01db
```

The 64 bytes before each table and 136 bytes after it are also byte-identical;
the latter contain a diagnostic PCG memory-size assertion, not clock
configuration. No alternate image substitutes a documented operation or an
immutable default that yields CTLC0/1, PW2, SYNC2, source selection or source
frequency. Exact identity does not exclude configuration elsewhere or runtime
arguments, but it closes this comparative-substitution hypothesis. **[V][O]**

Names such as `rpc_dispatch_table` and `rpc_handler_00` through
`rpc_handler_03` are mechanically generated by `tools/sharc_import.py` from a
user-supplied label-table address. They are not firmware symbols and do not
establish an RPC role or a ColdFire-facing edge. The tables above must be
described by their byte-backed locations and targets unless an independent
consumer edge is recovered. **[V]**

Independent byte review reproduced the table locations, target hashes and
instruction boundaries. Both reopened hypotheses therefore close negatively:
neither natural DMA10 marker production nor numeric PCG-C/SSI cadence is
recovered, and final A2 qualification remains blocked. This is a bounded
negative result, not a claim that future public evidence or a genuinely new
runtime observation source is impossible. **[V][O]**

## The bounded SHARC startup probe now reaches core initialization **[V][O]**

`tools/sharc_trace.py` can now replay the real section-7 loader stream from a
short-word PC, seed a bounded set of public-manual reset values, follow loaded
calls, and report concrete core/peripheral MMR accesses. The new instruction
slice implements documented Type18a system-register bit operations, including
`TST`/`XOR` updates of ASTAT BTF and the `TF`/`NOT TF` predicates, counted
Type12a loops, and the Type20a status-stack operations and stack-empty polling
used by startup. Unsupported instruction forms still stop explicitly. **[V]**

The strict reset-state run starts at `0x1c1338`. Its first documented Type14a
instruction reads the public reset value zero from `SHBTB_CFG` at `0x31400`.
Execution then stops after one instruction at the standalone `0x023e` parcel,
decoded provisionally as `Type23p_undoc16`, at `0x1c133b`. The zero is supplied
by the public reset table through `--core-reset-state`, not by a section-7
loader record. Artifact:
`out/experiments/sharc-runtime-probe/strict-entry-009-summary.json`. **[V][O]**

An explicitly exploratory restart at `0x1c1365`, after the first unsupported
island, branches through the loaded helper at `0x1c0000`, writes zero to
`SHL1C_CFG`, and executes six concrete zero-fill loops with counts
`1024, 1024, 4096, 256, 256, 128`. It then reads concrete reset value zero from
`SHBTB_CFG` and stops at the next standalone `0x023e` parcel at `0x1c13b7`.
Artifact: `out/experiments/sharc-runtime-probe/post-shbtb-009-summary.json`.
The restart seam makes this discovery evidence, not a qualifying continuous
boot trace. **[V][O]**

A second exploratory restart at `0x1c13c3`, with the already observed MODE1
state, now executes the firmware's three stack-empty polling ladders. Type18a
tests STKYX LSEM, SSEM and PCEM; Type20a pops the loop, status and PC stacks
until those read-only indicators become set. The path writes the real main
entry `0x1c1338` to `RCU0+0x2c` at instruction `0x1c1414`, enters loaded call
`0x1c0f26`, initializes DAG and mode state, loads public reset value zero from
`CMMR_SYSCTL` at `0x30024`, and stops at another standalone unsupported
`0x023e` parcel at `0x1c0f8b`. Artifact:
`out/experiments/sharc-runtime-probe/post-shbtb2-005-summary.json`. Independent
review reproduced the instruction bytes, decodes, loader-backed control flow,
MMR addresses and trace events. **[V][O]**

This is the first firmware-backed dynamic reach into SHARC core initialization,
but it has not yet reached a concrete PCG-C, SPORT4A or DMA10 configuration.
The strict path remains blocked at `0x1c133b`, while every later observation
above crosses an explicit unsupported-instruction restart seam. Therefore it
does not establish marker production, DMA10 descriptors, SSI cadence or final
A2 qualification. **[O]**

## The capped SHARC frontier sprint found no supported route to the SSI peer **[V][O]**

A final bounded public-source search found no semantics for aligned parcel
`0x023e`. The current SHARC+ programming reference and the earlier public VISA
reference both mark Types 23–24 reserved. Historical classic-core `IDLE16` is
device-specific, has a different documented opcode prefix, and cannot name or
define the SHARC+ parcel. Public emulator, assembler, LLVM, patent and forum
searches supplied no exact encoding or architectural effects. “Reserved” is
negative documentation evidence, not proof that the target silicon treats the
parcel as illegal or inert. **[V][O]**

The existing loaded-image graph also supplies no alternate supported route.
The strongest PCG-C candidate loads CTLC0 at `0xb8b70e` and immediately reaches
`0xb8b711: 3e02`; corresponding paths encounter the same provisional family.
The SPORT4A/DMA10 consumer at `0x1ca58a` still requires the calibration-only
`I4=-0x13c` selection and stops at `0x1ca6e9: 3e02`. Every ranked path therefore
requires an unsupported parcel, arbitrary direct-entry state, or unknown
runtime arguments before it can establish executed PCG, SPORT or DMA state.
**[V][O]**

`tools/sharc_frontier.py` now automates exploratory continuation without
changing strict tracer semantics. A versioned manifest names each predecessor
stop PC, successor PC, exact skipped byte range, SHA-256 and assumptions. The
driver hard-limits a run to three islands, 4,096 bytes per island and 50,000
instructions; reports and restart events are always `qualifying: false`.
`optimistic-preserve` carries state across an island, while
`conservative-clobber` invalidates registers, stacks and pre-island data/MMR
state but retains the immutable loader code map. Compact reports cap peripheral
samples while full traces remain optional artifacts. **[V]**

The startup manifest under
`out/experiments/sharc-runtime-probe/frontier-startup-001-manifest.json`
declares three independently byte-verified ranges:

```
0x1c133b..0x1c1365   84 bytes  b678736eb48034a335d831eef9c5f9f6f8fc3384bf343dedd3fdcaf35cd2a68d
0x1c13b7..0x1c13c3   24 bytes  3a239ba23af24b22909a98aebeb110fbdbb71794f17faf8a345cc9f4f48f9f19
0x1c0f8b..0x1c0f8e    6 bytes  1260410df141425e99ed75249a74463e83e70caae55a6ed30f37fd21999b6bf0
```

The optimistic run crossed all three, executed 6,932 instructions, reached no
PCG-C, SPORT4A or DMA10 target, and stopped at unsupported documented form
Type11c at `0x1c0fbc`. The conservative run crossed two islands, made the
post-island status predicates unknown, and reached its state bound before a
target. Artifacts are
`frontier-startup-001-{optimistic,conservative}-{summary,trace}.json` in the
same directory. These results satisfy the sprint's stop criterion: increasing
the island or instruction budget would produce more discovery-only execution,
not qualifying evidence. **[V][O]**

Static 1.15C/1.16 comparison is insufficient to substitute runtime values.
DAI routing and immutable SPORT association are compatible, but PCG source and
divisors, DMA descriptors/buffers, marker words and external SSI cadence remain
unknown runtime inputs. No 1.15C cadence or payload may therefore be promoted
to the 1.16 target by relocation or handler identity alone. **[V][O]**

## `0x023e` is the first parcel of a 48-bit immediate shift **[C][V][O]**

The earlier standalone-`Type23p_undoc16` interpretation is wrong. A public
SHARC+ VISA decoder (`js216/selache` revision
`2b26d3b75c53063575bc5c820fa0d38879335187`) selects a 48-bit instruction for
first byte `0x02`. For the observed words, the stricter fixed bits and fields
match the public programming reference's Type6a no-memory ShiftImm layout after
substituting that VISA prefix. The low 23-bit field then decodes entirely
through the public ShiftImm opcode table. The apparent following
Type1a/Type15b instructions began inside
the same 48-bit instruction; predecessor alignment alone did not fix the
successor width. `Type23p_undoc16` has therefore been removed. This correction
supersedes every earlier paragraph that calls `0x023e` standalone, reserved,
or a strict/frontier restart boundary, including the bounded-gate, startup and
frontier conclusions above. **[C][V]**

Reversing each little-endian loader parcel into architectural bit order gives
these exact selected-path instructions:

```
PC          architectural word  documented operation
0x1c133b    023e00300000        R0 = BSET R0 BY 0
0x1c13b7    023e00310000        R0 = BCLR R0 BY 0
0x1c0f8b    023e00300200        R0 = BSET R0 BY 2
0xb8b711    023e38108022        R2 = FEXT R2 BY 0:30
0xb8b723    023e3810c022        R2 = FEXT R2 BY 0:31
0xb8b7c5    023e7800f611        R1 = LSHIFT R1 BY -10
0x1ca57f    023e00300022        R2 = BSET R2 BY 0
0x1ca692    023e20100022        R2 = FEXT R2 BY 0:16
0x1ca6e9    023e00311922        R2 = BCLR R2 BY 25
```

An independent reviewer reproduced the loader bytes, per-parcel byte order,
all nine architectural words, the public decoder results and the corresponding
public ShiftImm operation descriptions. These exact unconditional operations
are verified. The generic form remains documented rather than fully verified:
the emulator does not implement its other predicates/opcodes, SIMD companion
effects, or documented ASTAT SS/SZ/SV updates, and the secondary decoder allows
one high field bit which the stricter PRM-derived mask fixes to zero. None of
those differences affects the nine words above. **[V][D][O]**

The tracer implements only the documented immediate operations encountered on
these selected paths. A strict reset-state run now crosses all three former
startup restart islands without a skip, performs the previously observed
BTB/cache/RCU/core-control accesses, and passes documented Type11c/Type12a
control flow. Its eight conservative predicate branches execute at least 6,952
instructions before stopping on a non-concrete register-counted loop or an
external-call boundary. Artifact:
`out/experiments/sharc-runtime-probe/strict-entry-type6b-004-summary.json`.
The old frontier restart hashes remain reproducible byte facts, but the
frontier's unsupported-island rationale and its resulting qualification limit
are superseded. **[C][V][O]**

Correct parcel sizing also changes the PCG-C slice. The sequence now reads
CTLC0 at `0xb8b70e`, extracts its low 30 bits at `0xb8b711`, and stores the
result back at `0xb8b714`; it reads CTLC1 at `0xb8b720`, extracts its low 31
bits at `0xb8b723`, and stores it at `0xb8b726`. The four previously selected
stores are ordinary documented read/mask/write operations and no longer cross
an unknown instruction effect:

```
0xb8b71d  SYNC2 = old SYNC2 & 0xfffffff9
0xb8b75a  CTLC1 = old CTLC1 & 0xfff00000
0xb8b7bc  CTLC0 = old CTLC0 & 0xc0000000
0xb8b801  PW2   = old PW2   & 0xffff0000
```

These formulas still do not provide the old values, subsequent set fields,
runtime handler selection, source clock or numeric cadence. A direct symbolic
entry at `0xb8b706` now crosses both former `0x023e` stops and records the
resulting PCG read/mask/write events, but remains non-qualifying because its
entry and branch state are not established from reset. Artifact:
`out/experiments/sharc-runtime-probe/pcg-type6b-001-summary.json`. **[C][V][O]**

Likewise, calibrated SPORT4A record selection now crosses the complete
`0x1ca698..0x1ca71b` suffix and reaches its return using documented semantics.
In addition to `0x1ca6e9: R2 = BCLR R2 BY 25`, the supported slice now covers
fixed-point AND/OR/XOR, variable and immediate BSET/BCLR/BTGL, Type6a's
parallel ShiftImm plus post-modify memory access. Selected MR/MRF data-move
and multiply-accumulate forms were also added for the earlier `0x1ca58a`
entry path, but do not establish the runtime inputs to this suffix. With
calibration-only `I4=-0x13c`, `0x1ca6c1` reads SPORT4A control base
`0x31002400` from `0x26969c`, and `0x1ca6c3` reads DMA10 base `0x31023000`
from `0x2696a0`.
No path state performs a concrete peripheral access: the store at `0x1ca6f9`
is `DM(I5,M5)=R9` in parallel with `R2=BCLR R2 BY 11`. It is not the DMA10
base store: `0x1ca5c9` loads its `I5` destination base from frame slot
`DM(I6+0x10)`, while `0x1ca5d1` copies incoming `I3` to its `R9` value.
The DMA10 base instead flows through `R0`: `0x1ca6c9` and `0x1ca6d1` load a
two-stage linked destination through `I4`, and `0x1ca6d6` stores `R0` through
that `I4/M5` address.

The compiler frame removes the earlier uncertainty around `0x1ca6f9`.
Type25a `CJUMP` executes `R2=I6, I6=I7`; its two delay slots save the prior
frame and return address. Replaying the four exact caller push sequences with
the documented 32-bit normal-word scaling makes the callee loads at
`0x1ca5c7` (`I3=DM(I6+0x8)`) and `0x1ca5c9`
(`I5=DM(I6+0x10)`) concrete:

| call | `I3`, copied to `R9` | `I5` | `0x1ca6f9` effect when reached |
|---:|---:|---:|---:|
| `0x1c78f6` | `0x2618d0` | `0x261960` | `DM(0x261960)=0x2618d0` |
| `0x1c798b` | `0x261918` | `0x261964` | `DM(0x261964)=0x261918` |
| `0x1c7a5f` | `0x261970` | `0x261a00` | `DM(0x261a00)=0x261970` |
| `0x1c7b12` | `0x2619b8` | `0x261a04` | `DM(0x261a04)=0x2619b8` |

`M5` is initialized to zero at `0x1c0f44` and is not reassigned on these
caller/callee paths, so `0x1ca6f9` installs four software-object pointers in
four global slots; it is not a DMA10 register or descriptor store. The DMA10
destination remains a different chain. If entry `I2` is `P`, then
`0x1ca6a6` gives `L1=DM(P+0x14)` and `0x1ca6c9` gives
`L2=DM(L1+0x14)`. With `M5=0`, `0x1ca6ce` installs SPORT4A base
`0x31002400` at `DM(L2)`. Then `0x1ca6d1` gives `L3=DM(L2+0x14)` and
`0x1ca6d6` installs DMA10 base `0x31023000` at `DM(L3)`. `P`, `L1`, `L2`,
and `L3` remain runtime inputs. Seeding `I5` with the DMA10 base would
therefore fabricate the wrong ownership join rather than discover it.
Artifacts:
`out/experiments/sharc-runtime-probe/sport4a-consumer-supported-002-summary.json`
and `sport4a-consumer-supported-002-trace.json`; the deterministic compiler
frame replay and exact-byte assertions are in `tools/sharc_interface_probe.py`.
This removes the remaining
decoder stop in the calibrated suffix but does not establish natural
`I4=-0x13c`, DMA10 ownership/descriptors, an application buffer, a first-word
writer, or production of `0x007fffff`. The natural marker chain and numeric
SSI cadence therefore remain open, and final A2 is still unqualified.
**[C][V][O]**

## The first strict-startup PM/PX loss is concrete; the next PM source is absent **[C][V][O]**

The earlier strict trace made every PM data load unknown, including the first
load in the helper at `0x1c0fb4`. Public SHARC documentation distinguishes the
combined 64-bit `PX` register from its 32-bit `PX1` and `PX2` halves. A
non-`LW` memory transfer through combined `PX` moves 48 bits into PX bits
63--16, so the upper two 16-bit memory parcels form `PX2` and the final parcel
occupies the upper half of `PX1`. The L1 block-3 normal-word and short-word
aliases begin at `0xe0000` and `0x1c0000`; 48-bit normal words occupy three
16-bit columns. `tools/sharc_trace.py` now models only this bounded,
loader-backed combined-PX case rather than treating arbitrary PM reads as
concrete. Independent review checked the register split and both DM- and
PM-bus handling against the public reference. **[V]**

In the 1.16 loader image, the direct Type14a PM read at `0x1c0fb4` addresses
normal word `0xe00e0`. It maps to loader/system byte address `0x28380540`,
covered by loader block 87; its exact six bytes are `00 00 00 00 00 00`, so
both PX halves are zero. The following documented moves therefore copy
`PX2=0` through `R0` to `I8`. The next Type3b PM read at `0x1c0fbd`
consequently addresses absolute normal word zero. That address is outside the
bounded block-3 mapping; direct loader checks find no record at byte addresses
`0` or `0x28000000`. (The record at `0x28380000` is block-3 normal word
`0xe0000`, not normal word zero.) The tracer therefore invalidates `PX`,
`PX1`, and `PX2`; it does not preserve the earlier zero or invent contents.
The six downstream Type12a paths still stop on non-concrete register loop
counts, while two sibling paths stop at the same external-call boundary as
before. Artifact:
`out/experiments/sharc-runtime-probe/strict-entry-pmpx-005-summary.json`.
Independent review reproduced the raw loader block and instruction bytes, and
an independent execution of the same bounded command reproduced all eight
terminal states and the absence of target-peripheral accesses. **[C][V][O]**

This narrows the initialization gate: Type12a loop semantics are not the first
loss, and the loader-backed `0xe00e0` read is no longer unknown. The next
missing input is the PM source at normal-word address zero, plausibly outside
the section-7 image but not yet identified as a specific ROM or other memory
provider. The run still reaches no PCG-C, SPORT4A, or DMA10 initialization and
does not derive `I4=-0x13c`. **[V][O]**

ASTAT work is also deferred: the public tables document PASS/COMPARE arithmetic
flags, but the currently implemented strict
predicates consume `TF`, so adding inferred shift flags would not move this
frontier. **[D][O]**

The separate Type25 PC-relative audit found no arithmetic defect: the 24-bit
displacement is sign-extended, added to the instruction's own short-word PC,
and remains in short-word units. A Type25-specific negative synthetic
regression now checks this convention. No loaded firmware Type25 negative
target was found, so this closes a test gap rather than authorizing a new
loaded-call edge. **[D][O]**

## PASS/EQ removes the low-PM false path, and Type25 wraps at 24 bits **[C][V][O]**

The preceding PM-address-zero blocker and ASTAT deferral are retracted. At
`0x1c0fb4` the loader-backed combined-PX read still produces concrete zero;
`0x1c0fb7` copies PX2 to R0, and `0x1c0fb9` performs documented fixed-point
`PASS R0` while also copying R0 to I8. PASS clears AC/AI/AS/AV and sets AN/AZ
from the 32-bit result, so zero sets AZ. The `IF EQ RTS` at `0x1c0fbc` is
therefore taken in concrete SISD execution. The feasible strict path returns
before `0x1c0fbd`: it never reads PM normal-word address zero, and the six
downstream Type12a failures disappear. Unknown PASS inputs invalidate ASTATX
rather than preserving stale flags. **[C][V]**

The preceding Type25 arithmetic conclusion is also retracted. Sign extension
and addition to the instruction's own PC were right, but the sequencer target
must then be reduced to the architectural 24-bit short-word PC. At
`0x1c0fa5`, storage bytes `44 18 9c 00 3d 84` normalize to
`0x1844009c843d`; its signed displacement is `-6519747`, and the wrapped
target is `0xb893e2`, not a negative external address. That target maps through
the loader's L2 fallback to byte address `0x200127c4` in block 69, interval
`[0x20000000,0x2001ab7c)`. The strict trace now follows this as its third
loaded call. **[C][V]**

## Enhanced Type19a `(NW)` advances strict startup to `0xb893fb` **[C][V][O]**

The earlier `Type19p_undoc48` classification and every `-257` / `I7 -= 0x404`
interpretation are retracted. At loaded SW `0xb893e2`, exact bytes
`87 15 ff ff fe ff` are three little-endian 16-bit parcels in
most-significant-parcel order, producing logical word `0x1587fffffffe`.
The SHARC+ PRM documents `sc=01` as enhanced Type19a address scaling, and the
public Selache encoder/decoder independently confirms fields `w=1`, `g=0`,
`idis=0`, `is=7`, signed immediate `-2`. The instruction is therefore
`I7 = MODIFY(I7,-2)(NW)`. **[C][V]**

`tools/sharcspec/build_table.py` now emits this prefix as confident
`Type19a_scaled`, while preserving the ordinary classic `0x16` Type19a form.
The strict tracer scales `(NW)` by four only in its explicit byte-address
model, applies the same scaling to the active circular length, and leaves B/L
unchanged. The observed entry state is `I7=0x26f7ee`, `B7=0x26f000`,
`L7=0x1fd`; the documented operation produces `I7=0x26f7e6` without wrapping.
In normal-word address space the architectural update remains `I7 -= 2`.
Synthetic tests cover both interpretations and a negative circular wrap.
An independent loader-aware review reproduced the image hash, L2 fallback
mapping `0x200127c4`, source block 69, exact six bytes, parcel normalization,
fields, and both trace endpoints. **[V]**

A new strict run begins at real entry `0x1c1338` against exactly
`out/sections/dt2-1.16/section_7_BLOB.bin` (SHA-256
`0f514a12a2255f5c081e292c47f1f29462003177658da4bbae0a22fd737fffa2`),
with loader-backed concrete memory, public core reset state, 32-bit normal
words and loaded-call following. It naturally executes the enhanced MODIFY,
then ends in two states after 6,987 / 6,989 instructions at the same next
boundary: Type2a at `0xb893fb`, whose full-compute field has `cu=0`, opcode
`0x00`. The public PRM's ALUOP table has no `0x00` operation, and the independent
Selache decoder also leaves it as an unknown ALU opcode, so no semantics are
invented for it. Both states record three loaded calls and no PCG-C, SPORT4A or
DMA10 access. Artifacts and SHA-256:

```
out/experiments/sharc-runtime-probe/strict-entry-type19nw-008-summary.json
7d69408b76fb262e9d03295a9632c7fb2cac90e6ed95474b90ba60489bbd9094
out/experiments/sharc-runtime-probe/strict-entry-type19nw-008-trace.json
3195e941880eaa32005db6a1c2186060e3a943a7be34afcdb7f4334522591cd6
```

This advances the qualifying continuous path but still does not reach PCG-C,
SPORT4A or DMA10 initialization, derive `I4=-0x13c`, identify the natural
`0x007fffff` producer, or establish numeric SSI cadence. A2 remains open and
A3 remains parked. **[V][O]**

**[C]** `0xb893fb` is not an undefined ALU opcode. It is a 32-bit compute,
`R2 = LEFTZ R8`, read with the wrong width. See the next section.

## Tracer decode and call-model corrections move strict startup to `0x1c1460` **[C][V][O]**

Six defects in the decoder and in `tools/sharc_trace.py` caused the startup,
callback and `0x1ca7e4` stops recorded above. With them fixed, a strict run
from `0x1c1338` runs to step 7,545 and stops at a different, earlier-unseen
boundary. The run uses the same image
(`out/sections/dt2-1.16/section_7_BLOB.bin`, SHA-256
`0f514a12a2255f5c081e292c47f1f29462003177658da4bbae0a22fd737fffa2`) and
flags as before, with at most 1,024 states. **[C][V][O]**

### `0x01` words with bit 39 set are 32-bit computes **[C][V]**

The decoder read every VISA word with first byte `0x01` as 48-bit Type2a.
When frame bit 39 (bit 7 of the first parcel) is 1, the instruction is 32
bits wide: an unconditional compute whose 23-bit field is
`((parcel1 & 0x7f) << 16) | parcel2`, frame bits 38:16. The public Selache
decoder applies this width rule to every `0x01` word (`selinstr/src/visa.rs`,
`visa_width`: "Type 2: sub5=00001, bit7=1→32b, bit7=0→48b";
`decode_32_type2b`). The PRM has no 32-bit form for this prefix. Its Type2b
(prefix `0xc0`) is a different encoding.

In the aligned Digitakt II 1.16 sweep (`tools/sharcflow.aligned`, minimum
depth 8), 1,880 of 2,396 Type2a words have bit 39 set. For them, the next
word decodes confidently 4 bytes later in 99.1% of cases and 6 bytes later
in 49.0%. For the 516 words with bit 39 clear, the 48-bit reading gives
92.4%. A second agent recomputed these numbers from the image and quoted the
Selache source. **[V]**

`tools/sharcspec/build_table.py` now emits the form as confident
`Type2a_short` (mask `0xff8000000000`, value `0x018000000000`, VISA only).
Classic ISA decoding keeps Type2a. In the aligned 1.16 sweep,
`Type21p_undoc16` words drop from 513 to 11 and `Type22p_undoc48` words from
75 to 2. `tools/sharcpcode.py compare` reports no regressions on the three
images. The earlier boundaries read as follows: **[C][V]**

| PC | earlier reading | 32-bit reading |
|---:|---|---|
| `0xb893fb` | Type2a, undefined ALUOP `0x00` | `R2 = LEFTZ R8`, then a relative jump to `0xb8941e` |
| `0xb8783f` (lock routine `0xb87838`) | Type2a, then undoc16 `0x0000`, `0x001d` | `R2 = LEFTZ R2`, then a relative jump to `0xb8785e` |
| `0xb8c615` | Type2a, then undoc16 `0x0000`, `0x001a` | `R1 = BTGL R2 BY R1`, then a relative jump to `0xb8c631` |
| `0xb8b0eb`, `0xb8b141` | Type2a, then undoc16 pairs | `COMPU(R4, R2)`, then relative jumps to `0xb8b114`, `0xb8b164` |

The callback stop at `0x1c0efa` also goes away: the tracer reached it through
the misaligned stream. The `0x0000` words there remain undocumented where
they really occur. **[V]**

A whole-image width comparison against Selache on the three images finds
364, 395 and 434 other disagreements. By the same successor test every one
favours the existing table. For example, reading Type4a words with first
parcel bit 0 clear as 32-bit (Selache's rule) makes `Type21p_undoc16` words
four times more common. **[V]**

### A delayed call returns after its second delay slot **[C][V]**

The tracer returned from every delayed call to call + 7 short words. The
firmware's CJUMP returns in software: the second delay slot stores
`own address + 2`, the callee loads that value into I12, and
`JUMP (M14, I12) (DB)` with M14 = 1 continues after the store. After a 16-bit
`3c` push that is call + 7; after a 48-bit `3a` push it is call + 9. The old
rule returned two short words into the store and decoded half of its literal
as `Type22p_undoc48`. The stops at `0xb89376` (strict) and `0xb868c0`
(callback) were this artifact. In the strict run the epilogue now loads
I12 = `0xb89409` for the call whose return is `0xb8940a`. **[C][V]**

### Indirect branches use DAG2 registers **[C][V]**

`JUMP/CALL (Md, Ic)` uses DAG2: Ic is I8-I15 and Md is M8-M15 (SHARC+ PRM,
DAG chapter: "DAG2 supports indirect branch addressing"; ADSP-2136x PGR:
"Ic indicates a DAG2 index register (I15–8)"). The return idiom
`0x083f343f` (`pmi=4`, `pmm=6`) is therefore `JUMP (M14, I12) (DB)`. The
tracer now checks that I12 + M14 equals the recorded return when both are
known; in the strict run four returns are checked and all match. Other
Type 9 jumps now go to I(8+pmi) + M(8+pmm) when both are known. **[C][V]**

### Type3a and Type6a scale the modifier under 32-bit normal words **[C][V]**

The Type3a and Type6a memory handlers added M to I unscaled, while every
other normal-word access scales it by 4. In the strict run, a Type3a push
`DM(I7,M7)=R2` in a nested call moved I7 by one byte, and the next store
overwrote the saved I6. With scaling, RFRAME restores I6 = `0x26f7e0` and the
return check above passes. **[C][V]**

### Status flags and conditions **[V]**

The tracer now updates ASTATX per the PRM instruction pages: add, subtract,
increment, decrement and negate set AC/AV/AN/AZ and clear AS/AI/AF; pass,
not, and, or and xor clear AC/AV/AS/AI/AF and set AN/AZ; comp and compu also
shift CACC; the shifter operations set SZ, SV and SS as each page states
(for example, LSHIFT sets SV for any left shift, and LEFTZ sets SV when the
result is 32); multiplier operations make MN/MV/MU/MI unknown, and the MR
data move clears them. ASTATX is tracked per bit, so an operation that
defines some flags does not need the others to be known. The conditions
LT, GE, LE and GT follow PGR p.4-93 / PRM p.4-53, with
X = (¬AF ∧ (AN ⊕ (AV ∧ ¬ALUSAT))) ∨ (AF ∧ AN) ∨ AZ (LE is X, GT is ¬X) and
Y = (¬AF ∧ (AN ⊕ (AV ∧ ¬ALUSAT))) ∨ (AF ∧ AN ∧ ¬AZ) (LT is Y, GE is ¬Y).
AC, MV, MS, SV and SZ conditions read their bits. Identical states are
merged. Before these changes the strict run split into 1,072 states; it now
follows one path to step 7,058 and 66 paths after that. **[V]**

### Current boundaries **[V][O]**

All 66 strict states stop at `0x1c1460`, raw `0x04bfc0800000`, which the
table decodes as uncertain Type7d. The PRM ACONV table (p.355) suggests
`I7 = B2W(I7)`; this is not yet checked. No state reaches PCG-C, SPORT4A,
DMA10, `0x1ca6d6`, `0x1ca7e4` or the marker store. The only access in
`0x31000000..0x310fffff` is the RCU0+0x2c store at `0x1c1414`. **[V][O]**

The callback replay from `0x1c7749` is calibration, not qualification. It
reaches the marker store `0x1c7586` in 118 of 1,041 states. The store writes
`0x7fffffff` to `I4 + M5*4`, but M5 is not set on that entry path, so the
buffer is not resolved. Its other stops are `0x1c7521`
(`JUMP (M13, I12)` with unknown registers) and, before the negate above was
added, `0x1c7599` (ALU `0x22`). **[O]**

### Static results for the DMA/SPORT slice **[D][O]**

- `0x1ca7e4` has four direct callers, each with an immediate R8:
  `0x1c7971` (`0x2620c8`), `0x1c79f8` (`0x262100`), `0x1c7af9`
  (`0x264138`), `0x1c7b9e` (`0x264170`). The image holds no literal
  `0x1ca7e4`, so no pointer table calls it. **[D]**
- For the two large lists, R4 is the slot that the setup call `0x1ca58a`
  has just filled: `R4 = DM(0x261a00)` at `0x1c7a6a` for `0x264138`, and
  `R4 = DM(0x261a04)` at `0x1c7b1d` for `0x264170`. The SPORT/DMA object P
  arrives in I2 and is not written in `0x1c7749..0x1c7b9e`. Whether P and the
  slot object are the same is open. **[D][O]**
- `0x1ca7e4` reads the byte at R4+0x30 (`0x1ca802`). One branch at
  `0x1ca807` returns at once; the other calls the lock routine `0xb87838`
  before any descriptor work. **[D]**
- No instruction or data word in the image holds an absolute SPORT4A/B or
  DMA10/11 register address. The one data word `0x31023000` is the SPORT
  record field at DM `0x2696a0` (`0x26968c + 0x14`). The driver can reach
  these registers only through the object chain. Two agents found this with
  different methods. **[V]**
- No writer of the selector DM `0x25f780` was found; it is read at
  `0x1c7524`, `0x1c7578` and `0x1c75b6`. **[D][O]**
- The template CFG word `0x00100000` sets only INT. EN, WNR, FLOW, NDSIZE,
  MSIZE and PSIZE are 0, and MSIZE/PSIZE 0 are not listed values
  (ADSP-2156x HWR, DMA_CFG fields, pp.1286-1293). The word cannot be the
  final DMA10_CFG value; `0x1ca7e4` or its callees must add fields. **[D][O]**
- `0x007fffff` is `0x7fffffff >> 8`, the top 24 bits. The HWR says SPORT
  words shorter than 32 bits are right-justified in the transmit buffer
  (p.1050), which would send the low 24 bits. The link must use another word
  length, packing or framing. The SPORT4A control value is still unknown.
  **[D][O]**

## Type 7 corrections carry strict startup into the DAI setup **[C][V][O]**

### Type7a keeps its modifier register **[C][V]**

`tools/sharcspec/build_table.py` dropped frame bit 29 of Type7a. Its merge
rule handles a bit the PRM prints and the classic grid leaves blank, and a bit
both fix, but not a bit the classic grid declares a field and the PRM figure
does not bracket. Bits 29-27 are the M register selector, the field Type7b's
own PRM figure carries at the same place, and the PRM figure brackets only 28
and 27 because it prints the same bits its Type7d ACONV figure names `breg`
and `toby`. With the field restored, the tracer applies the modifier with the
documented normal-word scaling. Before this, every Type 7a modify lost its
index register: `MODIFY(I7, M7)` at `0xb8946a` made the stack pointer unknown,
and the frame stayed unknown for the rest of the run. **[C][V]**

### Type7d is ACONV, and the strict run executes it **[C][V]**

PRM Table 14-22 gives Type 7d as the Type 7a word whose condition is 11111 and
whose compute field is empty, so those bits select the form. They are now
pinned into its mask and the form is confident. PRM Table 6-4 (p.6-16) gives
`Id = B2W(Is)` as "Likely semantics Id <- Is >> 2", with `W2B` the mirror,
hedged by "Exact semantics depend on address map" and an illegal-address trap
for addresses with no equivalent. The handler applies the shift, marks the
event as the manual's likely semantics, and stops rather than guess when the
source is unknown.

The firmware corroborates the pair. At `0x1c1460..0x1c1478` eight ACONV words
convert I7, B7, I6 and B6 to word addresses and back again:

```text
0x1c1460  b2w  I7  0x26f7f0 -> 0x9be7c
0x1c1463  b2w  B7  0x26f000 -> 0x9bc00
0x1c1469  b2w  I6  0x26f7f0 -> 0x9be7c
0x1c146c  b2w  B6  0x26f000 -> 0x9bc00
0x1c146f  w2b  I7  0x9be7c  -> 0x26f7f0
0x1c1472  w2b  B7  0x9bc00  -> 0x26f000
0x1c1475  w2b  I6  0x9be7c  -> 0x26f7f0
0x1c1478  w2b  B6  0x9bc00  -> 0x26f000
```

The round trip is exact, and the tracer's own return check agrees: every
`JUMP (M14, I12)` return in the run matches the call it came from. **[V]**

### Type14d and Type15a **[V][O]**

Both gain handlers from their PRM pages. Type15a is already confident, with
270 aligned instances in 1.16. Type14d stays uncertain, and a second agent
checked why: its PRM figure is transcribed correctly, but nothing independent
pins its seven fixed bits. There is no classic form to compare (its fixed bits
differ from Type14a at bit 42), no cross-reference table like the one that
settles Type7d, and the public Selache decoder models the form wrongly: it
requires bit 40 to be 1, which is the direction field, so it misses every load,
and it decodes the register as a universal register with a blanket width
suffix where the PRM restricts it to the R register file and gives six width
and extension rows. Promoting it on firmware counts alone would set a
precedent for every SHARC+-only form, so it waits for a decision. **[O]**

Instead, `tools/sharc_trace.py` takes `--allow-provisional-form NAME`, which
executes a named unconfirmed form and records it on every state that used one.
Any run that names a form is calibration, never qualification. **[V]**

### Startup stops at a boot-source probe **[V][O]**

The strict run is boot bring-up code. It configures the caches and MODE1,
clears a block of DM, then probes two candidate boot sources in a loop: it
reads `DM(0x80000010)`, which the image provides as 0, and then
`DM(0x10000000)`, which no section of the firmware populates. The branch on
that second read forks, and the path that falls through jumps through
`JUMP (M13, I13)` at `0x1c144c` with I13 holding the value just read. The
target therefore depends on what the hardware has at that address, not on
anything in the image. This is a real boundary, not a tracer gap. **[V][O]**

The qualifying strict run ends in two states: `0x1c144c` above, after 7,545
instructions, and `0xb8cdaf`, an unconfirmed Type14d, after 7,566. **[V]**

### The calibrated continuation reaches the DAI setup **[D][O]**

With `14d` named as a provisional form, and therefore as calibration, the run
reaches 11,597 instructions and executes the DAI and PADS setup at
`0x1cb28e..0x1cb323`. It writes exactly the 34 DAI stores and the two PADS0
stores already recorded from a direct entry, including `0x3def7b9c`,
`0x3ef83fbe`, `0x0fdf9d38` and `0x000fffff`, and it also resolves the three
stores that run left open: `0x310c91e4` takes 1, `0x310c91e8` and `0x310c91ec`
take 0. Every one of the 3,730 returns checked in that run matches its call
site. **[D]**

The run still reaches no SPORT4A, DMA10 or PCG register, so the cadence and
framing questions stay open. It ends on the state budget, on a floating-point
compare (ALU opcode `0x8a`, PRM Table 18-5) that the tracer does not model,
and on the boot probe above. A block of about 295 accesses in
`0x3108b000..0x3108bc20` is not named in these notes and looks like a table
being cleared. **[O]**

## The SHARC machine-type consumer: received and cached, no dispatch found **[D][O]**

Investigated 2026-09-20 to decide whether a new machine needs SHARC synthesis
code (roadmap A5). Static reads only (loader-backed `decode_at`), so INFERENCE,
not qualified. Three passes over `out/sections/dt2-1.16/section_7_BLOB.bin`
(sha `0f514a12...`):

- **Receive site (reproduces existing [V]).** The `0x94 + 2i` machine word is
  read and change-tested at `FUN_001c2b24` (call `0x1c771e -> 0x1c2b24`; load
  `0x1c33d2`, `R0 = DM(I0,M0)`; compare `0x1c33d7`; equal/not-equal paths join
  at `0x1c33e9` and store a derived scalar to `DM(I5+0xc4)`). It is a
  change-detector, not a dispatch, and carries **no bound/range check** against
  the ColdFire's 0..6 machine range. `FUN_001c2b24`'s sole caller is `0x1c768c`
  (Ghidra: 1 caller); `I5` there derives from an argument of `0x1c768c`'s own
  caller, so the **absolute DM address of the per-track machine cache is not yet
  pinned** (`DM(I5+0xc4)` is frame-relative). **[D][O]**
- **No per-machine dispatch table in the scanned regions.** A whole-image scan
  for runs of >=5 consecutive code-address words (main program `0x1c0000` region
  and the L2 driver overlay `0xb8xxxx` -- everything the loader stream populates)
  found only: the already-documented RPC command table (`DM 0x2577c4`, 11
  entries), the documented PCG 4-pointer table (`DM 0x2d7158`), and ADI SSL
  driver-service bookkeeping in the `0xb87xxx-0xb8dxxx` overlay (one run adjoins
  the ASCII string `"ASSERT [ADI_GPIO_CALLBAC..."`). No table of distinct
  synthesis-routine targets exists in that data. The 12 indirect calls
  (`COMPUTED_CALL`, raw `0x3f083f2c`, the documented idiom) are spread across 12
  unrelated functions and load their targets from locals, not an indexed table;
  none was shown machine-keyed. **[D][O]**
- **Not ruled out:** a compiler-emitted compare-chain dispatch (up to seven
  `type==N` branches, no table -- invisible to a data-table scan); the readers of
  the (unpinned) machine-cache DM address; and code in the external-memory blocks
  the loader places at `0x8045a6c8` (DT2 1.16 loads only 3,316 bytes there).

**The real gap: the SHARC audio synthesis engine is unlocated.** These passes,
like the prior interface work, stayed in the control/bring-up code (frame
receive, SPORT/PCG/DMA, boot). No per-frame/per-voice audio-render routine -- the
code that reads the sample buffers and produces output for SPORT/SSI -- is named
anywhere in FINDINGS. A whole-image scan did turn up float ramp/interpolation
tables in external memory (near `0x8055c840`), a plausible synthesis-table lead.
All DT2 machines are sample-based variants (SAMPLE/WERP/STRETCH/REPITCH/SLICED/
MANUAL SLICE), which makes a single parameter-driven sample engine (machine type
selecting a mode/params) at least as plausible as separate per-machine kernels.
Deciding A5 -- and building a machine that makes a new sound -- needs that engine
located first. **[O]**

## The SHARC audio engine: ingredients located, control flow runtime-assembled **[D][O]**

Three parallel static passes (2026-09-20, loader-backed `decode_at` on
`section_7_BLOB.bin` sha `0f514a12...`) hunting the per-voice synthesis engine.
They located the engine's *ingredients* but not its running control flow; the
edges are runtime-established, so static analysis stalls here and the emulator
(gated by A2) is the natural next tool. OBSERVATION unless marked INFERENCE.

**Audio output buffers (OBSERVATION).** Four DMA descriptor rings, all built by
the same `0x1ca58a` setup + `0x1ca7e4` submit, all with config `0x00100000`
(decoded against ADSP-2156x HWR DMA_CFG: EN=0, WNR=0 = **transmit**, INT=1 =
interrupt on X-count) -- so all four are output/transmit, none receive:
- Ring A: head `0x2620c8`, buffers `0x261cc8`/`0x261dc8`, 256 B (setup/submit
  `0x1c792f`/`0x1c7971`); Ring B: head `0x262100`, `0x261ec8`/`0x261fc8`, 256 B
  (`0x1c79c4`/`0x1c79f8`).
- Ring C: head `0x264138`, buffers `0x262138`/`0x262938`, 2048 B
  (`0x1c7ab7`/`0x1c7af9`); Ring D: head `0x264170`, buffers `0x263138`/`0x263938`,
  2048 B (`0x1c7b6a`/`0x1c7b9e`) -- a second full ping-pong ring, new to the crib
  sheet. The two 2048 B rings are the audio-output ping-pong pairs (INFERENCE:
  candidates for SPORT4A-TX / SPORT4B-TX). No literal reference to any ring
  buffer exists outside descriptor construction -- the render loop writes them
  through a runtime pointer, so the writer is not findable by literal scan.

**Synthesis tables + reader code (OBSERVATION).** Only two real external float
payloads load (rest of `0x80xxxxxx` is FILL/zero scratch), LE float32:
- Block A `0x8045a6c8`, 829 floats: exponential curve, denormal -> exactly 1.0
  (INFERENCE: pitch/note-to-freq or dB/exponential envelope map). Loaded at boot
  by `0x1c1686` (`R8 = 0x8045a6c8`) then passed to a `25a_direct` call at
  `0x1c168c -> 0x1c7442` with a second (internal) address -- the shape of a
  boot-time copy/expand into internal memory.
- Block B `0x8055c440`, 2324 floats. Table1 (idx 0-255, `0x8055c440..0x8055c83c`)
  is a **folded quarter-wave cosine**, `value(k) ~= cos(min(k,256-k)*pi/256)` --
  the classic single-table sin/cos generator. Read at `FUN_1c71ec` via two DAG
  pointers 128 words apart: `I5 = 0x8055c440` (`0x1c724f`, value 1.0) and
  `I5 = 0x8055c640` (`0x1c7247`/`0x1c7263`, the fold-point, value 0.0). Table2
  (idx 256+) is another exponential-shaped curve with a discontinuity past the
  DT2 payload boundary (DN2 1.11 loads far more here); read at `0x1c6c16`
  (`I4 = 0x8055c874`) inside a large routine `~0x1c6156..0x1c71e7`.
- **Boot-time relocation hypothesis (INFERENCE):** if the tables are copied into
  internal SHARC memory at boot (`0x1c1686 -> 0x1c7442`), the real per-frame
  synthesis reads *internal* addresses and would never appear in an `0x80xxxxxx`
  literal scan -- which explains why no per-frame render loop was found touching
  these addresses. Verifying this needs decoding `0x1c7442`.

**Per-track processing structure (OBSERVATION).** `FUN_001c2b24` (the frame-RX
consumer) contains a **uniform 16-track counted loop** (`0x1c2c97`, `TRACKS=16`)
that calls **one** routine `0x1c24e9` per track with a `track*0x60` (96-byte)
stride -- no per-machine branch at this level. `0x1c24e9` computes the per-track
stride, reads `DM(0x255934)`, and hits an ALU `MAX` (opcode `0x62`, PRM Table
18-5) the tracer does not model -- a clean decode boundary, a candidate
clamp/limit step; decoding past it is the top per-track lead. Separately,
`FUN_001c2b24` reads per-track TX-mirror fields `{0x54, 0x73c, 0x75c, 0x94}` off
base `I4`/`I1` and caches a derived word to `DM(I5+0xc4)`. Unit note: `Type19a`'s
16-bit offset is a byte literal (`0x94`, `0x73c`...), while `Type15b`'s 7-bit
field is a normal-word index (`49*4 = 0xc4`) -- reconciles the `+0xc4` cache
offset. A whole-image `Type19a` scan found 8 other routines
(`~0x1c8900..0x1cd600`) forming pointers to the same `0x34`/`0x54` per-track
fields; none is reached by a direct call, none decoded past pointer formation --
the most promising concrete lead for a follow-up decode pass.

**Why static stalls (INFERENCE).** The engine's control flow is runtime-built:
its routines (`FUN_001c2b24`, `FUN_1c71ec`, the table readers, `0x1c24e9`) have
no static direct callers -- they are entered via tasks/callbacks or the image's
12 unresolved indirect calls (`COMPUTED_CALL`, raw `0x3f083f2c`); the tables are
relocated to internal memory; the output buffers are addressed by runtime
pointers; and per-track state (`I5`) is stack-relative off a runtime `I6`. So the
ingredients are now mapped but assembling them into the running per-frame engine,
and proving whether any per-machine branch hides deep in `0x1c24e9` or the render
kernel, needs dynamic execution.

**Bearing on "does a new machine need SHARC code" (INFERENCE, strengthened but
not proven).** Every static level examined -- receive/cache, the 16-track loop,
the synthesis tables (general DSP primitives, not per-machine), and the absence
of any dispatch table -- points to a **uniform, parameter-driven engine** where
the machine type is one per-track parameter, not a selector of separate kernels.
If that holds, a new machine is largely a new parameter/mode configuration
(ColdFire-side, where `tools/machinepatch.py` already clones a machine slot),
not new DSP code. Unproven: the undecoded tail of `0x1c24e9`, the 8 field-reader
candidates, and any branch inside the (runtime-only) render kernel could still
hide per-machine behavior. **[D][O]**

**Firming pass (2026-09-20): the per-track routine and field readers are uniform
(OBSERVATION).** Two decode passes closed the leads the paragraph above left open:
- `0x1c24e9` (called once per track from the 16-track loop) fully decoded, entry
  to return: 396 instructions, a leaf (zero CALLs), no loop, no computed/indirect
  jump but its own return. No `comp`/`compu` ALU op anywhere and no
  AZ/AN/LT/LE/GT/GE-conditioned branch -- none of the shape a `switch(type)` or
  `if(type==N)` chain needs. Its four conditional branches all test the
  shifter-zero flag right after a bit-toggle/shift (per-track boolean flags), and
  the FINDINGS "MAX at 0x1c2530" is now resolved as a two-sided clamp
  `R1 = min(max(R1,R3),R4)` (`0x1c2530` MAX, `0x1c2532` MIN). The body is a float
  convert/multiply/clamp/bit-test parameter pipeline addressed through I6 (word
  indices 5-126); it never reads the machine-type cache word (index 49 / `0xc4`
  absent). Full-body OBSERVATION, not inference: `0x1c24e9` is uniform, no
  per-machine dispatch.
- Of the 8 other per-track field (`0x34`/`0x54`) readers, six decode as uniform
  (generic field marshalling; a shared compiler check idiom -- byte-identical
  `2a_short` computes recurring across unrelated routines; and `0x1c9fd5`'s
  count-bounded callback-registration loop). No compare-chain against 0..6 and no
  indexed jump in any of them.
- **Two residual sites, not closed:** `0x1cc225` (`comp(R9,R14)` -> EQ; `R9-1==0`
  -> EQ) and the twins `0x1cc44e`/`0x1cc4cb` (`compu` vs literal `3` -> GE) have
  genuine two-way compares, but their non-constant operand was not traced to the
  machine-type field. A two-way test against a register or the literal 3 cannot
  by itself select among 7 machines, so these are unlikely to be a machine
  dispatch (more plausibly a stereo/mode/bounds flag); provenance untraced. **[O]**

Net: the "uniform parameter-driven engine" reading is now OBSERVATION at the
per-track processing routine and 6/8 field readers, with two two-way compares and
the runtime-only render kernel the only residual uncertainty. A second-agent
byte-check is still owed before any of this is marked **[V]**.

Tool gap noted: `tools/sharc_trace.py` `_execute()` has no case for Type
`8a_rel`/`8a_abs`, so symbolic runs stop at the first Type8a branch -- worth
adding for future SHARC symbolic tracing (and the A2 work). **[O]**


## The frame displacements are raw ColdFire bytes, unscaled **[V]**

Settled, and it matters because every offset claim about the DSP's view of the
frame depends on it. `FUN_001c2b24` forms its frame pointers with SHARC+ form
**`19a`** (plain, not `19a_scaled`) -- a 48-bit `Ireg += imm32`. Decoding the
`data` fields directly:

| addr | form | I-reg | data | hex |
|---|---|---|---|---|
| `0x1c2cc1` | 19a | I4 | 1884 | `0x75c` |
| `0x1c2ccb` | 19a | I1 | 148 | `0x94` |
| `0x1c2cd7` | 19a | I4 | 1852 | `0x73c` |
| `0x1c33da` | 19a | I4 | 84 | `0x54` |

All four match the ColdFire byte literals in value *and* register.

The proof does not even need the ColdFire side. The TX frame is `0x802` = 2050
bytes (`tools/framelink.py` `TABLES`). Word-scaled (x4), `0x73c`/`0x75c` would be
bytes 7408/7536 -- more than three times the whole frame. Short-word scaled (x2)
gives 3704/3768, still past the end. Only the raw-byte reading fits.

The contrast is instructive: the same function's prologue at `0x1c2b24` uses
`19a_scaled` (`I7 += -48`, normal-word, = -192 bytes, a stack allocation). Two
visually similar forms, two different units. The frame-pointer code consistently
uses the unscaled one.

## `FUN_001c2b24` makes 32 calls with an integer, not 16 with a pointer **[C][V]**

Corrects the "Per-track processing structure" note above, which recorded
`FUN_001c2b24` as calling `0x1c24e9` **once per track**, 16 times.

The hardware `LCNTR` loop is set up at `0x1c2c94` (form `12a_imm`, count 16) with
body `0x1c2c97`-`0x1c2cb2`. Each iteration makes **two unconditional calls** to
`0x1c24e9`, passing a plain incrementing integer in `R12`: `R12=R13`, call,
`R13++`, `R12=R13`, call. Across the loop the argument runs 0..31.

So it is 32 calls, and the argument is a small integer -- not a track-relative
frame pointer. Sixteen tracks x two is the obvious reading (stereo, or two voices
per track) but that is inference, not shown. The consequence for the frame work
is that `FUN_1c24e9`'s own `I6` addressing (word range 5-126, previously
documented) is **not** shown to be the ColdFire frame; it is more likely that
routine's own stack frame, with the real parameter access derived from `R12` by
code not yet traced.

## No read of the frame's per-track parameter block found yet **[D][O]**

The ColdFire places the four parameter pages in a per-track `0x60`-byte block at
frame byte `0xda + track*0x60` (see `04-coldfire-dsp-link.md`, "The mirror index
to TX frame map"). Two independent searches over the whole main program block
(blk93, file offsets `0x31c3c`-`0x4b470`, 104,500 bytes, decoded sequentially
with resync-on-desync: 22,646 instructions, 99.3% confident, 8 desync points
losing ~16 bytes) found **no read site**:

- **Literal displacements.** Zero `19a`/`19a_scaled` instructions anywhere carry
  `0xda`, `0xfa`, `0x116`, `0x130`, `0xde` or `0xe6`. The already-known scalar
  fields do recur as expected (`0x54` x4, `0x94` x2, `0x73c`, `0x75c`), matching
  the "8 other per-track field readers" already recorded -- so the method does
  find real frame reads when they exist.
- **Stride `0x60`.** The literal 96 appears 19 times in blk93 and every one is
  explained: consecutive stack-slot indices in prologues (`I6+90,91,...,98`,
  callee-saved spill areas) or unrelated small constants. No `I += 0x60` and no
  M-register modifier load of `0x60`.
- `0xec` (LEV) produced three in-region `19a` hits, all investigated and rejected
  as value collisions: `0x1c5b57` sits in a run of consecutive-by-one offsets
  (52,53,54,55,56 -- a byte/flags struct), and `0x1c6a90`/`0x1c6ebd` sit inside
  the synthesis-table reader alongside sibling adds of 72, 212, 20 and 300 off
  the same base, none of which match any frame field.

**What this negative does not cover**, stated precisely per the repo rule:

1. Pointer arithmetic synthesised by shift/add rather than a literal -- a
   compiler can build `track*0x60` as `(t<<6)-(t<<5)` and never materialise 96.
   No `0x60`-into-register load was found to seed such a multiply either, but
   shift/add combinations were not exhaustively enumerated.
2. De-interleaving done in the SPORT/DMA descriptor rather than in program code,
   in which case no program literal would exist. The frame's receive-side DMA
   descriptor construction was not inspected.
3. The interior of `FUN_1c24e9` past its prologue. Only the caller side was
   traced.

Point 3 is the strongest remaining lead: `FUN_1c24e9` is the 396-instruction
uniform per-track routine with no per-machine branch, it is called 32 times with
an integer 0..31, and an index-to-address computation inside it is exactly the
shape that point 1 says a literal search cannot see.

## The ColdFire frame is mapped into SHARC DM at `0x2558dc` **[V]**

The link's other end, found by decoding `FUN_1c24e9` and reading its literal
bases back against the ColdFire frame map. This closes the transport question
that the per-track-block audit above left open: the SHARC does receive the
parameter pages, at byte-identical offsets.

`FUN_1c24e9` computes a per-track pointer with a literal multiply -- which is
why the earlier scan for a `0x60` stride, and the scan for shift/add synthesis
of 96, both missed it: it is neither an immediate displacement nor a shift
sequence, it is an integer multiply by a register loaded with `0x60`.

```
0x1c250e  m4=r12                        ; M4 := track index
0x1c2512  r2=0x60
0x1c2514  r2=r12*r2 (ssi) , m3=r8       ; R2 := track * 0x60
0x1c251a  i4=r2
0x1c2537  i2=modify (i4,0x2559b6)       ; I2 := track*0x60 + 0x2559b6   (19a, unscaled)
```

Subtract a common base of `0x2558dc` from every literal this function and its
caller use, and all eleven known per-track scalar frame offsets land exactly:

| SHARC literal | - `0x2558dc` | ColdFire frame field |
|---|---|---|
| `0x2558de` | `0x02` | per-track scalar |
| `0x255910` | `0x34` | per-track scalar |
| `0x255930` | `0x54` | read by `FUN_001c2b24` |
| `0x255950` | `0x74` | per-track scalar |
| `0x255970` | `0x94` | machine type |
| `0x255990` | `0xb4` | per-track scalar |
| `0x256018` | `0x73c` | read by `FUN_001c2b24` |
| `0x256038` | `0x75c` | read by `FUN_001c2b24` |
| `0x256058` | `0x77c` | per-track scalar |
| `0x256078` | `0x79c` | per-track scalar |
| `0x256098` | `0x7bc` | per-track scalar |

Eleven independent hits with no exceptions is not coincidence. And
`0x2559b6 - 0x2558dc = 0xda` -- exactly the frame offset where the per-track
`0x60`-byte parameter block begins. So `I2 = 0x2559b6 + track*0x60` **is** track
`t`'s parameter page, in the frame's own byte numbering.

**Addressing units, resolved** (this has caused repeated errors, so it is worth
stating precisely): the unit is per *instruction form*, not global.

| form | scaling |
|---|---|
| `19a` (`modify`, classic) | raw bytes, always x1 |
| `19a_scaled` (`modify (nw)`) | x2/x4 by width |
| `15b`/`4a`/`4b` (`dm(K,I)`) | x4 under 32-bit normal words |
| `3b`/`3c` (M-register indexed) | x2 if short-word tagged, else x4 |

32-bit normal words is already established for this firmware. So base pointers
built with `modify` stay byte-exact, while loads through them advance four bytes
per immediate unit -- each mirrored 16-bit ColdFire field occupying one 32-bit
SHARC slot. That also explains the descriptor-shaped structure at `0x268220`
carrying `XCNT = 1025`, `XMOD = 4`: `0x802 / 2 = 1025` words, one per 32-bit
slot. The two facts are the same mechanism seen from two sides, not a
contradiction.

## `FUN_1c24e9` is the filter/amp/FX converter, and it does not read the SRC page **[V]**

Mapping every `I2`-relative read through the scaling rules above:

| site | form | block byte | mirror | page |
|---|---|---|---|---|
| `0x1c26a5` `r11=dm(0x5,i2)` | 15b, x4 | `0x14` | -- | slice sub-block |
| `0x1c2699` `r14=dm(0x6,i2)` | 15b, x4 | `0x18` | -- | slice sub-block |
| `0x1c268b` `r4=dm(0x7,i2)` | 15b, x4 | `0x1c` | -- | slice sub-block |
| `0x1c26b7` `r10=dm(0xa,i2)` | 15b, x4 | `0x28` | 39 | filter |
| `0x1c2652` `r4=dm(0xb,i2)` | 15b, x4 | `0x2c` | 41 | filter |
| `0x1c268e` `r14=dm(0xc,i2)` | 15b, x4 | `0x30` | 43 | filter |
| `0x1c26d1` `r2=dm(0xd,i2)` | 4a, x4 | `0x34` | 45 | filter |
| `0x1c2659` `r8=dm(0x17,i2)` | 15b, x4 | `0x5c` | 67 | FX |
| `0x1c2622` `i0=modify(i2,0x22)` | 19a, x1 | `0x22` | 36 | filter |
| `0x1c267f` `i4=modify(i2,0x3e)` | 19a, x1 | `0x3e` | 50 | amp |
| `0x1c262d` `i0=modify(i2,0x42)` | 19a, x1 | `0x42` | 52 | amp |
| `0x1c2615` `i3=modify(i2,0x46)` | 19a, x1 | `0x46` | 54 | amp |
| `0x1c2633` `i1=modify(i2,0x4e)` | 19a, x1 | `0x4e` | 58 | amp |
| `0x1c263d` `i3=modify(i2,0x52)` | 19a, x1 | `0x52` | 60 | amp |
| `0x1c266d` `i4=modify(i2,0x56)` | 19a, x1 | `0x56` | 64 | FX |
| `0x1c2630` `i3=modify(i2,0x5a)` | 19a, x1 | `0x5a` | 66 | FX |

All sixteen feed a dense `leftz`/`float`/multiply/spill chain running to about
`0x1c2870` -- an ordinary audio-parameter conversion pipeline, values turned into
floats and scaled.

**Every one of them is filter, amp, FX or the slice sub-block. Not one touches
block bytes `0x00`-`0x12`, which is the entire SRC page** -- TUNE, PLAY, CFADE,
SAMP, STRT/SLICE, LEN, BARS/GRID/LOOP, LEV. This routine is the continuous
per-track parameter converter for the pages *after* the machine's own; the SRC
page must be consumed somewhere else, plausibly at note-on. **[O]**

**CFADE (block byte `0x04`, mirror 27) is not read here [V].** Three
register-indexed reads (`dm(m6,i2)`, `dm(m5,i2)`, `dm(m4,i2)`) have unresolved
offsets because M5/M6/M7 are never assigned in this function or its caller and
must come from further up the chain **[O]** -- but none looks like a CFADE
consumer: M6's feeds bit tests, M5's and M4's feed straight float/multiply
chains. And since nothing on the ColdFire side writes mirror 27 today, any such
read would see a constant zero.

**The function is uniform, confirmed [V].** Its only branches are four `8a_rel`
conditionals at `0x1c25c4`-`0x1c2604`, all testing bits of a flags word via
`btgl`. The bit positions come from a **track-independent global** (`R14`, from
`r1=dm(0x255902)` = frame offset `0x26`, no track index) and from a hardcoded
zero (`R3`, `r3=r3-r3`). The machine type is not loaded into any register until
`0x1c26d4`, *after* all four branches. So these are not a per-machine dispatch.

## `FUN_001c2b24` passes the track in R12 and a 0..31 counter in R8 **[C][V]**

Refines the correction above. The loop is:

```
0x1c2c91  r13=r13-r13 , r15=m5
0x1c2c94  lcntr=0x10, do (pc,0x1e) until lce
0x1c2c97  r8=pass r15 , r12=r13
0x1c2c9a  cjump 0x1c24e9 (db)
0x1c2ca3  r8=r15+1 , r12=r13          ; same R13 -- not yet incremented
0x1c2ca6  r15=r15+r14 , r11=m7        ; R14=2, so R15 += 2 per iteration
0x1c2ca9  cjump 0x1c24e9 (db)
0x1c2cac  r13=r13+1 , dm(i7,m7)=r2    ; R13 increments in the delay slot
```

So **R12 is the plain track index 0..15**, identical for both calls in an
iteration, and it is what drives the `*0x60` block addressing. **R8** is the
0..31 counter (`R15`, `R15+1`), and inside the callee it indexes a second
structure with stride `0xdc`: `0x1c2560 r0=r8*r0(ssi)` with `r0 = 0xdc`. Two
sub-slots per track; which two is **[O]**.

## Two search gaps from the earlier audit, closed **[D]**

**Shift/add synthesis: none.** Over the same 22,646-instruction decode of blk93,
all 600 shift-immediate instructions (`Type6a(mem)`, `Type6a(nomem)`,
`Type6b_shiftimm`) were decoded; 27 have an immediate of +-2, +-4, +-5 or +-6,
and none sits near a second shift on the same source register. Cross-referencing
against all 78 fixed-point ADD/SUB (`Type2a`, `Type2a_short`) within a
12-instruction window gave 6 candidate pairs, all rejected on inspection (the
add precedes the shift, so it uses the pre-shift value). Not enumerated:
`Type2c`/ShortCompute add/sub, and the "M register loaded with 96 from memory"
sub-case. The negative is moot anyway -- the stride turned out to be a literal
multiply.

**The receive descriptor.** A descriptor-shaped structure is built at `0x268220`
around `0x1c7e30`-`0x1c7f10`: ADDRSTART `0x268240`, CFG `0x00100000`, XCNT
`1025`, XMOD `4`, YCNT/YMOD from M5 (~0). `ADDRSTART + XCNT*XMOD = 0x269244`,
which is independently loaded into R4 two instructions earlier -- a self-checking
coincidence that supports the field reading. It is submitted via `0x1c834a` and
`0x1c83ff`, neither decoded. Note this destination is `0x268240`, **not**
`0x2558dc`, so it is not obviously the same buffer; whether there are two
descriptors, a TX/RX pair, or a generic builder is **[O]**.
