# Digitakt II OS 1.15C — findings

Target SHA-256 `62d588456e47194bd56dfee9568fb9dd4521c4ff1e8b5427eb461355532e8c6c`
(matches the target of `lalzart/digitakt-ii-firmware-research-public`).

Evidence classes used below:
**[V]** verified by running it here · **[D]** documented by prior research, not
re-checked · **[O]** open / nobody has established this.

## Scope, and the 2.01 firmwares **[V]**

Everything address-specific in this file is **Digitakt II 1.15C**, whose MAIN
OS is `sections/section_3_MAIN_OS.bin`, sha-256 `6a6a887b…`. The snapshot
ladder and the Ghidra program are the same image. The container and transport
results — both checksums, the HMAC and its key derivation, the framing
message's transfer constant and message count — are the exception: those are
confirmed byte-exact against all four firmwares in the repo root.

`Digitakt_II_OS1.16.syx` and `Digitone_II_OS1.11.syx` are a different
generation, and three things separate them from 1.15C/1.10E:

- **A sixth section, id 8**, packed, **103,416 bytes compressed on both
  devices** — byte-for-byte the same compressed length on Digitakt and
  Digitone, which suggests a shared component rather than per-device content.
  Nothing else is known about it. **[O]**
- **The bootstrap version bumps, `0x0200` -> `0x0201`.** Section 2's `dest` is
  the version word, and it reads `0x02000000` in 1.15C and 1.10E, `0x02010000`
  in 1.16 and 1.11. So installing either of the newer firmwares performs the
  bootstrap upgrade — the one irreversible operation on the device, and the
  reason `tools/patchimg.py` refuses section 2 outright.
- **This repo cannot read them.** Every packed section of 1.16 fails to
  depack. The cause is the oracle, not the new section: the depacker is taken
  from the UPDATER, and 1.16's UPDATER differs from 1.15C's by **43.4%**
  (14,231 of 32,776 bytes, first difference at offset `0x9b`), so the entry
  point at `0x80000432` has moved. The two 2.01 updaters also differ from each
  other, so the oracle would need re-deriving per device.

Retargeting the machine work to 1.16 is therefore not an address rebase. It
needs the 2.01 depacker oracle re-derived, a re-extraction, a fresh snapshot
ladder built by cold boot, a re-import to Ghidra, and every address in "The
ColdFire machine dispatch" re-derived. **[O]**

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
  firmware itself**, not stored — same code at `0x80005d90` in both devices,
  only the data differs. For a per-device STRING and the 32-byte CONST stored
  immediately after its NUL: **[V]**

      key[i] = CONST[i] ^ sha256(STRING)[i] ^ sha256(STRING[::-1])[i]

  | device | STRING | CONST at |
  |---|---|---|
  | Digitakt II | `"Master Overdrive"` @`0x80006ff8` | `0x80007009` |
  | Digitone II | `"Multiplier"` @`0x8000706c` | `0x80007077` |

  The "32-byte constant beginning `69 5d 82 bc`" earlier notes describe is only
  one of the three XOR operands, not the key. **[C]**
- **All three integrity fields are recovered and computed**, each confirmed
  byte-exact against all four firmwares in the repo root. **[V]**

  | field | where | algorithm |
  |---|---|---|
  | content checksum | preamble bytes 4-7 | `sum(i ^ word_i)` over 1-based big-endian u32 words of the whole container, trailer included |
  | HMAC trailer | container's last 32 bytes | HMAC-SHA256 over `container[:total_len-32]` |
  | per-packet | message byte 125 | `(K + sum(body[6+i] ^ (i+K), i=0..118)) & 0x7F` |

  The container ends with 16-byte alignment padding then the 32-byte trailer,
  all inside `total_len` (`1347692+4+32 = 1347728`, and the same on the other
  three). The per-packet checksum had previously resisted an exhaustive search
  over 30,603 pairs — it is not a CRC or a hash but folds each byte's own
  index in, a family that search never covered. **[C]**
- The transport carries no unknown fields. `K` above is byte 7 of the 16-byte
  framing message (`0x0F` Digitakt II, `0x10` Digitone II), and framing body
  bytes 11..13 are the **data-message count** as a 21-bit base-128 value.
  Blanking those counts and discarding the source preamble, re-encoding
  reproduces all four firmwares byte-identically. **[V]**
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

1. content checksum — `sum(i ^ word_i)` over 1-based big-endian u32 words,
   at `0x80003ca6`. Earlier notes give this as `0x40003ca6`; that is a
   transcription slip — `0x80003ca6` is the instruction that reads the length
   word the checksum covers, `move.l (0x40000000).l,D2`. **[C]**
2. HMAC-SHA256 trailer (`0x80005e2a`; SHA-256 H0 at `0x800058bc`, K-table at `0x80006ef8`)

**No version comparison on this path.** On failure: "UPGRADE ABORTED" and a spin
loop, nothing written. **[V]** That a corrupt MAIN OS still lets the menu come up
is a strong inference from the code layout, not demonstrated. **[O]**

The receive path itself, traced in the bootstrap: each message's 101 decoded
bytes are written to `0x40000000 + seq*101`, the message count comes from the
framing message with **no bound check**, and the erase/write loop to flash
offset `0x80000` caps nothing either — no software size limit exists anywhere
on this path. **[V]**

The two classes of failure behave very differently. A bad byte-125 checksum
sets `_DAT_80008e3c`, which is written in six places and **read in none** —
the receive state machine silently resets, with no message. A bad content
checksum or HMAC branches into `FUN_80003bfc`, which prints "UPGRADE ABORTED"
/ "PLEASE REBOOT" and hangs in an infinite loop that never returns, so the
erase/write loop after it is unreachable. **[V]**

```
80003748  move.b (0x80007d17).l,D4b   ; K, the transfer-type const (0x0F here)
80003752  move.b (0x0,A3,D0*1),D5b    ; body[6+i]
8000375c  eor.l  D5,D2                ; ^ (i + K)
8000375e  add.l  D2,D1                ; running sum
8000376e  mvz.b  (0x78,A2),D1         ; body[125], the stored checksum
80003774  cmp.l  D1,D0                ; against (K + sum) & 0x7F
```

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
- **Adding a new machine**: the ColdFire side is no longer the blocker — see
  "The ColdFire machine dispatch" below. Section 7 is a real ADI loader stream;
  the remaining blocker is that there is **no SHARC assembler or semantic
  model**, so a genuinely new algorithm still means flash-and-listen on
  hardware. A machine that reuses an existing DSP mode with different
  parameters avoids that entirely. **[V]/[O]**

## The ColdFire machine dispatch **[V]**

Found by emulator read-watch, not statically. Earlier analysis had concluded
the descriptor table was write-only — every entry had exactly one reference, a
write from the static initialiser `FUN_401ac1be`, and no readers anywhere. That
was correct as far as it went: the table is uninitialised bss, so it exists
only at runtime, and Ghidra throws `MemoryAccessException` reading it. Running
`tools/mmiotrace.py` range-scoped over it on a boot resumed from
`snapshots/boot400M.snap` gave 432 reads, all from a single PC, `0x4001767a`. **[C]**

The dispatch is 34 bytes at `0x400caf48`:

```
400caf48  moveq  #6,D1               ; the bound -- one byte
400caf4a  move.l (4,A7),D0           ; machine_type
400caf4e  cmp.l  D0,D1
400caf50  bcs.b  $400caf62           ; type > 6 -> fallback
400caf52  move.b #0x2c,D1            ; stride, 44 bytes
400caf56  mulu.l D1,D0
400caf5a  addi.l #0x42923644,D0      ; descriptor array base
400caf60  rts
400caf62  move.l #0x4292374c,D0      ; == base + 6*0x2c, i.e. entry 6
400caf68  rts
```

So an out-of-range machine type resolves to MANUAL SLICE rather than crashing —
a forgiving failure mode for anything that patches this. The field accessor is
`FUN_4001762c(obj, field)` → `*(descriptor + 8 + field*4)`; `FUN_400caf48` has
six callers, all resolvable. Each descriptor is two string pointers, nine
literal ID fields and a trailing tag of 10.

Dumped live with `tools/memdump.py` — the only way to see it, since it is bss —
the seven entries are the machine list in order: `0 SAMPLE`/`SAMP`, `1 WERP`,
`2 STRETCH`, `3 REPITCH`, `4 SLICED SMP`/`SLIC`, `5 MIDI`, `6 MANUAL SLICE`/`MLIC`.
Entry 5 (MIDI) is the one irregular record — all nine ID fields zero and no
tag, which shows the IDs are not mandatory. Entries 3 and 6 carry six IDs
rather than seven. **[V]**

Those are **not** the names the UI shows — they look like internal or legacy
labels. See "The display names are a separate table" below. **[C]**

The UI's list length is not a numeral. `MachineSelectionView` (`FUN_400607b2`)
builds two `std::vector<int>` by copying a rodata range, so the count is a pair
of pointer immediates; `MachineListView` (`FUN_4005e022`) enumerates nothing
and renders one row per vector entry. **[V]**

| list | table | contents | built by |
|---|---|---|---|
| source | `0x401e1958`-`0x401e1974` | `{0,1,2,3,6,4,5}` — 7, in UI display order | `FUN_40051fbc` |
| filter | `0x401e1940`-`0x401e1958` | `{0,1,4,3,5,2}` — 6, excludes MANUAL SLICE | `FUN_4005224c` |

Every bound an eighth machine would have to clear, verified against the
section bytes: the dispatch's `moveq #6` at `0x400caf48`, and the four `pea`
immediates at `0x40052000` (table D end), `0x4005200a` (D start), `0x40052296`
(E end) and `0x400522a0` (E start). The dispatch bound is a single byte,
`0x400caf49`, `06` → `07`. **[V]**

That alone buys nothing, because neither array can grow in place. Index 7
resolves to `0x42923644 + 7*0x2c` = `0x42923778`, which is the live
NONE/TRIG/RTRG parameter-page array; and `0x401e1974` is immediately live
vtable/RTTI pointer data. Both neighbours are occupied. The workable shape is
a trampoline (see `docs/PATCHING.md`): relocate table D into the cave with
eight entries and repoint the two immediates, redirect `FUN_400caf48` to cave
code handling `type == 7` while entries 0..6 resolve exactly as now, and build
the 44-byte descriptor there. Note `0x401e1974` also appears at `0x40124252`,
`0x401985dc` and `0x401bae4e` — those refer to the *next* object, which begins
at that address, not to table D's end, and must be left alone. **[O]**

The relocation half of that is done and works. Patching, in guest memory on a
run resumed from `snapshots/boot400M.snap`: an eight-entry table
`{0,1,2,3,6,4,5,7}` written at the cave base `0x402f9c14`, and the two `pea`
operands repointed at it. The firmware then builds its machine-list vector
from the cave — eight reads, eight distinct addresses, all from `0x4012d28e`,
the same vector-copy loop that reads seven entries from `0x401e1958` in an
unpatched control run, which sees zero reads of the original table. The table
reads back intact afterwards, so nothing else claims that memory.
`tools/machinepatch.py` runs both arms. **[V]**

The dispatch half is done too. A 48-byte trampoline in the safe cave region
replaces `FUN_400caf48`'s first six bytes with `jmp $40303e5c.l`, adds a
`type == 7` case, and otherwise reproduces the original logic exactly: **[V]**

```
40303e5c  move.l $4(a7), d0          ; the machine type
40303e60  moveq  #$7, d1
40303e62  cmp.l  d0, d1
40303e64  bne.b  $40303e6e           ; not 7 -> original path
40303e66  move.l #$40303f5c, d0      ; the new descriptor, in the cave
40303e6c  rts
40303e6e  moveq  #$6, d1             ; ---- original logic from here
40303e70  cmp.l  d0, d1
40303e72  bcs.b  $40303e84
40303e74  move.b #$2c, d1
40303e78  muls.l d1, d0
40303e7c  addi.l #$42923644, d0
40303e82  rts
40303e84  move.l #$4292374c, d0
40303e8a  rts
```

Calling the patched dispatch directly in the live guest — set up a scratch
stack, `emu_start` at `0x400caf48`, read `D0` — gives the right answer for
every input:

| arg | returns | |
|---|---|---|
| 0..5 | `0x42923644 + arg*0x2c` | unchanged |
| 6 | `0x4292374c` | unchanged |
| **7** | **`0x40303f5c`** | the new descriptor |
| 8 | `0x4292374c` | fallback preserved |

The descriptor carries entry 6's nine fields verbatim, so the new machine
behaves as MANUAL SLICE, but its own name pointers: two static COW reps laid
out in the cave as `[len][cap][-1][chars]`, reading back as `PLACEHOLDER`
(11/11/-1) and `PLHD` (4/4/-1). The `-1` refcount is what makes them safe —
every copy deep-clones rather than mutating cave memory. The run still reaches
post-intro with the patch installed, so nothing about it breaks the boot.
`tools/machinepatch.py --milestone b`.

**Installed in the GUI, where the UI actually runs, the list half breaks
boot and the dispatch half does not.** Bisected with
`--patch-machine=list` / `=dispatch`: **[V]**

| patch | result |
|---|---|
| dispatch only | 6 tasks, DTIM3 firing, panel rendering past 340M instructions |
| list only | 2 tasks, DTIM3 never fires, main task in the terminal loop at `0x4012d2fa` |
| neither | 6 tasks, normal |

That clears the trampoline, the descriptor and the two static COW string
reps — and the cave, since the dispatch half writes into the same region.
It also clears the pre-existing `weak_ptr` hang as an explanation: both arms
ran with `--weakptr`, and only the patched one fails. The fault log reports
**0 distinct pages touched**, so it is not a wild pointer either; the
`weak_ptr` trap is an object that was never constructed.

**The terminal loop is not a weak-pointer failure. It is `std::terminate`.**
`0x4012d2fa` is a 2-byte trap with 34 call sites; the GUI's long-standing
"hung on a weak pointer" label is a guess that predates this. A stack scan at
the moment it trips gives one candidate return address, `0x40178484`, which is
the instruction after a `jsr` at `0x4017847e` inside `FUN_40178424`. That
function is part of the **C++ exception unwinder** — `FUN_401772cc`, whose
non-zero return sends it to the trap, parses `.eh_frame`, checking for the
`"eh"` augmentation string and walking CIE/FDE records. So the sequence is: an
exception is thrown, no handler is found, `std::terminate` is called. **[V]**

That explains the otherwise-odd combination of symptoms — an abort with **zero
memory faults**, triggered only by a specific value. A bounds check that
throws is not a wild read.

**The thrower is `std::map<int,int>::at` in the list's sort comparator — not
either `vector::at`.** Found with `tools/guirun.py`, a headless twin of the
GUI's emulator configuration that reproduces the failure exactly (terminal
loop at ~63M, 2 tasks, `DTIM3 0`), by hooking the throw path instead of
guessing at containers. On a `list`-only run: **[V]**

| hook | hits |
|---|---|
| `__cxa_throw` `0x401d5680` | 1, typeinfo `0x40210018` |
| `__throw_out_of_range` `0x401d105c` | 1, message `0x40213a8f` = `"map::at"` |
| `FUN_4019bf70`, `FUN_401ac0fe` (the two `vector::at` candidates) | 0, 0 |

A correction to what this replaces: `0x40225586` and `0x40213a8f` are the
*message strings* `"vector::_M_range_check"` and `"map::at"`, not functions —
`0x40213a8f` is odd, and ColdFire code is word-aligned. Both `vector::at`
candidates `pea 0x40225586` then `jsr 0x401d105c`, which is
`__throw_out_of_range(const char*)`: it allocates the exception and calls
`__cxa_throw` at `0x401d5680`. Hooking those two catches every such throw,
whatever the container. **[C]**

The throwing `at()` is `FUN_40198030`, a `std::map<int,V>::at` (RB-tree walk,
signed-int key at `node+0x10`, value at `node+0x14`) with exactly one caller,
`FUN_400517c4`. A stack scan at the throw gives the chain `FUN_400517c4` <- the
insertion-sort and merge helpers at `0x40051968`..`0x40051e4c` <- `FUN_40051fbc`
at `0x4005207e`, the `jsr` to `__stable_sort_adaptive` right after
`get_temporary_buffer`. **[V]**

So `FUN_40051fbc` does not just copy table D into the list vector. It then
`std::stable_sort`s it, with `FUN_400517c4` as the comparator. That comparator
holds a function-local static `std::map<int,int>` at `0x40984cbc` (guard byte
`0x40984ce8`; `__cxa_guard_acquire`/`release` are `0x401cf7ea`/`0x401cf846`),
filled once by the range insert `FUN_40198948` from seven longword pairs on its
own frame, `[-0x38(a6), a6)`. Read from the instruction bytes, not the
decompiler: **[V]**

| key (machine type) | 0 | 1 | 2 | 3 | 6 | 4 | 5 |
|---|---|---|---|---|---|---|---|
| value (display position) | 0 | 1 | 2 | 3 | 4 | 5 | 6 |

That is the inverse of table D. The comparator returns `map.at(a) < map.at(b)`
in D0's low byte (`sgt.b`, then `neg.l`). With type 7 in the list, the first
comparison involving it calls `map.at(7)`. There is no key 7, so it throws,
nothing catches it, and that is the whole failure.

Ghidra records no references to `0x40984cbc` or `0x40984cc0`, even though both
are absolute `pea`/`lea` operands in `FUN_400517c4`, so `xrefs` on the map
finds nothing; `callers 0x40198948` finds its one writer. **[V]**

This also retires the grouping hypothesis further down. On the failing run,
`FUN_4005d7b8` has **zero** hits before the throw: the sort runs before any
row is grouped. **[V]**

**The fix is patch 5, `rank`: extend the map's initialiser, not its lookup.**
The insert's call site is a 6-byte `jsr $40198948.l` at `0x40051872`.
Repointing its operand at a 22-byte cave shim leaves the comparator, guard,
map, lookups and throw-on-unknown exactly as they were. The shim overwrites the
`[begin, end)` stack arguments with an eight-pair cave table and tail-jumps to
the real insert. The table is `(type, position)` over the list itself, which
reproduces the stock seven pairs and adds `(7, 7)`. Disassembled back from the
emitted bytes: **[V]**

```
40051872  jsr    $403040fc.l          ; was jsr $40198948.l
403040fc  move.l #$4030411c, $8(a7)   ; begin -> cave table
40304104  move.l #$4030415c, $c(a7)   ; end   -> table + 64
4030410c  jmp    $40198948.l          ; the real range insert
```

Its precondition refuses to patch if the guard byte is already set, because
the static would never be rebuilt. All runs are `tools/guirun.py --weakptr`
from `snapshots/boot400M.snap` to 400M instructions: **[V]**

| parts | result |
|---|---|
| none (control) | boots: 6 tasks, `DTIM3` 2038, no throw |
| `list` | terminal loop at ~63M, one `out_of_range` |
| `list+rank` | boots: 6 tasks, `DTIM3` 2034, no throw |
| `list+dispatch+group+name+rank` | boots: 6 tasks, `DTIM3` 2028, no throw |

Its arguments show that type 7 really passes through the comparator rather
than being skipped. On `list+rank` the comparator runs 16 times against the
control's 13; the first ten comparisons are identical in both, and the 11th
and 12th are `(7, 6)` and `(7, 5)`. **[V]**

Narrowing further with `--patch-machine=list:6`, which builds an eight-entry
list whose last entry duplicates MANUAL SLICE instead of introducing a new
machine type: **it boots normally.** So eight entries is fine, and **the
value 7 specifically is what breaks it.** **[V]**

That pointed at `FUN_4005d7b8`, the grouping helper `MachineListView` uses to
place separators. It is not a table lookup but inline branch logic:
`{0,1,2,3,4,6} -> 1`, `{5} -> 2`, and anything `>= 7 -> 0` (via `x &
0xffffff00`, arithmetically zero for 7..255). So machine 7 lands in group
id `0`, which nothing else uses. **[V]**

An earlier version of this section concluded that group `0` is what breaks
boot. **That was wrong.** The value-7 failure is the sort comparator's
`map::at`, described above, which runs before the grouping helper is ever
called, and `list+rank` boots with type 7 still in group `0`. Whether group
`0` renders wrongly (a spurious separator, a missing row) is unobserved,
because no run has drawn the list yet. Patch 3 stays in the set as the
likely rendering fix, not as a boot fix. **[C][O]**

Worth recording as a near-miss: the trampoline's two branch displacements were
wrong on the first attempt — `bne.b` landed on the `rts` rather than the block
after it. Disassembling the emitted bytes back with `dt2.coldfire.disasm` and
checking each branch target lands on an instruction boundary caught it before
it ever ran. The corrected `bcs.b` displacement came out as `65 10`, byte-
identical to the original function's, which is its own confirmation.

What that does *not* show is a row on screen. `FUN_4005e022` (`MachineListView`)
never fires on an idle post-intro run, so the list is built with eight entries
but never drawn without navigation — and Digitakt's post-intro screen renders
blank anyway. The eighth row rendering as a second MANUAL SLICE (index 7 falls
back to entry 6) is an expectation, not an observation. **[O]**

Driving the UI to prove it does not work yet, and the reason is upstream of
this patch. `tools/uidrive.py` installs the Milestone B patch, scripts panel
input, and watches three pixel-free signals: executions of `FUN_4005e022`,
reads of the cave descriptor and its name reps, and calls to the COW copy
`FUN_401d3aba` sourced from the cave. Across an idle window and ten scripted
navigation checkpoints, **all three stay at zero**, in both the patched run
and an unpatched control. The framebuffer stays blank throughout. **[V]**

The panel input itself is fine — every injection produces a shape-valid
`queue_send` record with the right code. The PC, sampled at every checkpoint,
is pinned at `0x40002a18`: `FUN_40002a18`, which sets a PIT2 bit and calls
`FUN_4000148c(0x47d9ade0)` — the **idle task**. So in *these headless runs*
nothing else is runnable and the queued panel events are never consumed. The
control run behaves identically, so this is not something the patch
introduced. **[V]**

Do not generalise that into "the UI never runs": it does. Under `emu/gui.py`
a button click visibly changes the page, so the UI task is scheduled and
consuming panel events there. The difference between the GUI's configuration
and `tools/uidrive.py`'s headless resume is not yet pinned down, and is the
thing to chase before concluding anything about the UI from a headless
run. **[C][O]**

Note `FUN_400607b2` (`MachineSelectionView`) *does* fire, exactly once, ~60M
instructions into a resumed run, in patched and control runs alike. So the
view is constructed and its list vectors are built; only the row-building
`MachineListView` never runs. **[V]**

### Driving panel chords: modifiers must latch **[V]**

A chord is not a press followed by another press. `emu/panelin.py`'s `held`
argument is a mask of other buttons *in the same channel*, and the modifier
keys are not in the same channel as the page buttons, so `held` cannot express
a chord at all:

```
code = channel*8 + bit + 1
FUNC = 17 -> channel 2, bit 0      SRC  =  2 -> channel 0, bit 1
YES  = 10 -> channel 1, bit 1      NO   = 12 -> channel 1, bit 3
UP   = 11 -> channel 1, bit 2      DOWN = 14 -> channel 1, bit 5
```

The wire carries each channel's whole 8-button state as one byte, so a
cross-channel chord is expressed by asserting one channel and *leaving it
asserted* while another changes — never by a press/release pair:

```
buttons(m, profile, 2, 0x01)   ; FUNC down, and leave it
buttons(m, profile, 0, 0x02)   ; SRC down, FUNC still held
buttons(m, profile, 0, 0x00)   ; SRC up
buttons(m, profile, 2, 0x00)   ; FUNC up, last
```

The firmware's own records confirm the difference: a plain tap gives flag
`0x01` on press and `0x10` on release, while the same button inside a latched
chord gives `0x03` and `0x12`, and the modifier's own release reads `0x00`.
Press/release pairs produce two isolated taps that no chord handler will ever
see. **[V]**

The descriptor's two name pointers are **`std::string`, not `char*`** — the
pre-C++11 libstdc++ copy-on-write representation, with a 12-byte header
immediately *before* the character data: **[V]**

```
data-0xc  length
data-0x8  capacity
data-0x4  refcount
data+0    chars, NUL-terminated
```

Read back live, the header is exactly that — `SAMPLE` at `0x44f25c7c` has
length 6, capacity 6, refcount 0; `STRETCH` at `0x44f25cfc` has 7, 7, 0;
`MANUAL SLICE` at `0x44f25ddc` has 12, 12, 0. Three of `FUN_400caf48`'s six
callers copy the whole 44-byte descriptor by value, calling a constructor and
destructor per name field — which is why they are non-trivial members rather
than pointers. The copy is `FUN_401d3aba`: **[V]**

```
401d3aba  move.l (A1),D0             ; the stored data pointer
          tst.l  -4(D0)              ; refcount
          bmi    deep_clone          ; refcount < 0 -> _M_is_leaked(), clone
          cmp.l  #DAT_44f1e088,...   ; the empty-string singleton, by address
          beq    skip                ; never refcount the singleton
          addq.l #1,-4(D0)           ; otherwise share: refcount++
```

So a new descriptor **cannot** point bare at a rodata string: the bytes before
it are not a valid header, and `*(int*)(ptr-4)` would be whatever happens to
sit there — either corrupting neighbouring data with a refcount increment, or
taking the release path against a bogus header.

It does not need a runtime-constructed string either. Laying the full rep out
statically in the cave as `[u32 length][u32 capacity][i32 -1]["NAME\0"]` and
pointing the field at the chars makes `refcount < 0` true, so every copy
deep-clones into the heap, the static bytes are never mutated, and destructors
only ever run against the clones. This is the same mechanism libstdc++ uses
for a leaked rep. Not yet tried. **[O]**

`FUN_4005e022` separately gates auto-scrolling the list to the active row on
`param_1[0x73] + 1 < 8`; that is cosmetic — an unpatched eighth row would fail
to auto-scroll rather than crash. **[O]**

The list vectors are rebuilt every time `MachineSelectionView` is constructed,
not once at static init: hooking `FUN_400607b2`, `FUN_40051fbc` and
`FUN_4005224c` on a run resumed from `snapshots/boot400M.snap` shows all three
firing ~60M instructions in. So a patch to the rodata tables or the descriptor
array can be tested by poking guest memory after a resume — no cold boot
needed. `FUN_4005e022` does *not* fire on an idle post-intro run, so the rows
are built but never drawn without navigation. **[V]**

Still open: what the literal IDs (`0xca`-`0xfe`) mean, and how `machine_type`
reaches the six callers. **[O]**

### The eighth row on screen, and a replay that disagrees with the GUI **[V][O]**

**Rung 1 is observed.** In `emu/gui.py` with all five parts (`--patch-machine`,
no `--weakptr`), MACHINE SEL stays open and scrolls to an eighth row drawn as
`PLACEHOLDER` — the display-name table's `Placeholder`, upper-cased at draw
time. It sits below MIDI with a dotted separator between them, so patch 3 does
put type 7 in a different group from MIDI; whether that is group `1` is not
visible from one screen. Seen by a person, 2026-09-14, at 248.6M
instructions. **[V]**

**A scripted replay does not reproduce it.** `tools/guirun.py --input`
(FUNC latched, then SRC through the GUI's own inbox and dwell pacing) opens
MACHINE SEL and then, 2-4M instructions later and with SRC still held, drops
back to the SRC page with a `ONE: ---` header (the track's machine and sample)
for about five seconds. The outcome is the same in every variation tried: **[V]**

| variation | list drawn | list gone |
|---|---|---|
| unpatched, `--weakptr`, SRC held 170-196M | 178M | 180M |
| all five, `--weakptr`, SRC held 170-196M | 176M | 178M |
| unpatched, no `--weakptr` | not caught at 2M spacing | `ONE: ---` by 180M |
| all five, no `--weakptr` | 176M | 178M |
| all five, SRC pressed late (250M) | 258M | 262M |
| all five, second SRC press (230M) | 240M | 242M |

No exception is thrown in any of them. So neither the patch, `--weakptr`, nor
press timing explains the difference, and an earlier version of this section
that called the auto-close "what a person sees in the GUI" was wrong. **[C]**

What the GUI session delivered that the replay does not is open. To settle
it, `emu/gui.py` now prints every panel feed it delivers as
`[gui] input --feed <instrs>:<hex>`, and `tools/guirun.py --feed` replays
those bytes raw at the same chunk boundary. A recorded session that keeps the
list open, replayed headlessly, either reproduces (and can then be bisected
event by event) or exposes a difference between `guirun.py` and the GUI. **[O]**

**The replay is faithful; the two GUI sessions are not the same run.** A GUI
session whose MACHINE SEL flashed was recorded (`[gui] input --feed`: FUNC
latch plus SRC tap four times, at 202M, 262M, 410M and 493M, plus one bare
SRC tap and one FX tap) and replayed with `tools/guirun.py --feed`. Every
feed landed on its recorded chunk, the replay's DTIM3/mainloop pairs match the
GUI's status lines at every 20M from 80M to 280M (`89/88`, `211/201`, ...
`1296/1272`), and the list flashes on screen at the same point, drawn at 210M
and gone by 212M. So `guirun.py` reproduces the GUI, and an idle boot is
deterministic between them. **[V]**

The earlier session in which the list stayed open had already diverged by
80M, before any recorded input: mainloop `98` against DTIM3 `87`, then `225`
against `212` at 100M, while the flashing session and every headless run have
mainloop *behind* DTIM3. It was run before feeds were printed, so what it
received is unknown; since an idle boot is deterministic, input during boot is
the likely difference. So whether the list stays open depends on state
established early, not on when FUNC+SRC is pressed. **[V][O]**

### The display names are a separate table **[V]**

Seeing the machine-select screen render for the first time showed three of the
seven names disagreeing with the descriptors: position 0 reads `ONESHOT` where
the descriptor says `SAMPLE`, position 4 reads `SLICE` where index 6 says
`MANUAL SLICE`, and position 5 reads `GRID` where index 4 says `SLICED SMP`.

The displayed names come from a second, purely static table at `0x401fbc50` —
7 rows of 12 bytes, three big-endian `char*` each, indexed by the **raw**
machine type rather than the UI's display order. These are plain
NUL-terminated C strings, with no COW `std::string` header, so they are a
different mechanism from the descriptor's own name fields: **[V]**

| idx | long | abbrev |
|---|---|---|
| 0 | `Oneshot` | `ONE` |
| 1 | `Werp` | `WRP` |
| 2 | `Stretch` | `STRE` |
| 3 | `Repitch` | `RPI` |
| 4 | `Grid` | `GRD` |
| 5 | `MIDI` | `MIDI` |
| 6 | `Slice` | `SLC` |

Row 5 reuses one pointer for both columns, mirroring MIDI's irregularity in
the descriptor array. Row 6 has a third non-null pointer (`0x4022c7cb`) that
the others lack; unexplained. **[O]**

`ONESHOT` was not findable by grep because the stored literal is `Oneshot` —
the UI upper-cases it at draw time.

The accessor is `FUN_400dcc50`, and it has the same shape as the dispatch:

```
400dcc50  moveq  #$6, d1           ; the bound, again one byte
400dcc52  move.l $4(a7), d0
400dcc56  cmp.l  d0, d1
400dcc58  bcs.b  ...               ; out of range -> "ERROR"
          lea.l  $401fbc50.l, a0   ; the table base
```

It is called from `FUN_4005da40`, the invoker half of a `std::function`-style
closure built in `MachineListView`'s constructor and stored per row for lazy
evaluation at draw time — which is exactly why an idle or headless run never
observes it, even though the data is static ROM the whole time.

**This is a fifth bound an eighth machine must clear**, on top of the dispatch
bound and the four `pea` immediates. And the name table cannot be extended in
place: `0x401fbca4`, immediately after row 6, is the base of another table,
referenced by `lea.l $401fbca4.l, a0` at `0x400dcb26`. The 194 zero bytes there
are that table's contents, not slack. So the name table has to be relocated to
the cave as well, with `FUN_400dcc50`'s `lea` immediate repointed. **[V]**

The complete recipe for a visible eighth machine, then, is five patches, all
in `tools/machinepatch.py` and selectable part by part with `--patch-machine`:

1. **list** — relocate table D to the cave with an eighth entry, repoint the
   two `pea` immediates. Done and proven.
2. **dispatch** — trampoline `FUN_400caf48` for `type == 7`, descriptor and
   `std::string` reps in the cave. Done and proven.
3. **grouping** — `FUN_4005d7b8`'s exact-6 test becomes a `<= 7` range test,
   so type 7 gets group `1`. Implemented. Not a boot blocker; its rendering
   effect is unobserved.
4. **display name** — relocate the `0x401fbc50` table to the cave with an
   eighth row, repoint the `lea` at `0x400dcc50`, and raise its `moveq #6`
   bound. Implemented, and the table reads back correct; not yet seen drawn.
5. **rank** — give the list's sort comparator a key for type 7, through a cave
   shim on its map's one-time insert at `0x40051872`. Implemented. This was the
   boot blocker, and all five together boot.

`tools/machinepatch.py` now takes a `MachineSpec` (display names, descriptor
names, the stock type to copy fields from, list position, optional fields),
and `plan_b` computes every write from a `read(addr, n)` function. With the
default spec it produces the same 18 writes as the verified run, live and
against the static image (`tests/test_machinepatch_plan.py`). With
`--machine=Lofi:LOF:3:0` the list becomes `{7,0,1,2,3,6,4,5}`, the rank pairs
follow it, boot completes with no exception, and MACHINE SEL shows LOFI as its
first row. The fields copied live from REPITCH's descriptor are
`0, 0xe7, 0, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0x0a`. **[V]**

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

### Why full boot stalls — the real reason **[V]**

The RTOS task created at boot (entry `0x400cef6c`, stack `0x4000`, priority 1)
**is the DSP bring-up task**. Walking the call tree upward from the ColdFire<->SHARC
transport lands exactly on it:

```
0x40128c7c   transport: write arg -> DSPI 0xFC074004, kick 0x841b -> 0xFC074000,
             then block on a semaphore the completion ISR would signal
  <- 0x400cf000, 0x400cf928, 0x400cfd8a, 0x4012d46e   (4 call sites)
    <- 0x400cef6c   the task entry itself
```

The transport installs an ISR at vector 97 (`0x40000184`), enables INTC sources
`0x21`/`0x1d`, starts the transfer and waits. Firing the completion interrupt by
hand gains only ~330 addresses; stubbing the transport outright gains nothing and
just moves the stall to `0x400cf956`. Four call sites means DSP bring-up is a
**stateful conversation**, not one transfer.

This is a genuinely different wall from the SPI flash. There, the data we needed
already existed in the `.syx`. Here the ColdFire is waiting on replies from a
processor with no open emulator, so the responses would have to be *synthesised*
from a protocol nobody has documented. Boot cannot complete without that, and the
UI task presumably never starts because DSP init never finishes.

**Update (next session): the "do not pursue" call above was too pessimistic.**
The DSP handshake did not need real SHARC replies synthesized -- it needed the
*ColdFire-side* synchronization primitives satisfied, which turned out to be
inspectable and fakeable without modeling the SHARC at all. See "DSP bring-up
-- session 2" below: `task_create` sites reached went from 4/16 to 10/16 this
way. The capability table remains accurate for what *doesn't* need booting:

| capability | status |
|---|---|
| CRC-32 oracle (`0x80001bd0`) | works, byte-exact |
| aPLib depacker (`0x80000432`) | works, validates a 3.1 MB repack |
| firmware graphics rendering (`emu/screen.py`) | works, pixel-exact vs ground truth |
| Bitmap framebuffer encode/decode | works, verified two independent ways |
| full boot to UI | in progress -- 10/16 `task_create` sites reached, see below |

## DSP bring-up -- session 2

Starting point: 4/16 `task_create` (`0x400012c8`) call sites reached, ~37,627
distinct code addresses, stuck inside the DSP-transport wait at `0x40128c7c`.
Ending point: **10/16 `task_create` sites, 58,337 distinct addresses.** New
tooling: `emu/dspboot.py` (instrumented boot harness, reusable) and a scoped-hook
speedup added to `emu/harness.py`. All of it verified by running, not inferred.

### Blocker 1 (cleared): the transport is a mutex+semaphore wrapper, not an RPC

Re-reading `0x40128c7c` disassembly line by line (not just skimming) shows it
is **not** "send a request word, wait for a reply word" as the earlier session
guessed. It is:

```
lock mutex @0x44e4d6a4                          (0x400015a0)
  (first call only: install ISR @0x40128c4c at vector 97,
   enable INTC sources 0x21/0x1d, init completion sem @0x44e4d69c to 0)
write timeout(!) -> 0xFC074004
write control word 0x841b -> 0xFC074000          (kicks the transfer)
jsr 0x4000141a   (sem_pend on 0x44e4d69c)        <-- blocks here
unlock mutex (tail call into 0x400016d2)
```

The value each of the 4 call sites pushes (`0xF4240`, `0x3E8`, `0x64`,
`0x2DC6C0` = 1,000,000 / 1,000 / 100 / 3,000,000) is a **microsecond timeout**
written to hardware, not a command/payload word -- it is never read back by the
ColdFire side. The real completion signal is the semaphore at `0x44e4d69c`,
which the would-be completion ISR at `0x40128c4c` posts to via
`0x4000155c -> 0x400011ee`.

Critically, `0x4000141a` (sem-pend) has a fast, non-blocking path: if the
semaphore's count field is already `>0`, it clears it and returns immediately
without ever calling the scheduler (`trap #0`) -- and **every one of the 4
callers discards its D0 return value** (overwritten immediately after the
call), so nothing downstream ever checks "did the transfer really succeed."

**Patch**: at `PC == 0x40128d08` (the `jsr 0x4000141a` instruction itself),
write `1` into the 4 bytes at `0x44e4d69c` before it executes. No interrupt
firing, no scheduler re-entry, no `rte` -- just pre-satisfying the flag the
very next instruction is about to check. This is different from, and more
surgical than, the earlier session's attempts (firing vector 97/33/29 by hand,
or blanket-stubbing the whole transport function), which is presumably why
those only gained ~330 addresses or moved the stall without progress.

Result: the one transport call site actually reached at this point in boot
(`0x400cf928`, timeout `0x3E8`) goes through. Two more polled hardware status
registers immediately downstream needed the same treatment, discovered by
running and reading what changed at the new stall PC:

- `0xEC03802C` bit 31 (`0x400cf956`, a byte-at-a-time TX loop unrelated to the
  already-known UART8/DSPI0 mocks -- a *second* status register pair,
  `0xEC094018`/`0xEC03802C`, spent uploading what is very likely the SHARC ADI
  loader blob byte-by-byte after the handshake succeeds)
- `0xFC05C02C` bit 28 / RFDF (`0x40129da2`) -- same DSPI0 status register
  already mocked for RXCTR, but a *different* bit, tested by a second,
  synchronous SPI0 read routine reached only after the transport unblocks

Both mocked the same way as the pre-existing UART8/DSPI0 mocks: force the
polled bit permanently set in `Machine.mmio`.

### A red herring that turned out to be correct behavior, not a bug

Past the above, boot hit a second embedded aPLib-style depacker at
`0x4012ab70` (distinct from the bootstrap's `0x80000432`, and from the
flash-section-table depacker used by MAIN OS's own boot-time decompression --
this one runs on in-memory buffers during DSP bring-up). One invocation
(source `0x402489b4`, a *static address inside the already-loaded MAIN OS
image*, not flash- or DSP-reply-dependent) appeared to run away: 2.6M+ hits at
the same 3 addresses (`0x4012acba/bc/be`, its copy loop) with zero new code
coverage for tens of millions of instructions -- classic infinite-loop
signature.

It is not one. Register tracing (dump D2/D3/A1 on every entry to the copy
loop) showed match lengths never exceeding ~2KB; the "stall" was thousands of
small, legitimate tokens through a tight loop, which the coverage-based stall
heuristic cannot distinguish from a hang because it only tracks *new* PCs, not
forward progress within a loop. Independently ruled out a Unicorn MVZ/MVS
decode bug (the specific opcode class flagged as broken in Capstone) by
testing `mvz.b`/`mvs.b` in isolation, register and `(a0)`/`(a0)+` addressing --
all matched 68k semantics exactly. Given more instruction budget (400M+) this
depacker completes normally and boot proceeds. A defensive safety valve was
added anyway (clamp the copy count if it ever exceeds 64K, `DEPACK_COPY` in
`emu/dspboot.py`) but it has never actually fired -- included for whatever
comes next, not because it was needed here.

**Lesson for next time**: before concluding a repeating-PC "stall" is a hang,
dump the actual loop-bound register(s) a few times. A slow-but-finite loop and
an infinite one look identical to a coverage-only heuristic.

### Blocker 2 (cleared, and generalized): idle spins need timer ticks too

With the above fixed, boot progressed in a large burst: task_create sites went
4 -> 5 -> 9 -> 10 as longer instruction budgets were tried (47M, 257M, 416M).
Between two of those bursts, boot hung again -- this time truly, 139M+
instructions with zero new coverage, at `0x400cf3e0`.

`0x400cf3e0` disassembles to `bra.b $400cf3e0` -- a literal self-branch. This
is the **exact same idiom** as the already-known `HALT` idle loop
(`0x400ceeb6`, also `bra.b $self`), which the harness already fed periodic
timer ticks (vector 32) to keep the RTOS scheduler moving. But the harness only
ever ticked *that one hardcoded address* -- a second thread/task's own
idle-wait-for-scheduler point at a different address got no ticks at all, so
once execution reached it, nothing could ever preempt it.

**Fix, generalized rather than special-cased**: scanned all of MAIN OS for the
opcode `0x60FE` (`bra.b -2`, i.e. branch-to-self) -- 13 occurrences total --
and feed periodic timer ticks to *all* of them, not just the one instance
someone happened to hit first (`find_idle_spins` in `emu/dspboot.py`). This is
exactly the kind of fix the diverging/converging distinction in the task brief
calls for: a class of blocker, not a single address.

This got two of the three known idle points working correctly (`0x400ceeb6`
and `0x400cf3e0` both now receive ticks and both did unblock at least once,
confirmed by `spin_by_addr` counters saturating at clean multiples of
`tick_every`).

### Where it stands now: a new, different kind of stop

After the burst that reached 10/16 (last new task at instruction ~416M,
`0x400f1a6c` -> entry `0x400f1eb6`, prio 2), execution parked at `0x400cf3e0`
and stayed there for the rest of a 1.4B-instruction run -- ~48,000 further
timer ticks, zero new coverage.

Traced precisely (not just inferred from the address repeating): `0x400cf3e0`
sits between a one-shot guard and a permanent idle trap in the *same* function
that produces 3 of the burst's 4 tasks:

```
400cf3d6  moveq #$40,d0
400cf3d8  and.l $40288190.l,d0
400cf3de  beq.b 400cf3e2                 ; bit clear -> do the work (it was clear: confirmed 0x40288190=0x04 at runtime)
400cf3e0  bra.b 400cf3e0                 ; <-- idle trap, same idiom as HALT
400cf3e2  jsr 0x4011311c                 ; wrapper containing task_create site 0x401131d2 (prio 7)
400cf3e8  jsr 0x4014635e                 ; wrapper containing task_create site 0x4014638e (prio 5)
400cf3ee  jsr 0x400329ee                 ; wrapper containing task_create site 0x40032a20 (prio 6)
400cf3f4  bra.b 400cf3e0                 ; done -- park here forever by design, same as HALT
```

So this is **not** a guard repeatedly failing -- it passed once, did its
one-shot job (matching the 3 near-simultaneous hits at instructions
257710408/257710485/257710555), and then deliberately loops to the same idle
trap as its designed terminal state, exactly like `HALT`. There is nothing
further for *this* thread to do; it is functioning correctly. This resolves
what looked like an open question in an earlier draft of this note.

The real open question is why **no other** thread creates any of the
remaining 6 `task_create` sites even after tens of thousands of scheduler
ticks. The newly-created prio 2/5/6/7/8 tasks are themselves candidates to be
the ones that would create more (or not -- they may simply be leaf worker
tasks). Two live hypotheses, neither confirmed:

1. One of the **other three** DSP transport call sites (`0x400cf000` timeout
   `0xF4240`, `0x400cfd8a` timeout `0x64`, `0x4012d46e` timeout `0x2DC6C0`) is
   what some other task is blocked on -- all session, only one of the four
   (`0x400cf928`) has ever been exercised (`transport calls: 1` in every run).
   If a task is parked in a *real* semaphore wait (`trap #0`, correctly
   descheduled by the RTOS) rather than a self-branch idle loop, our idle-spin
   fix does not apply to it -- it needs the same treatment as blocker 1
   (satisfy whatever it is actually waiting on), not more timer ticks.
2. The remaining 6 sites are in code that is reachable only through a
   different subsystem-init path this cascade never calls into at all under
   this configuration (not blocked -- just not on the current call graph).

**Checked, and it points at hypothesis 1.** For each of the 6 tasks created
after the first burst (prio 7/8/7/5/6/2), coverage tracking shows the RTOS
scheduler *did* switch into every single one of them -- their entry addresses
are all in `seen`, each followed by a small additional cluster of newly-hit
addresses (6 to 31 distinct addresses within a few hundred bytes of its entry
point). So `task_start` is not merely called on all 10 tasks
(`task_start hits: 10`, already known) -- the scheduler genuinely gave CPU
time to the 6 newest ones, each ran a handful of real instructions, and then
every single one went quiet with no further coverage growth for the rest of
a 450M/1.4B-instruction run. That is the signature of each one reaching its
own short init sequence and then hitting a genuine blocking wait very
quickly -- not of the scheduler failing to reach them (hypothesis 2, now
effectively ruled out) and not of them running unboundedly (they are not
CPU-bound). **Concrete next step**: for each of these 6, disassemble the
handful of instructions right past where its coverage cluster ends -- that
boundary is exactly where each one blocks, and is a small, bounded amount of
code to read per task (nothing like the earlier multi-hundred-instruction
transport functions).

### Convergence assessment

Up to 10/16: **converging**. Each fix (semaphore fast-path, two MMIO bit
forces, generalized idle-spin ticking) unlocked either the next blocker or a
burst of several `task_create` sites at once, and the depacker "stall" that
looked alarming turned out to be a false alarm resolved by patience, not a
patch. Past 10/16: **stalled, not diverging** -- one clearly-identified
address, no new blockers appearing, but the fix used for the last two blockers
(generic timer ticking) is confirmed insufficient here and the next fix needs
actual tracing of `0x40288190`'s producer(s), most plausibly tied to one of
the three still-unexercised transport call sites.

### Performance: a 2x+ harness speedup, reusable

`emu/harness.py` and `emu/dspboot.py`'s original hot path ran a single global
`UC_HOOK_CODE` callback on *every instruction*, which for the FF1/MOVEC
patches did a `mem_read` + `struct.unpack` unconditionally to check "is this
one of the two rare opcodes" -- on every single instruction of the run, not
just the rare ones. `Machine.install_isa_patches_scoped` (new) pre-scans the
image once for the actual FF1 (`0x04C0`-`0x04C7`, 232 hits) and MOVEC
(`0x4E7A`/`0x4E7B`, 7 hits) opcode addresses and registers a Unicorn hook
scoped to each exact address (`begin=addr, end=addr`) instead. `emu/dspboot.py`
does the same for its own instrumentation points (`fast=True`, the default;
`fast=False` keeps the original global-hook path for cross-checking). Measured
on identical 60M-instruction runs: 146s -> 73s wall-clock, same result
(verified byte-for-byte identical task_create hits, addresses, priorities).
This matters because runs at the scale needed here are 400M-1.4B instructions
(9-25+ minutes each even with the speedup).

### Reusable artifacts from this session

- `emu/dspboot.py` -- the instrumented DSP bring-up harness. Reports
  `task_create` sites reached (with entry/priority/tcb), transport call sites
  hit, semaphore-satisfy count, depack-clamp count, idle-spin addresses found
  and hit counts, distinct-address coverage curve, and stall PCs. Run directly:
  `./venv/bin/python -m emu.dspboot <instruction_limit> <patch_sem 0|1>`.
- `emu/harness.py` -- added `Machine.install_isa_patches_scoped`, a drop-in,
  much faster alternative to `install_isa_patches` for long runs.

### Next blockers, named **[V]**

After reaching 10/16 tasks, the remaining ones start and then go quiet. Measured,
not guessed:

1. **They are not blocked on semaphores.** There are two counting-semaphore pend
   primitives, both with a fast path when count > 0: `0x4000141a` and
   `0x400013a6`. Logging every call to both across 150M instructions finds
   **exactly one** — the already-patched transport wait at `0x40128d0e`. So the
   stalled tasks are not waiting on anything; they are not being scheduled.
   (`emu/blockers.py` does this logging.)
2. **The scheduler is hand-cranked.** Injecting `trap #0` (vector 32 — the
   task-switch trap) is the only thing that helps. Compared at 60M instructions:

   | injected vector | tasks | distinct addrs |
   |---|---|---|
   | 32 (trap #0) | 5 | 38,247 |
   | 66 | 2 | 329 |
   | 221 | 2 | 260 |
   | 222 | 2 | 260 |

   The candidate hardware ISRs installed during init (vectors 221/222/66 →
   handlers `0x400019bc`/`0x400019e6`/`0x40001a10`) are **not** the system tick.
   So we are forcing context switches rather than running a real scheduler.

**The prize is identified.** Task `0x400d3fb6` (prio 7, created at instr 47M) is
the **intro/animation task**: it calls a RNG at `0x40144bd8`, compares results
against `0x7fdf` and `0x3ffe`, and selects among static structs at
`0x4028ae5c`/`0x4028ae6c` — the same neighbourhood as the known intro
`PixelData` at `0x4028ae98`. If that task runs, it draws, and `emu/screen.py`
can capture the result.

**So the next blocker to attack is the scheduler itself**, not another
peripheral: find the real tick source, or drive the context-switch path directly
against the ready-list/TCB structures so tasks round-robin properly. **[O]**

### Snapshots — stop replaying boot **[V]**

Chasing each blocker meant re-running from the entry point: ~32M instructions of
identical setup (the memory-clear loop alone is ~8M) before reaching anything
new, then 15M more to the next event. Every experiment paid that toll.

`emu/snapshot.py` + `emu/checkpoint.py` remove it:

```
./venv/bin/python -m emu.checkpoint make 40000000 snapshots/boot40M.snap   # once
./venv/bin/python -m emu.checkpoint resume snapshots/boot40M.snap 5000000  # thereafter
```

Checkpoint creation: **42 s**. Resume + 5M instructions: **6.9 s**. Only non-zero
pages are stored (22 of 134 mapped), so 23 MB of live memory compresses to
1.8 MB on disk.

**Resume must happen inside `dspboot.run`, not onto a bare Machine.** The first
attempt restored state onto a fresh `Machine` with only the base hooks, which
silently dropped the flash HLE, the semaphore patch and the scheduler tick — and
diverged by ~50 addresses over 5M instructions while looking plausible. Fixed by
`restore_into()`, which loads onto an already-hooked Machine. Verified: snapshot
at 40M + 5M resume gives **coverage identical** to a straight 45M run (37,616
addresses both ways).

Snapshots are firmware-derived state, so `snapshots/` and `*.snap` are gitignored.

`make` takes a comma-separated ladder and saves them all in **one** pass, since
saving only reads state and emulation continues afterwards:

```
./venv/bin/python -m emu.checkpoint make 60000000,120000000,200000000,280000000
```

One 5-minute pass produced:

| checkpoint | distinct addrs | tasks | on disk |
|---|---|---|---|
| 60M  | 38,247 | 5 | 1.9 MB |
| 120M | 39,244 | 5 | 2.0 MB |
| 200M | 42,234 | 5 | 2.3 MB |
| **280M** | **47,335** | **9** | 2.4 MB |

Resuming from 280M reaches 9 tasks in **10 seconds**.

Two things that immediately became visible once iteration was cheap:

- The apparent "stall" at `0x40175288` is **`__mulsf3`** — a softfloat multiply
  (23 shift-and-add iterations = float mantissa). The stall metric flags any hot
  address after a window with no *new* coverage, so ordinary hot arithmetic looks
  like a hang. Not a blocker.
- Boot is **still progressing** past 280M, just slowly: 47,335 -> 47,637 distinct
  addresses over 60M further instructions, arriving in bursts. Not deadlocked.

### The scheduler was never running **[V]**

With cheap iteration, the actual state at the 280M checkpoint turned out to be
much simpler than "many blockers":

- **Zero context switches in 20M instructions.** The tick only fired at idle-spin
  addresses, and a *busy* task never reaches one. So one task held the CPU
  outright and the other eight never ran.
- **Preemption must respect the interrupt mask.** An earlier attempt at periodic
  `trap #0` injection crashed the machine (`pc=0`). The cause was injecting
  regardless of `SR`; a maskable interrupt cannot fire at IPL 7. Skipping
  injection when `(SR & 0x0700) == 0x0700` makes it stable — 100 injections,
  99 switches, no crash.
- **Scheduling is priority-based, not round-robin.** The ready-list cursor at
  `0x4094c914` points at a node whose `->next` is itself, i.e. a single ready
  task. Lower-priority tasks starve until the running one blocks — and our mocks
  are precisely what stop it blocking.

**The task holding the CPU is the intro task** (`tcb=0x43135210`, prio 7). It is
not stuck: outside the softfloat library it sits at `0x400d3900`, inside
`intro_dither`, doing per-pixel float work with the constants `0x3c000000`
(= 1/128) and `0x3f800000` (= 1.0) — consistent with normalising x across the
128-pixel-wide panel. It is generating the boot animation, just very slowly:
software floating point, per pixel, at ~300k emulated instructions/sec.

The known intro framebuffer at `0x43139290` is still all zeros after +100M, so
either a frame has not completed or the output goes to a different buffer.
Finding it is the next step — watch writes issued from the `0x400d3xxx` code
range. **[O]**

### Where the intro writes its pixels **[V]**

Watching writes issued from the `0x400d3xxx` code range (via the new `pre_start`
hook on `dspboot.run`) gives two destinations:

| destination | writes | what |
|---|---|---|
| `0x43135000` | 161,621 | the intro task's own stack (`tcb=0x43135210`) — not output |
| **`0x44f52000`** | 1024 per 4KB page | **the pixel work buffer** |

1024 longword writes per 4KB page means every word is written. The footprint is
**128 x 64 x 4 bytes = 32,768 bytes** — a float per pixel, matching the softfloat
work and the `1/128` normalisation constant.

Reading it back after +120M from the 280M checkpoint: **7,925 of 8,192 floats
non-zero**, and rendering with a relative-intensity ramp shows clear structure
with mirror symmetry — a smoothly varying field, consistent with `intro_dither`
generating a dither/noise field rather than a finished logo.

So the pipeline appears to be: generate a float field at `0x44f52000` -> combine
with a source image -> threshold into a `Bitmap`. The values are very small in
absolute terms (both min and max print as 0.0000 at 4dp), so this is an
intermediate, not the final image. **[O]** The `Bitmap` at `0x43139290` is still
zero, so the threshold/copy step has not run yet in emulation.

### The intro buffer is a particle array, not a framebuffer **[V]**

The 32,768-byte buffer at `0x44f52000` is **not** floats, despite sitting next to
heavy softfloat use. Only byte 3 of each 32-bit word is ever non-zero, so these
are small big-endian integers. Splitting them by parity settles it:

| | range | meaning |
|---|---|---|
| even indices | 0..127 | **x** — panel width |
| odd indices | 0..63 | **y** — panel height |

It is an array of **4,096 (x, y) particle positions** — the state of the boot
animation, which is what `intro_dither` animates. Rendering the captured buffer
plots all 4,096 in range and shows clear left-right mirror symmetry.

So the chain is: animate particles at `0x44f52000` -> rasterise into the 8bpp
`PixelData` at `0x43139290` -> `>>2` into `0x43137290` (loop at `0x400d3628`)
-> `px_copy_to_bitmap` -> `Bitmap`. Both 8bpp stages are still zero in emulation,
so the rasterise step has not run yet. **[O]**

Note this corrects the previous entry, which read the buffer as floats and
described it as a dither field. The values that made it look like a smoothly
varying field were coordinates.

### The firmware's draw path has not executed — timeboxed negative **[V]**

Two traces from the 280M checkpoint, 100M instructions each:

- **No reads of the particle array** at `0x44f52000` — so nothing has consumed
  the animation state yet.
- **No writes to either 8bpp buffer** (`0x43139290`, `0x43137290`).
- **`Bitmap::setPixel` (0x40104eb4): 0 calls. `px_copy_to_bitmap` (0x400d315e):
  0 calls.**

So the intro task is still in its *compute* phase — animating particles — and the
rasterise/draw stage begins later, or waits on something not yet satisfied. No
callable entry point for it was found, so per the agreed timebox this stops here
rather than becoming another grind.

What we do have: the animation state itself is readable and renderable
(4,096 particles plotted on the real 128x64 geometry), and the final stage
(`px_copy_to_bitmap` -> `Bitmap` -> decode) is independently verified pixel-exact
by `emu/screen.py`. Only the middle link — particles to 8bpp raster — is missing,
and it is missing because it has not *run*, not because it is not understood.

### Emulation is 9x faster than it was **[V]**

The per-instruction Python hook used for coverage tracking capped throughput at
~300k instr/sec. Almost none of it was necessary: every HLE side effect lives at
a known address, and Unicorn hooks registered with `begin == end` cost nothing
between hits. The one thing that appeared to need a global hook — the preemption
tick, fired on an instruction count — doesn't: `emu_start(pc, 0, count=N)`
returns after N instructions, so the tick can be driven by *chunking* instead.

`emu/fastrun.py`: **2.72M instr/sec**, a 9x improvement. A billion instructions
is now ~6 minutes rather than an hour.

### The firmware has a serial command console **[V]**

MAIN OS carries a command protocol, dispatched by a `strcmp` chain at
`0x400cd93e` onward:

`#HELLO` -> `HOW DO YOU DO?`, plus `#BREAK`, `#UPGRADE`, `#FULL_UPGRADE`,
`#WRITE`, `#DUMP_AUDIO`, `#RECEIVE_AUDIO`, `#PLAY_STEREO`, `#VERIFY_SAMPLES`,
`#ENTER_TEST_MODE`, `#EXIT_TEST_MODE`, and status replies `READY FOR OS`,
`READY FOR BOOTSTRAP`, `READY FOR SAMPLE DATA`.

Key handles:
- **`0x400054b4` is the print function.** Hooking it captures all console output
  regardless of transport — no UART modelling needed.
- The console is a **task**, entry `0x400cd594`, priority 2 — one of the 16
  `task_create` sites, and one our boot has not reached.
- UART8 is modelled properly in `emu/console.py` (USR8 `0xEC070004` with real
  RXRDY/TXRDY, data register `0xEC07000C` popping queued input and capturing
  output) rather than pinned to a constant.

Starting the console task manually from a snapshot runs but yields almost
immediately into an idle spin, so it needs more of the system up first. **[O]**

## Making the emulator actually run -- session 3

Marks: **[V]** verified in this session, **[C]** corrects an earlier claim,
**[O]** open.

### The scheduler never worked, and one line explains it **[V][C]**

Every run before this one scheduled exactly **one task**. The stated ceiling in
`docs/NEXT.md` -- "1 new task per ~250M instructions, and the gaps are
widening" -- was not a property of the firmware. It was this bug.

`harness.raise_vector` pushed the *current* PC into the exception frame. The
RTOS yields with `trap #0`, and Unicorn reports a trap with PC still pointing
**at** the trap instruction. So every task that blocked in `sem_pend` got a
stack frame that resumed onto its own `trap #0`. The instant the scheduler
restored it, it trapped again. Tasks could block but could never wake.

The evidence is direct: `emu/tasks.py` decodes each TCB's parked PC, and
before the fix all eight blocked tasks sat at `0x40001486` / `0x40001414` --
the `trap #0` instructions themselves. After it they sit at `0x40001488` /
`0x40001416`, the `move.w d0,sr; rts` that follows.

`raise_vector` now takes `from_instruction=True` from the interrupt hook and
advances the pushed PC by 2 when the faulting word is `0x4E40-0x4E4F`.
Asynchronous injections still push the interrupted PC, which is correct.

**Distinct TCBs scheduled: 1 -> 5.** `emu/oracle.py` and
`emu/screen.py selftest` both still pass.

### TCB layout, from the context switcher **[V]**

`0x40000410` gives it away:

    movea.l $47d9adb4,a0        ; current TCB
    movem.l d0-d7/a0-a7,$c(a0)  ; registers at TCB+0x0C
    move.l  -4(a7),$2c(a0)      ; => a0 at +0x2C, a7 at +0x48
    movea.l $4094c914,a1        ; ready-list cursor
    movea.l (a1),a0 ; movea.l (a0),a0   ; TCB+0x00 = next pointer

A parked task's PC is on its own stack: ColdFire pushes two longwords,
`[a7]` = format/vector/SR and `[a7+4]` = PC. `emu/tasks.py` prints the whole
table plus the ready list from any snapshot.

**Priorities run low-number = low priority.** prio 0 and 1 are the init/idle
tasks; the real work is at 5-10.

### `0x400cf3e0` is not an idle spin needing ticks **[V][C]**

`emu/dspboot.py`'s comment calls it "a different task/thread's idle point"
that was blocking progress. It is actually where the prio-1 init task **parks
after finishing its work**, reached by the `bra.b` at `0x400cf3f4` at the end
of its main loop:

    400cf3e2  jsr $4011311c
    400cf3e8  jsr $4014635e
    400cf3ee  jsr $400329ee
    400cf3f4  bra.b $400cf3e0     ; -> bra self

Feeding it timer ticks does nothing, because it is a *ready* task at priority
1 and the scheduler correctly keeps choosing it. It parks there because
everything above it is blocked.

### A boot-mode flag word at `0x40288190` **[V]**

Two bits of it gate real behaviour in the init task, and its value in every
snapshot is `0x00000004`:

| bit | test site | effect when set |
|---|---|---|
| 5 (`0x20`) | `0x400cf386` | creates and starts the **serial console task** |
| 6 (`0x40`) | `0x400cf3d8` | falls into `bra self` at `0x400cf3e0` -- deliberate halt |

Bit 5 clear is why the console task never existed. Setting it before the init
task reaches `0x400cf384` creates it:
`TASK entry=0x400cd594 prio=2 tcb=0x40383e58`.

Note bit 6 is a *halt*, not a hang: `beq` past it is the normal path. The
earlier reading of `0x400cf3e0` as an idle spin conflated the two.

### The six task_create sites that never fire **[V]**

`0x400cd594` has no absolute reference anywhere in MAIN OS -- it is pushed
PC-relative (`pea.l $400cd594(pc)`), which is why searching for the address
found nothing. Reading the entry operand out of each unreached site:

| site | entry | prio | |
|---|---|---|---|
| `0x400ced72` | `0x400cd594` | 2 | serial console |
| `0x401135a8` | `0x401136ee` | 3 | |
| `0x401279e8` | `0x40127c78` | 4 | |
| `0x40127a7c` | `0x40127d9e` | 4 | |
| `0x40127960` | `0x40127b24` | 5 | |
| `0x40125fde` | `0x4012606a` | 6 | |

### Every task waits on a device event that never happens **[V]**

With the trap fix in, tasks block properly -- and then all of them block, on
semaphores that only real hardware would post. `dspboot` already force-satisfies
one such semaphore (the DSP transport completion sem). Generalising that to
*any* pend whose count is <= 0 is `longrun.build(unblock=True)`.

Sweeping all ~20 installed device ISRs and injecting each one wakes nothing:
the two that look like timers (`0x400cf424` vec 65, `0x400cf450` vec 68)
dispatch a one-shot callback pointer that is null, so they are timeout slots,
not the event source.

### The panel draws **[V]**

With `unblock=True` from `boot400M`, `Bitmap::setPixel` executes for the first
time in this project: **688,128 calls = exactly 84 frames of 128x64**, all into
one Bitmap object at **`0x4313b298`** -- the panel framebuffer instance, which
was previously unknown. The rendered frame is the Elektron logo.

`emu/frame.py` captures it and writes a PNG. This is firmware code drawing
through the firmware's own `setPixel`; nothing about the raster is
reimplemented.

Note this also settles the older open item: the intro's rasteriser does run,
and reaching it needed no new entry point -- only a scheduler that works.
`unblock=True` does change semantics (nothing ever really waits), so
inter-task ordering under it is not the hardware's.

### Resume fidelity: the chunk-boundary tick was corrupting runs **[V][C]**

`longrun.spin` injected a vector-32 trap at every 500k-instruction chunk
boundary. Vector 32 *is* `trap #0`, the scheduler yield, so this forced a
reschedule in the middle of arbitrary code. A run resumed from `boot200M` then
never reached the init task's own flag test at `0x400cf384`, while
`dspboot.run(resume_from=...)` reproduced the from-entry timeline exactly
(task creations at n=257642531, 257710409, 257710486, 257710556, 416346994).

`spin()` no longer ticks by default. `build()` instead installs the two
behaviour hooks it had been missing -- the depack copy clamp and the idle-spin
ticks -- so it now matches `dspboot.run` while staying ~2x quicker.
This is trap 4 in a subtler dress: the hook set, not just the Machine, has to
match the run that produced the snapshot.

### Emulation is 3.2x faster again **[V]**

`longrun.build` was calling `install_isa_patches` (a Python callback on every
instruction) where the snapshots had been made with
`install_isa_patches_scoped`. Switching to scoped: **0.79 -> 2.80M instr/sec**,
with byte-identical state (same PC, `ff1=120821`, `movec=4`, same particle
count). `isa='global'` remains available.

### The console blocker, named exactly **[V][O]**

With bit 5 set the console task starts, runs **22 instructions**, and blocks --
never reaching the UART read or the `strcmp` dispatcher. The last instruction is

    400cd5e6  pea.l $40388eac.l
    400cd5ec  jsr   $40001928.l      ; queue-receive on the console input queue

`0x40001928` is a ring-buffer queue receive. Reading it:

    a2 = queue (0x40388eac)
    d2 = a2 + 8                 ; the semaphore, 0x40388eb4
    loop: if 4(a2) == 0 { pend(a2+8); repeat }
    ...  head/tail at 0x1c(a2), mask at 0x10(a2), buffer at 0x14(a2)

So the console needs an *item enqueued*, not merely a semaphore post -- posting
`0x40388eb4` via the firmware's own post primitive (`0x4000148c`, driven from a
synthetic ISR) lets the pend return, but `4(a2)` is still 0 so it loops
straight back. Confirmed: 0 instructions of console-task code execute.

`0x40388eac` has only three static references, all inside the console task and
its own creation, so the producer reaches the queue through a pointer --
most likely the object at `0x40303e50` registered at `0x400cd5a8`
(`jsr $40110592`) right before the receive loop. **That registration is the
thread to pull next.** **[O]**

Also worth noting for whoever picks this up: the console protocol words are
`#HELLO`, `#BREAK`, `#UPGRADE` and friends -- not `help`.

## Why the emulator was slow: 93% of it was soft-float **[V]**

The GUI ran at ~1.3 firmware frames/sec. Profiling found the cause is not the
harness at all -- a minimal machine (scoped ISA patches + mmio + exceptions)
runs at 2.16M instr/sec and the full hooked machine at 2.19M, so **every hook
in this project is free**. Chunk size makes no difference either.

> **Corrected 2026-09-13.** This section used to end "~2.2M instr/sec is
> simply what Unicorn's m68k core does here." That is wrong, and it steered
> later decisions. ~2.2M is what the core does *when `count=` is passed to
> emu_start*, which Unicorn implements by counting every instruction and
> which breaks TB chaining. The same machine with the identical hook set and
> the identical stop mechanism runs at **15.5M instr/sec uncounted -- a 7.6x
> tax**, and a cProfile of the running configuration puts **99.5% of wall
> time inside emu_start** with every Python callback in this project under
> 0.5% combined. The hooks really are free; the ceiling was never the core.
> `longrun.spin(fast=True)` buys it back for interactive use, at the cost of
> timers landing on a block boundary rather than an exact instruction. The
> paragraph below -- "the only way to go faster is to execute fewer
> instructions" -- followed from the wrong premise.

So the only way to go faster is to execute fewer instructions. An exact PC
histogram over the intro says where they go:

| region | share |
|---|---|
| `0x40174000-0x40176000` (soft-float) | **93.2%** |
| everything else | 6.8% |

This ColdFire build has no hardware FPU, so every float operation is a
libgcc-style routine, and the particle animation is float-heavy.

### Identifying the routines, rather than guessing

Entry points were found by watching which addresses execution *enters* the
region at (transitions from outside it), then identified by calling each one
with known values and comparing against real arithmetic:

| entry | routine | share |
|---|---|---|
| `0x40175204` | `__mulsf3` | 46.3% |
| `0x40174f1c` | `__subsf3` -- `bchg.b #$1f,$8(a7)` then falls into add | 22.1% |
| `0x40174f22` | `__addsf3` | |
| `0x40175346` | `__divsf3` | 4.5% |
| `0x40175a94` | `__fixsfsi` (float -> int, truncate) | |
| `0x40174134` | `fabsf` | |
| `0x40175834` | float compare -> -1/0/1 | |

The other hot addresses in the region (`0x40175644`, `0x4017550a`, ...) are
internal helpers of these, so intercepting the entries removes them too.

### The firmware's float routines are not IEEE-754 **[V]**

Comparing a native implementation against the firmware's own code found
systematic disagreement, all at the edges: the add returns **-0.0 on exact
cancellation** where IEEE gives +0.0, and it gets **infinity signs wrong**
(`-1.0 - inf` yields `+inf`). `__fixsfsi` returns `0xFFFFFFFF` for
out-of-range input, which is undefined behaviour in C.

Rather than replicate those quirks, `emu/softfloat.py` intercepts **only the
fast path** -- finite arguments producing a finite, normal, non-zero result --
and falls through to the real routine for everything else, which then defines
the answer by construction. Same shape as the sem_pend patch, which takes the
primitive's own fast path instead of reimplementing it.

For normal values this is not an approximation: computing in float64 and
rounding once to float32 gives exactly the correctly-rounded float32 result
for +, -, * and /, since 2*24+2 = 50 <= 53 bits. `uv run python -m emu.softfloat`
checks all seven routines against the firmware's: **1,774 intercepted cases,
0 mismatches**, 1,154 edge cases deferred.

### Then setPixel became the bottleneck **[V]**

With the float work gone, the soft-float region fell to 1.9% and the top cost
became `Bitmap::setPixel` (`0x40104eb4`) plus `getPixel` (`0x40104f80`) at
~54% combined -- the rasteriser touches all 8,192 pixels per frame and reads
many back. Both are small, fully understood bit-twiddlers, HLE'd in
`emu/hle.py`. Two details matter: the bounds comparisons are **signed**, and
the value is tested with `btst.b #0`, so **val=2 clears a pixel**. The HLE
writes the same bits into emulated memory, so anything reading the bitmap back
sees identical state. Verified: 680 cases, 0 mismatches.

### Result

| configuration | fps | instructions for 12 frames | |
|---|---|---|---|
| all emulated | 1.32 | 20,750,000 | 1.0x |
| + soft-float HLE | 2.37 | 9,250,000 | 1.8x |
| + bitmap HLE | 4.06 | 3,750,000 | **3.1x** |

Frames are **pixel-identical** across all three, which is the gate that makes
the optimisation trustworthy.

What is left is mostly the rasteriser itself (`0x400d3d7e` 39%, `0x400d3bea`
12%) -- the firmware logic the whole exercise exists to watch, so HLE'ing it
would defeat the point. Another ~17% is scattered math worth maybe 1.2x more.

Both HLEs are **off by default** in `longrun.build`. They are bit-exact so
program state evolves identically, but instruction *counts* change, and too
much here depends on a resumed run matching the run that made its snapshot.
`emu/frame.py` and `emu/gui.py` opt in; `FAST=1` turns them on for the
`emu.longrun` CLI.

The GUI's own redraw was measured at 0.94ms (~2% of a core) and was never the
problem; it now skips redrawing when no pixel changed, and reuses one zoomed
image instead of allocating per frame.

## The intro is meant to run at 15.00 fps, and the bus clock is 132 MHz **[V]**

"How fast should it be?" is answerable exactly, not by eye.

**The draw loop is paced by a semaphore, not by how fast it can go.** The task
at `0x400d3fb6` ends in:

    400d402a  jsr (a2)              ; render one frame  (a2 = 0x400d3e94)
    400d402c  tst.b d0
    400d4030  pea.l $43131200
    400d4036  jsr (a3)              ; a3 = 0x400013a6, sem_pend
    400d403a  bra.b $400d402a

and `0x43131200` is posted by the ISR at `0x400d2d70`, installed at vector 208
(`move.l #$400d2d70,$40000340` at `0x400d3a5a`), which acknowledges PIT3 and
calls sem_post. **One PIT3 interrupt = one frame.**

PIT3 is configured at `0x400d3a7a`: `PCSR = 0x0936` (PRE=9, so prescaler
2^10 = 1024), `PMR = 0x2191` = 8593, then `PCSR |= 9` (EN|PIE). One frame is
therefore `(8593+1) * 1024 = 8,800,256` bus cycles.

**The bus clock comes from the UART, not a guess.** The serial init computes
its baud divider at `0x400024a4`:

    4000245a  lsl.l  #5,d0          ; baud * 32
    400024a4  move.l #$07de2900,d2
    400024b0  divs.l d0,d2          ; divider = f_bus / (32 * baud)
    400024ce  move.b d2,$ec07001c   ; UBG2

`0x07DE2900` = **132,000,000**, and the ColdFire UART divider is exactly
`f_bus / (32 * baud)`, so that constant is f_sys/bus clock.

It cross-checks against all four PITs landing on round rates, which is what
makes 132 MHz trustworthy rather than merely plausible:

| timer | PMR | prescaler | bus cycles | period | rate |
|---|---|---|---|---|---|
| PIT0 (RTOS tick) | 41249 | 64 | 2,640,000 | 20.0000 ms | **50.0000 Hz** |
| PIT2 | 17187 | 128 | 2,200,064 | 16.6672 ms | **59.998 Hz** |
| PIT3 (intro frame) | 8593 | 1024 | 8,800,256 | 66.6686 ms | **14.9996 Hz** |

So the boot animation runs at **15 fps** on hardware, the RTOS tick is 50 Hz,
and PIT2 is a 60 Hz something. PIT1 is set up at `0x40128d34` in the DSP
transport path.

### What that says about the emulator

The GUI reaches ~4.2-4.7 fps, i.e. **~30% of real time**, and the status line
now reports it that way instead of leaving it to the eye.

Arithmetic for closing the gap: real hardware runs ~1.73M instructions per
frame; with both HLEs on we execute ~312k. At Unicorn's ~2.2M instr/sec that
is ~7 fps of headroom before hook overhead, and we measure 4.2-4.7. Reaching a
true 15 fps needs ~147k instructions per frame. The remaining scattered math
(~17%) is worth maybe 1.3x; past that the cost is the rasteriser itself
(~51%), so matching real time would mean reimplementing the very thing the
emulator exists to watch.

### unblock=True removes the pacing -- and distorts boot **[V]**

Because `unblock=True` satisfies *every* wait, it satisfies the frame
semaphore too: the animation runs unpaced rather than at 15 fps.

Excluding `0x43131200` and driving vector 208 from a modelled PIT3 was tried
and **does not work on its own**: the ISR fires and the semaphore count climbs
(observed reaching 33), but the draw task never runs, because with every other
wait satisfied the prio-6 task never yields and the scheduler never
reschedules. Faithful pacing needs cycle accounting so the 50 Hz RTOS tick can
preempt as well. `longrun.build` now takes `unblock_except` for whoever picks
this up.

Worth noting: leaving the frame semaphore unsatisfied changed the boot path
and created **two further tasks**, including `0x4012606a` (prio 6) -- one of
the six that never appear under blanket unblock. That is more evidence that
blanket unblock distorts boot, and a hint for reaching the remaining tasks.

## What we were overlooking about ColdFire: eDMA **[V]**

Feeding bytes to the UART model in `emu/console.py` could never have produced
console input, because **the firmware never reads UDR8 to receive**. UART8
receive is done by eDMA channel 34, with no CPU involvement per byte.

Checked and ruled out first: the PIT counter registers (`PCNTR`, `0xFC08x004`)
are **never read** by MAIN OS, so they do not need modelling. eDMA is a
different story -- 14 channels are configured.

From the init at `0x40002516`:

    TCD34.SADDR  = 0xEC07000C     ; UDR8, fixed (SOFF = 0)
    TCD34.ATTR   = 0x0050         ; DMOD = 10 -> destination modulo 1024
    TCD34.DADDR  = 0x4FE1A000     ; a 1024-byte ring
    TCD34.NBYTES = 1              ; one byte per request

and the ISR at `0x40001f1a`, vector 154:

    idx  = [0x4094CDA4]                        ; consume index
    base = [0x4094CD84]                        ; ring base
    while base + idx != [0xFC045450]:          ; DADDR = live write pointer
        byte = ring[idx]; idx = (idx + 1) & 0x3FF
        [0x4094CDB4](byte)                     ; registered callback

The ATTR decode (destination modulo 1024) matches the ISR's `andi.l #$3ff`
exactly, which is what confirms the reading.

**The channel's own DADDR register is the producer pointer**, polled by the
ISR. So injecting input needs no general eDMA emulation -- write into the
ring, advance DADDR with the same modulo, raise vector 154. That is
`emu/serial.py`, and it works: feeding `#HELLO\r\n` drives the RX callback
exactly 8 times, the consume index advances 0 -> 8, and the bytes are enqueued
onto the serial message queue at `0x47D9ADC0` (count 6 -> 8).

TCD35 is the matching transmit channel; the ISR at `0x40001d00` (vector 180)
is UART8 **transmit** only, pulling from a ring at `0x4094CD80`.

### The remaining console blocker, one step further on **[O]**

Nothing drains `0x47D9ADC0` -- it already holds 6 unconsumed messages before
any input is injected. Its consumer is the task at **`0x401136EE` (prio 3)**,
one of the six that never get created. It is created lazily by the singleton
at `0x401134CC` (guard `0x44F1E070`, allocation via `0x401114A8`) on first use
of the serial service, and nothing in our boot ever asks.

`emu.serial.create_serial_task` runs that initialiser and the task **is**
created (`entry=0x401136ee prio=3 tcb=0x44dfccb4`, an 11th task). It has not
been observed draining the queue yet -- created is not the same as started and
scheduled, and that is the next thing to check (whether `task_start`
`0x40001314` runs for that TCB, and whether the scheduler ever selects it).

So the chain is now fully mapped and only its last link is missing:

    DMA ch34 -> ring 0x4FE1A000 -> vector 154 -> callback 0x40110F20
      -> queue 0x47D9ADC0 -> [task 0x401136EE, not draining]
      -> queue 0x40388EAC -> console task 0x400CD594 -> dispatch 0x400CD93E

### Other ColdFire details worth knowing

- `raise_vector` does not set SR on exception entry. Real ColdFire sets S,
  clears T and, for interrupts, raises the mask. Most ISRs here begin with
  `move.w #$2700,sr` themselves, but the PIT3 ISR at `0x400d2d70` does not, so
  this is a latent reentrancy difference rather than a proven bug.
- The exception frame's format field is written as 0; ColdFire uses 4 for a
  normal 2-longword frame. Harmless here because `rte` is implemented by hand
  and ignores it.

## The MMIO hook was global too **[V][C]**

The earlier conclusion "every hook in this project is free" was wrong, and
wrong for a methodological reason worth remembering: it compared a *minimal*
machine against a *fully hooked* one, but `install_mmio()` was in **both**, so
its cost cancelled out and never appeared in the comparison.

`install_mmio` registered `hook_add(UC_HOOK_MEM_READ, on_read)` with no
`begin`/`end` -- a Python callback, plus a loop over the mmio dict, on **every
memory read the firmware makes**. Exactly the same mistake as
`install_isa_patches`, which had already cost 3.2x.

There are only three MMIO addresses, so one narrow hook each:

| configuration | throughput |
|---|---|
| global hook (as shipped) | 2.15M instr/s |
| scoped per-address hooks | **2.86M instr/s** (1.33x) |
| no MMIO hook at all (ceiling) | 2.91M instr/s |

Scoped lands within 2% of the ceiling, so this is the whole of that cost.

**But it barely moves the GUI**, and that is the interesting part: on the
fully-emulated path it is worth 1.33x (1.32 -> 1.50 fps end to end), while on
the softfloat+bitmap HLE path the GUI actually runs it is worth ~3% (3.99 ->
4.10 fps). With HLE we execute 5.5x fewer instructions, so there are far fewer
memory reads to tax, and the bottleneck has moved from TCG to Python callback
dispatch -- ~88k HLE calls per 12 frames. Further speed has to come from
making those callbacks cheaper or fewer, not from removing more hooks.

Ordering hazard, now fixed: `restore_into` merges the snapshot's own mmio
entries, so `install_mmio` has to run *after* the restore or a
snapshot-carried address gets no hook. `longrun.build` does that now.

## Correct-speed playback **[V]**

Emulating at the real 15 fps needs ~3x more throughput than we have, but the
frames themselves are correct and pixel-identical to a fully emulated run --
so the animation can be *shown* at its true speed even though producing it is
slower. `emu/gui.py` keeps every completed frame and its **Replay 15fps**
button plays them back at `FRAME_HZ`, self-correcting for drift. Measured 83
frames cycling at ~14-15 fps against the 14.9996 target.

That separates the two things that were conflated: emulator throughput (30% of
real time, and bounded by the rasteriser) versus what the animation actually
looks like on the device (now viewable).

## The serial console works **[V]**

    #HELLO            -> HOW DO YOU DO?
    #BREAK            -> OK
    #UPGRADE          -> READY FOR BOOTSTRAP
    #ENTER_TEST_MODE  -> OK
    #EXIT_TEST_MODE   -> OK
    #NOPE             -> (no reply, correctly rejected)

`uv run python -m emu.serial console '#HELLO'`.

The last piece was realising **what the console queue actually carries**. It
does `sscanf(item, "%s", buf)` (format `'%s'` at `0x4022A912`, via
`0x400CC93A`) and then strcmps `buf` against its command table using strcmp at
`0x4017C300`. So a queue item is a **pointer to a NUL-terminated string**.

That is why routing the raw serial stream at it did not work. The chain from
DMA does deliver messages -- pointing the sink at the console queue made the
console wake and run its dispatcher twice -- but those messages are the
timestamped 16-byte records built at `0x40110D40` by what is really a
MIDI-style router (8 ports, a timestamp from `0xFC07000C` at `+0x0C`), not
text. The dispatcher ran and matched nothing, exactly as it should.

Two things found along the way:

- **The serial sink is a global**: the producer pushes the destination queue
  from `[0x4029D864]`, and `0x401109E0` is `set_serial_sink(queue)` (its only
  caller is `0x40033130`). By default it points at `0x47D9ADC0`, a queue that
  **no `queue_receive` call site in the firmware reads** -- there are only
  three such sites in the whole image, for queues `0x4094EF3C`, `0x40388EAC`
  (console) and `0x44E0C290`.
- The console task at `0x400CD594` is created only when **bit 5 of
  `0x40288190`** is set (see the boot-mode flag section), and it registers
  `(0x80008, 0x40303E50)` into `0x44DADD0C`/`0x44DADD10` at `0x400CD5A8`.

`emu.serial.send_command` enqueues through the firmware's own `queue_send`
(`0x40001896`), so the semaphore is posted and the task woken exactly as it
would be normally; output is captured by hooking `print` at `0x400054B4`.

**`#UPGRADE` answering `READY FOR BOOTSTRAP` matters for work item B**: the
firmware-upload path is now drivable under emulation, so a patched image can
be pushed at the device's own acceptance logic without touching hardware.

## Boot reaches the main OS: the stall was eDMA, not a semaphore **[V]**

The previous session's conclusion -- that `unblock=True` was needed for the
intro and poisoned everything after it, and that `0x400d404a` was unreachable
in 900M instructions -- had the right symptom and the wrong cause. The intro
was not failing to *exit*; it was failing to *finish*. It stopped rendering at
exactly frame 88 of 175, every time, and never got near its exit path.

### The intro's own termination condition

`0x400d3e94` (the render call at `0x400d402a`) returns 0 when the intro is
over, and it is driven purely by call count, not by time:

| | |
|---|---|
| scene count `[0x4313b290]` | 1 |
| scene table `[0x4313b294]` | `0x4028ae2c` |
| draw fn / frames | `0x400d3ab6` / **175** |

So the intro is 176 render calls and nothing else. It is not waiting for a
timer, and there was never a reason it could not finish.

### Where it actually stopped

`0x4000220c` is the firmware's "queue bytes for the console" routine. It opens
with a spin loop waiting for room in a 4096-byte ring at `0x4FE1B000`:

    4000221c  d2 = [0x4094cd90] + len          ; bytes wanted
    40002232  d1 = w[0xFC045474]               ; TCD35.CITER
    40002238  d3 = w[0xFC04547C]               ; TCD35.BITER
    40002244  d1 = (d1 - d3) + ([cd88] - [cd94])
    40002246  d1 &= 0xfff                      ; -> bytes still in the ring
    40002252  if 0x1000 - d1 < d2: goto 4000221c

Nothing advanced that channel, so the ring never drained. The intro draw task
span there at priority 7 and starved everything -- which looked exactly like
the priority-7 busy-spin `unblock=True` was blamed for.

### Channel 35 is UART8 transmit

TCD35 at `0xFC045460`, in the **ColdFire** eDMA layout where CITER is at +0x14
and BITER at +0x1C (not the Kinetis order):

    SADDR  = 0x4FE1B000   ring; ATTR = 0x6000 -> SMOD 12, source modulo 4096
    NBYTES = 1            one byte per request
    DADDR  = 0xEC07000C   UDR8, DOFF = 0

`0xFC044018` is EDMA_SERQ (start), `0xFC044019` CERQ (stop). Vector **155**
points at `0x40001e7c`, the channel-35 completion ISR -- ch34 (RX) is 154, so
the vectors are contiguous. The ISR clears EDMA_CINT, sets `[cd94] = [cd88]`,
and either parks the channel or chains the next transfer.

`emu/edma.py` runs the whole major loop on a SERQ write, advances SADDR with
the ring modulo, reloads CITER from BITER as hardware does at major-loop
completion, and raises vector 155 so the firmware's own ISR does the
bookkeeping. The completion is queued rather than raised inside the write
hook: the enqueue routine writes SERQ with SR = 0x2700, so hardware could not
deliver it there either.

The firmware ring fields, all confirmed against the enqueue routine and the
ISR: `cd74` state (0 idle / 1 running / 2 draining), `cd7c` ring base, `cd88`
head, `cd8c` write index, `cd90` bytes queued but not yet handed to DMA,
`cd94` offset fully drained.

### Result

Intro runs all 175 frames, then reaches `0x400d404a`, `0x400d4058` and
`0x400d4060`. Six previously-missing tasks spawn (`0x400f1eb6` prio 2,
`0x4012606a` prio 6, `0x400f1fce` prio 3, `0x40127b24` prio 5, `0x40127c78`
and `0x40127d9e` prio 4) and `0x40000e82` formats real parameter values:
`'%s: %.16s' 'ONE'`, `'FWD'`, `'OFF'`, `'0.00'`.

PIT3's PCSR goes `0x093f -> 0x0000` across the intro, by the firmware's own
`move.w d0,$fc08c000` -- so a PCSR-gated PIT model stops delivering frames
after the intro without being told to. PIT0 (50 Hz, vec 205) and PIT2
(59.998 Hz, vec 207) stay enabled; PIT1 is off.

### `unblock` had to be narrowed, not removed **[V]**

Blanket-satisfying every pend hid a second copy of the same mistake.
`queue_receive` (`0x40001928`) pends on the queue's own semaphore at queue+8
and then **re-reads `queue->count`**. Satisfying the semaphore without also
enqueuing an item turns a sleep into an infinite spin: 8.9M iterations, ~92%
of all post-intro cycles, on one queue.

The fix is caller-based, not semaphore-based, so it generalises to every queue
in the system: never satisfy a pend whose return address is `0x40001946`. The
same shape appears again at `0x401260c2` in the prio-6 task, which pends on
`0x44e2d148` then re-checks a flag at `0x44e2d5cc`.

Caller-based discrimination also removes the intro handoff entirely. The intro
loop pends the frame semaphore from `0x400d4038` and must be satisfied; the
park loop pends the *same* semaphore from `0x400d4068` and must not be. Two
different callers, one rule, no state to hand over -- and it survives a
snapshot taken after the intro.

Post-intro pends satisfied: **8.9M -> 1.** Nine tasks reach clean blocking
waits instead of spinning.

## The part is an NXP MCF5441x (ColdFire V4m) **[V]**

Established from the peripheral map the firmware itself uses, which is an
exact fingerprint:

| base | module |
|---|---|
| `0xEC070000` | UART8 (a part needs 10 UARTs for UART8 to live here) |
| `0xEC094000` | GPIO |
| `0xFC044000` | eDMA, TCDs at +0x1000 |
| `0xFC048000` / `0xFC04C000` / `0xFC050000` | INTC0 / INTC1 / INTC2 |
| `0xFC05C000` | DSPI0 |
| `0xFC080000`-`0xFC08C000` | PIT0-PIT3 |
| `0xFC090000` | EPORT |

### Flash and DDR capacity **[V]**

Both come out of the firmware's own code; neither needs a datasheet or a probe.

DDR is **64 MiB**, from the bootstrap's own DDRMC writes:

```
DDR_CR04 @0xFC0B8010 = 0x00010101   ; bit 8 8BNK=1     -> 8 banks
DDR_CR15 @0xFC0B803C = 0x02000103   ; ADDPINS=2        -> rows = 15-2 = 13
DDR_CR16 @0xFC0B8040 = 0x02000407   ; COLSIZ=2         -> cols = 12-2 = 10
```

with the controller's fixed 1 chip select and x8 datapath: `2^23 * 8 * 1 =
67,108,864`. The init sequence is byte-identical on both devices.
`tools/ddr_geometry.py` re-derives this from any bootstrap image.

NOR flash is **16 MiB**. The bootstrap issues RDID (`0x9F`) and dispatches on
the 5 ID bytes at `FUN_800024ec`; only the branch matching mfg `0x01`, id
`0x2018`, ext `0x00` — an S25FL127S-class part, 128 Mbit — selects the
512-byte page and 256 KB erase geometry the flash loop actually uses. Weaker
than the DDR result by one step: the firmware *recognises* the part, it never
computes a capacity. **[V]/[D]**

Against a store-only repacked image this is not close. What is staged and
flashed is the decoded container, **4.00 MB** against a stock 1.35 MB — the
5.07 MB `.syx` figure includes 8-in-7 transport framing that never lands in
memory. Headroom is 16.8x on DDR and 4.1x on flash. A real LZ77 packer is not
needed. That everything past the OS container to the end of the chip is free
is an assumption; no partition table has been located. **[O]**

**V4m, not V4e** -- MMU and EMAC but **no FPU**. That is the real reason 93%
of executed instructions were soft-float: it is not a compiler flag, the part
has no hardware float. (We run Unicorn as `UC_CPU_M68K_CFV4E`, a superset;
harmless because the firmware never issues FPU instructions.)

One loose end: the firmware's own bus-clock constant is 132 MHz
(`0x07DE2900`), while the datasheet headline is 250 MHz core. If the bus were
core/2 that implies a 264 MHz core, slightly over the published maximum. The
15 fps result does not depend on resolving this -- the PIT and UART share a
clock domain and we used the firmware's own constant, cross-checked by three
timers landing on round rates.

## What actually limits speed: our hook layer, not Unicorn **[V]**

Superseded by measurement. An earlier version of this section reported
"Unicorn m68k ceiling here 2.90M instr/s" and concluded that live 15 fps was
out of reach for Unicorn plus Python hooks. **The ceiling figure was
mis-attributed.** It is the speed of *this workload with our hooks*, not
anything Unicorn imposes.

| measured on this machine | |
|---|---|
| hook-free m68k loop, `count=` on | **250.8M instr/s** |
| our workload, both HLEs on | 1.3-2.5M instr/s |

Two orders of magnitude sit between those, and all of it is ours.

### `count=` on emu_start costs 1.84x

Passing `count` makes Unicorn install an internal per-instruction hook to
decrement the budget, which defeats its fast dispatch path. Over the same 40
rendered frames:

| | |
|---|---|
| `count=250_000`, chunked loop | 8.07s |
| uncounted, stop from a hook at frame completion | 4.39s |

The cost is `count` itself, not the number of emu_start calls: over the same
100 frames, `count=20k` (1308 calls), `count=500k` (53 calls) and `count=1e9`
(1 call) all land within 3% of each other. Chunking was never the price.

`emu/longrun.py:run_until` is the uncounted form. Stop only from a hook that
has already advanced PC past the current instruction -- the setPixel HLE
writes PC = return address, so it qualifies. Stopping from a plain code hook
leaves PC on the hooked address and the resume re-enters the same hook
immediately: the run then spins making no progress while appearing to
iterate, which is how an early attempt at this measured a fictitious 118x.

`emu/gui.py` now stops per completed panel frame instead of every 250k
instructions: **~8.7-9.3 fps during the intro, ~58-62% of the real 15.00 Hz,
against ~30% before.**

A hook-only stop condition also needs a wall-clock floor, or the caller hangs
the moment the firmware stops meeting it -- the end of the intro does exactly
that. **A timeout is free, unlike `count`.** Same 40 frames, identical 327,681
setPixel calls each way:

| | |
|---|---|
| `count=250_000` | 8.03s |
| uncounted | 4.45s |
| uncounted + 0.5s timeout | 4.43s |

`count` installs a per-instruction hook; a timeout only arms a timer thread.
Bound wall-clock time freely; bound instruction counts only when something
genuinely has to happen per fixed number of instructions.

### Where the remaining time goes

cProfile over 10M instructions, both HLEs on:

| | share |
|---|---|
| `emu_start` -- Unicorn actually executing m68k | 34% |
| Unicorn's Python ctypes binding | ~54% |
| our own handler logic | ~12% |

1.02M of 10M instructions cross into Python. Per crossing we pay a ctypes
`create_string_buffer` allocation for every `mem_read` (1.94M of them) and a
separate FFI call for every `reg_write` (1.85M). The dominant cost is the FFI
boundary, not our logic and not the chip model -- so the next wins are fewer
crossings and cheaper crossings, not a better peripheral model. Real time is
no longer ruled out.

### A measurement mistake worth recording

An earlier attempt to split "hook dispatch" from "handler work" gave dispatch
4% and handler bodies 93%, which looked like large headroom in our Python.
**That reading was wrong.** With no-op handlers the firmware still executes all
the soft-float code, so the two runs cover completely different amounts of
firmware work per instruction -- the comparison was not apples to apples.

Acting on it produced only 8% (4.10 -> 4.43 fps): precompiled `struct.Struct`
codecs and unpacking arguments directly as `>f` instead of bits-then-convert
(the old `b2f`/`f2b` each cost a pack *and* an unpack). Those are worth
keeping. The third change in that batch -- caching Bitmap geometry per pointer
-- was **a bug**, not a win, and has been reverted: the firmware mutates the
fields of an existing Bitmap. See the note in `emu/hle.py`.

The lesson matches the earlier `install_mmio` one, and the fictitious 118x
above, and the "2.90M ceiling" this section replaces: only trust an A/B where
the two sides do the same work.
