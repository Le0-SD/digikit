# Digitakt II live MIDI SysEx / MidiRpc protocol (1.16)

The runtime SysEx command surface of **MAIN OS 1.16**: how the device is spoken
to over its USB (or DIN) MIDI port while it is running normally, as opposed to
the OS-upgrade *container* format (that is `docs/FINDINGS.md` "Container", and
`dt2/container.py`). Discovered 2026-09-20.

Scope note: `docs/FINDINGS.md` is 1.15C-scoped. **Everything here is
Digitakt II 1.16**, MAIN OS `out/sections/dt2-1.16/section_3_MAIN_OS.bin`,
sha-256 `57bb4dfa8df07d846adc72fdb4fb0d3cd3c5680c524bf498338460207e008e7d`
(matches the `out/ghidra/dt2-1.16-seeded` Ghidra program). The physical device
was upgraded to 1.16 on 2026-09-20, so it and the analysis target are the same
version.

Evidence classes follow `docs/FINDINGS.md`: **[V]** verified by running it here ·
**[D]** documented by reading the image once, not re-checked · **[O]** open.

> **Two distinct protocols.** Device-id `0x14` (§2–§9) is the OS-**upgrade**
> container path: 8-in-7 packed body, `type | 0x80` responses, a trailing
> checksum+length. Device-id **`0x10` (§11)** is the **live** path Elektron
> Transfer actually uses: raw body, no packing, no checksum, no length, no
> response bit. They share the `MidiRpcMessage` class and type enum but nothing
> else. A live round-trip against real hardware is confirmed for the `0x10`
> path (§11).

> **Verification status.** The `0x10` protocol in §11 is confirmed by a live
> hardware round-trip **[V]** plus a firmware trace. The `0x14`/upgrade static
> decode in §2–§9 is single-agent, read once — **[D]** — and has *not* had the
> project's required second-agent byte-check. Do not promote §2–§9 to **[V]**
> without that check. Addresses are for follow-up.

## Why this matters

- **Delivery is the device's own mechanism.** `OsUpgradeStart / OsUpgradeWrite /
  OsUpgradeEnd` (RPC types `0x50 / 0x51 / 0x52`) are ordinary MidiRpc commands
  over this same MIDI port. Flashing a patched OS is driving the official
  update RPC, not a third-party tool. See §7.
- **A live oracle exists.** `Ping`, `SoftwareVersion`, `DeviceUID`,
  `StorageSpace`, `Query` are read-only round-trips. Once we speak the framing
  we can interrogate the real device, which demotes emulator fidelity (gate A2)
  from a blocker to a convenience.
- **No raw peek/poke.** There is no arbitrary-memory read/write command. Live
  data access is filesystem-shaped (`FsSample*`, `Data*`), not RAM-shaped.
- **`DigisharcSysexRpc`** is the RPC container class name (§3). "Digisharc" =
  SHARC — a possible SysEx path toward the DSP, relevant to the machine work.
  Lead only, not chased. **[O]**

## 1. Live device round-trip **[V]**

Over USB MIDI (`Elektron Digitakt II` in/out ports, `python-rtmidi`), with no
device settings changed:

```
sent: F0 7E 7F 06 01 F7          (MIDI Universal Non-Realtime device inquiry)
got:  F0 7E 00 7C 00 F7
```

Sub-ID `0x7C` = **WAIT**. The device routes any `F0 7E …` message
unconditionally into its Sample Dump Standard state machine (§8), whose sub-ID
switch does not handle `0x06` (inquiry) and parks in WAIT. So SysEx over USB
works out of the box; no MIDI menu setting is required to receive.

## 2. Outer framing and the command jump table **[D]**

Raw MIDI byte router: `FUN_4011e9f0`, dispatches on the status-byte low nibble.

Elektron envelope match: the literal `f0 00 20 3c` lives at `0x4021e11a`. A
device-ID table at `0x402b4098` (24 slots; populated `0x00,0x04,0x0a,0x10,0x14,
0x17`) selects a per-device descriptor. Device `0x14` (Digitakt II MAIN OS) →
descriptor at `0x4021e0f0`: separator byte must be `0x00`, command range
`[0x00,0x7F]`, and a **128-entry command jump table at `0x402b4748`** (recovered
by reading the raw pointer array; Ghidra would not resolve it statically —
"too many branches" at `0x4011fda2`).

For device `0x14` the 128 entries collapse to six handlers:

| command range | handler | role |
|---|---|---|
| `0x00-0x0F,0x11-0x4F,0x70-0x77,0x79-0x7D` | `0x4011e9ca` → `FUN_400e27ec` | generic → the **MidiRpc / DigisharcSysexRpc** container (§3) |
| `0x10` | `0x4011e9cc` | singleton, unexamined |
| `0x50-0x5F` | `0x4011eb94` → `FUN_4012208e` | legacy kit/sound/pattern/song/project backup **GET** (object-indexed, `idx < 0x80`, not address-based) |
| `0x60-0x6F` | `0x4011ebba` | symmetric write counterpart, unexamined |
| `0x78` | `0x4011e9ce` | singleton, unexamined |
| `0x7E-0x7F` | `0x4011f1fc` | unexamined |

`FUN_400e27ec` itself contains a further unresolved indirect jump table at
`0x400e2830` (per-object-type dump dispatch), not decoded. **[O]**

## 3. Transport packing, checksum, framing **[D]**

The generic path builds a message as
`header · packed-body · checksum · length · F7`:

```
F0 00 20 3C 14 00 <cmd> <b5> <b6> <b7>   <-- header, FUN_400e25da
<8-in-7 packed body ...>                 <-- FUN_400e26d0
<cksum_hi> <cksum_lo>                     <-- 14-bit additive sum, FUN_400e2750/2716
<len_hi>   <len_lo>                       <-- (bodyLen + 5), 2×7-bit
F7
```

- **8-in-7 packing** (`FUN_40152242`, size `= (rawLen*8 + 6)/7`; unpack
  `FUN_40152428` / `0x401524a2`, dispatch `0x4015253e`) — the same routine the
  OS-upgrade container uses. The whole body (the 5-byte MidiRpc header plus its
  payload) is packed as one contiguous run, MSB-collector byte then 7 data
  bytes. It is **not** sent raw.
- **Checksum** (`FUN_400e2716`): `sum(packed_body[i] & 0x7f) & 0x3fff`, emitted
  MSB-first as two 7-bit bytes.
- The four header bytes after `14 00` — `<cmd> <b5> <b6> <b7>` (each masked
  `&0x7f`) — are the **one unverified gap**. `b5` is very likely the OS-stream
  id (`0x0f` for DT2 on 1.15C). A `0x20` type tag appears when
  `DigisharcSysexRpc` objects are built (`0x400e3150`), a plausible `cmd`.
  Circumstantial guess `cmd=0x20, b5=0x0f, b6=0x00, b7=0x00` — **[O], do not
  trust for hardware without confirming.**

## 4. MidiRpc message layer **[D]**

Base header `elektron::MidiRpcMessage::ctor_dtor` (`0x4013d864`), 5 raw bytes
(pre-packing), big-endian:

```
seq_hi seq_lo   len_hi len_lo   type
```

Master type-byte factory switch at `0x4013aaf4` (called from `0x401243c6`)
builds ~90 concrete request/response classes. **Rule: `type = family | 0x80`
for a response** (verified across families: Ping req `0x01`/resp `0x81`, Query
`0x09`/`0x89`, OsUpgradeWrite `0x51`/`0xD1`).

Request command table (`0x01`–`0x5F`):

| type | name | | type | name |
|---|---|---|---|---|
| 0x01 | Ping | | 0x30 | FsSampleOpenFileForRead |
| 0x02 | SoftwareVersion | | 0x31 | FsSampleCloseFileReader |
| 0x03 | DeviceUID | | 0x32 | FsSampleReadFileV1 |
| 0x04 | Screenshot | | 0x33 | FsRawOpenFileForRead ✝ |
| 0x05 | StorageSpace | | 0x35 | FsRawReadFileV1 ✝ |
| 0x06 | TempoRead | | 0x36 | FsSampleReadFileV2 |
| 0x07 | TempoWrite | | 0x40 | FsSampleOpenFileForWrite |
| 0x09 | Query | | 0x42 | FsSampleWriteFileV1 |
| 0x10 | FsSampleReadDir | | 0x45 | FsRawWriteFileV1 ✝ |
| 0x13 | EnumerateFiles | | 0x46 | FsSampleWriteFileV2 |
| 0x17 | FsSampleListRam | | 0x50 | OsUpgradeStart |
| 0x19 | FsSampleAssign | | 0x51 | OsUpgradeWrite |
| 0x20 | FsSampleDeleteFile | | 0x52 | OsUpgradeEnd |
| 0x21 | FsSampleRenameFile | | 0x53-0x5f | Data* object API |

(Abbreviated; `0x11-0x38` also carry the `FsSample*`/`FsRaw*` create/delete/
rename/get-info/hash variants. ✝ = `FsRaw*`, see §6.)

## 5. Read-only commands (safe live probes) **[D]**

- **Ping (`0x01`)** — request is header-only, `len = 0`, no payload
  (`MidiRpcPingRequest` adds nothing to the base). Response `0x81`
  (`0x401ddb9e`): `u8 blobLen · blob[blobLen] · NUL-terminated string`.
- **SoftwareVersion (`0x02`)** — response `0x401e06ac`: two NUL-terminated
  strings (version, build).
- **DeviceUID (`0x03`)** — response `0x401dce08`: one big-endian `u32`.
- **StorageSpace (`0x05`)**, **Query (`0x09`)** — read-only, layouts not
  decoded.

Worked Ping request (raw pre-pack body, `seq=0x0001`): `00 01 00 00 01`.
Packed (all bytes `<0x80`, so collector `0x00`): `00 00 01 00 00 01` (6 bytes).
Checksum `0+0+1+0+0+1 = 2` → `00 02`. Length `6+5 = 11` → `00 0B`. Full frame,
with the unverified header bytes bracketed:

```
F0 00 20 3C 14 00 [<cmd> <b5> <b6> <b7>] 00 00 01 00 00 01 00 02 00 0B F7
```

Responses may carry their own monotonic `seq` rather than echoing the request's
(`0x401d3ea6` builds Ping response with `seq=0`, and the header builder
auto-assigns from a global counter when given 0). Not confirmed against a real
round-trip; with one request in flight, ordering suffices for correlation. **[O]**

## 6. Filesystem primitive: live vs dead **[D]**

Both `FsSample*` and `FsRaw*` define an **offset+length file read/write keyed by
an arbitrary path string** — open-by-path → handle, then `{handle, offset,
length[, data]}` (big-endian `u32` fields; path via `FUN_401dd35e`, NUL-
terminated, ≤255 bytes). The write path resizes a heap buffer to the caller's
length then `memcpy`s (`FUN_401dcd40`); the read length is clamped to bytes
remaining in the SysEx buffer, so it cannot over-read the message.

Liveness, by `tools/refscan.py` over the raw image (96.78% instruction
coverage), checking each class's RTTI typeinfo for a `dynamic_cast` site:

- **`FsRaw*` (12 request classes): 0 hits — apparently dead on the 1.16 receive
  path.** The factory will parse an incoming `FsRawWriteFileV1` into a live
  object, but nothing ever `dynamic_cast`s to that type, so no I/O follows.
  Control checks (Ping, Query typeinfos each show exactly the one expected site)
  confirm the method detects live sites correctly.
- **`FsSample*` siblings: referenced (live)**, byte-identical wire shape.
- **`OsUpgradeWrite` (`0x51`): live**, the flash-write-with-offset primitive,
  gated by the `OsUpgradeStart`/`End` handshake.

Caveat: refscan is a static byte scan and can miss a computed/indirect typeinfo
load; the FsSample dispatch call site itself was not located, so whether
`FsSampleOpenFile*` confines the path to a sample root (as its name implies) is
**[O]**.

## 7. The OS-upgrade RPC = the delivery channel **[D]**

`OsUpgradeStart (0x50)` / `OsUpgradeWrite (0x51)` / `OsUpgradeEnd (0x52)` are
MidiRpc commands. `MidiRpcOsUpgradeWriteRequest` (`0x401e0e22`) has the same
`{slot, offset, length, data}` shape as the file-write primitives. This is the
same content the offline `.syx` container carries (`dt2/build.py`,
`tools/roundtrip.py`), delivered over MIDI instead of as a file. It is the
natural target for pushing a rebuilt image to hardware.

Nothing sent over **USB** can reach the irreversible bootstrap upgrade: the
bootstrap's STARTUP-menu upgrade path is **MIDI DIN only** (`README.md`,
`docs/FINDINGS.md` "Recovery"), and on 1.16 the bootstrap version gate no longer
fires for a 1.16-derived image anyway (incoming must exceed running).

## 8. Sample Dump Standard (`F0 7E`) **[D]**

Worker `FUN_40121eec` spawns a `MidiAsyncWorker` thread literally named
"Handle sysex SDS", backed by an `SdsManager`, parser `FUN_400e530a`, length
guard `FUN_400e45d0` (≥2). Sub-IDs: `0x01` DUMP HEADER, `0x02` DATA PACKET,
`0x03` DUMP REQUEST, `0x05` extension negotiation, `0x7B` EOF, `0x7C` WAIT,
`0x7D` CANCEL, `0x7E` NAK, `0x7F` ACK — standard MMA handshake, matching the §1
observation. Field readers `FUN_401c8828` (14-bit) / `FUN_401c886c` (21-bit) do
no 7-bit masking and no cursor-vs-length check at that layer; whether
`SdsManager` clamps `sampleLength`/`sampleNumber` upstream is **[O]**.

## 9. Debug console — UART8, not MIDI **[D]**

Not a MIDI surface, recorded here to close it off. Dispatch `strcmp` chain
`FUN_400cae8c` (1.16; was `0x400cd93e` on 1.15C) over UART8 (`0xEC070004`
status, `0xEC07000C` data). Commands include `#HELLO`, `#READ`, `#WRITE`,
`#DUMP_AUDIO`, `#RECEIVE_AUDIO`, `#ENTER_TEST_MODE`, `#MRAM_DUMP`,
`#READ_SERIAL`, and many `#*_TESTED` factory-test variants.

- **`#WRITE <name> <int>` is a named-parameter setter, not a memory poke.**
  `FUN_400cab40` looks the name up in a fixed 11-entry table (one entry named
  `SYNC_1`); a hit calls `entry+0xc(1)` then `entry+4(value)`; a miss prints
  "ADDRESS ERROR". `#READ` uses the same table. Neither takes an address.
- `#DUMP_AUDIO` / `#RECEIVE_AUDIO` take one integer index into a firmware-chosen
  buffer, not an address (index bounds unchecked here — possible OOB, **[O]**).
- `#ENTER_TEST_MODE` sets byte `0x4031be48`, stops audio, arms interrupt
  vector 191, writes `0xFC04C07F`. `FUN_400ceeb4` enter / `FUN_4002dc74` exit.
- No evidence the console is reachable over any transport other than UART8, and
  no repo evidence UART8 is physically exposed or bridged to USB. **[O]**

## 10. Open questions

1. The four envelope header bytes `<cmd> <b5> <b6> <b7>` (§3) — resolve by
   snooping the official Transfer/Overbridge traffic, or by a bounded read-only
   Ping probe against hardware.
2. Whether responses echo the request `seq` (§5).
3. `DigisharcSysexRpc` — is there a SysEx→SHARC path? (§2, name lead only.)
4. `FsSampleOpenFile*` path confinement (§6).
5. `FUN_400e27ec`'s inner jump table `0x400e2830`; the `0x10`, `0x60-0x6F`,
   `0x78`, `0x7E-0x7F` handlers (§2).
6. SDS length/number validation upstream in `SdsManager` (§8).

## 11. The live Transfer protocol (device 0x10) **[V]**

This is the path Elektron Transfer uses and the one we can drive from a host.
Confirmed two ways: a firmware trace of the `0x10` descriptor, and a live
round-trip against the real device on 2026-09-20 (`tools/devrpc.py`).

### Frame

```
F0 00 20 3C 10 00 <cmd> <seq_hi> <seq_lo> 09 <ctr> <type> <payload...> F7
```

- `10` device id, `00` separator — the descriptor at `0x4021e08c` requires the
  separator to be exactly `0x00` (`+0x00` devid `0x10`, `+0x01` sep `0x00`,
  `+0x04` jump-table ptr `0x402b40f8`, `+0x08/+0x0c` cmd range `0..0x7f`).
- **`cmd` is ignored by the receiver.** All 128 entries of the jump table at
  `0x402b40f8` point to the same handler `0x4011efb8`, so any `cmd` in
  `0x00..0x7f` routes identically. (Observed values: `0x04`/`0x05`, and a second
  channel `0x0c`/`0x0d` when a new connection opens.)
- `seq_hi seq_lo` (`u16` BE) then `09 ctr` (a second `u16`-shaped field, high
  byte constant `0x09` in all traffic, low byte a per-channel counter) then
  `type` — these are the 5-byte `MidiRpcMessage` header parsed by `0x4013d864`,
  aligned to frame bytes 7–11. `seq` is caller-chosen; the device assigns its
  own `seq`/`ctr` in the reply, so **match replies on devid `0x10` + `type`,
  not on any echo.**
- **No checksum, no length, no 8-in-7 packing** — verified absent in the
  receive chain (`0x4011efb8` → `0x40125184` → `0x4013d864`); the body is raw
  bytes. Binary values that would exceed `0x7f` appear 7-bit encoded (the
  `DeviceUID` `u32` comes back as 5 bytes); the general ≥`0x80` escape on this
  path is not yet decoded. **[O]**
- `type` reuses the shared enum: `0x01` Ping, `0x02` SoftwareVersion, `0x03`
  DeviceUID, `0x05` StorageSpace, `0x09` Query, `0x53` DataList. There is **no
  `0x80` response bit** on this path; request vs response is only by direction.

### Live round-trip (verified against hardware)

Sent `F0 00 20 3C 10 00 04 00 01 09 00 01 F7` (Ping). Replies observed:

- Ping → capability blob + NUL-terminated name string `"Digitakt II"`.
- SoftwareVersion → NUL-terminated strings `"00"`, `"79"`, `"1.16"`.
- DeviceUID → 5-byte (7-bit-encoded) value.
- StorageSpace, Query, DataList (dir listing with `"projects"`, `"soundbanks"`)
  all respond.

Tools: `tools/midisniff.py` (passive capture, transmits nothing) and
`tools/devrpc.py` (read-only queries: `--ping --version --uid --storage
--query`). Nothing on the USB path can reach the irreversible bootstrap
(DIN-only, §7).

### 0x10 key addresses

```
device 0x10 descriptor       0x4021e08c (sep 0x00, jump table 0x402b40f8)
jump table (all -> handler)  0x402b40f8  -> 0x4011efb8 (128× identical)
receive chain                0x4011efb8 -> 0x40125184 -> 0x401243c6
MidiRpcMessage header parse  0x4013d864 (shared with 0x14 path)
```

## Key addresses

```
router / envelope            0x4011e9f0 ; f0 00 20 3c literal 0x4021e11a
device-ID table              0x402b4098 (dev 0x14 desc 0x4021e0f0)
dev 0x14 command jump table  0x402b4748 (128 × 4 bytes)
generic → RPC container       0x4011e9ca → 0x400e27ec (inner table 0x400e2830)
frame header/body/checksum   0x400e25da / 0x400e26d0 / 0x400e2750 / 0x400e2716
8-in-7 pack / unpack         0x40152242 / 0x40152428 / 0x401524a2 / 0x4015253e
MidiRpc base header          0x4013d864 ; type factory 0x4013aaf4 ; dispatch 0x401243c6
Ping resp / build            0x401ddb9e / 0x401d3ea6
SoftwareVersion / DeviceUID  0x401e06ac / 0x401dce08
FsRaw read/write req         0x401e112a / 0x401e1286 (path reader 0x401dd35e)
FsSample read/write req      0x401e0a8c / 0x401e0be8
OsUpgradeWrite req           0x401e0e22
SDS worker / parser          0x40121eec / 0x400e530a ; field readers 0x401c8828 / 0x401c886c
debug console dispatch       0x400cae8c ; #WRITE name table 0x400cab40
```
