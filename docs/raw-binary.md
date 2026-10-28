# Headerless raw-binary analysis with Ghidra

Headerless images are covered here. GameCube/Wii DOL images have a header and
use their own format selection; see [GameCube DOL analysis](ghidra-dol.md).

REA admits a headerless executable when the caller supplies the CPU family and
the address where file offset 0 should be mapped, optionally with a separate
entry address inside the image. That interpretation is not inferred from a
`.bin` suffix or from unrecognized bytes.

## Open and inspect

```bash
rea inspect /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea function /absolute/path/to/ecu.bin 0x8000000 --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
```

```json
{
  "name": "open_binary",
  "arguments": {
    "path": "/absolute/path/to/ecu.bin",
    "format": "raw-binary",
    "architecture": "arm",
    "entry_point": "0x8000000",
    "provider_id": "ghidra"
  }
}
```

`architecture` is one of `x86`, `x86_64`, `arm`, `arm64`, `6502`, `m68k`, `rx`,
`armv8m`, `xtensa`, or `xtensa-hifi4`.
`entry_point` is a hexadecimal address of the form `0x…`. Without
`base_address`, the complete file is mapped starting at that address, and
Ghidra seeds an `entry` function there before auto-analysis.
ARM and AArch64 entries must be 4-byte aligned; m68k and armv8m entries must be
2-byte aligned; x86, 6502, rx, xtensa and xtensa-hifi4 entries may be
byte-aligned.
For 6502, the entry and complete mapped file must fit within `0x0000..0xffff`;
images that cross the 16-bit boundary are rejected before provider startup.
For m68k, rx, armv8m, xtensa and xtensa-hifi4, the mapping must fit within
`0x0..0xffffffff`.
`open_binary` and an open `binary_session` return the canonical `entry_point`
for raw targets so callers can verify the selected mapping directly.

### Separate base address

Firmware images often begin with data or a vector table, so the entry is not
at file offset 0. Pass `base_address` (CLI `--base-address`) to map file offset
0 there and seed `entry` at `entry_point` instead:

```bash
rea inspect-native-load-image /absolute/path/to/rom.bin --target-format raw-binary --architecture arm --base-address 0x8000000 --entry-point 0x8000100 --provider ghidra --json
```

`entry_point` must lie inside `[base_address, base_address + file size)`, and
the family's entry alignment also applies to `base_address`. The 16-bit and
32-bit fit checks run from `base_address`. A different base is a different
analysis profile; `open_binary` and `binary_session` then also return the
canonical `base_address`, and load-image verification checks the mapping start
against the base and the entry's file offset separately. Omitting
`base_address`, or passing the same value as `entry_point`, keeps the existing
profile, snapshot identity, and Evidence unchanged, and results do not echo a
`base_address`. REA does not read the entry from a vector table; select it
explicitly.
Omitted `format` keeps header-based detection; architecture, entry, and base
without `format=raw-binary` are rejected.

Ghidra imports a private snapshot with `BinaryLoader` and these languages and
compiler specifications. All but `rx` and `xtensa-hifi4` ship with Ghidra. Each family has one
fixed byte order: m68k is big-endian and the others are little-endian.

| architecture | language_id               | compiler_spec_id |
| ------------ | ------------------------- | ---------------- |
| x86          | `x86:LE:32:default`       | `gcc`            |
| x86_64       | `x86:LE:64:default`       | `gcc`            |
| arm          | `ARM:LE:32:v7`            | `default`        |
| arm64        | `AARCH64:LE:64:v8A`       | `default`        |
| 6502         | `6502:LE:16:default`      | `default`        |
| m68k         | `68000:BE:32:default`     | `default`        |
| rx           | `rx62t:LE:32:default`     | `default`        |
| armv8m       | `ARM:LE:32:v8-m`          | `default`        |
| xtensa       | `Xtensa:LE:32:default`    | `default`        |
| xtensa-hifi4 | `Xtensa:LE:32:rt600hifi4` | `default`        |

Compiler specifications select analysis conventions; they do not identify the
original compiler or ABI of a headerless target. Ghidra's x86 languages do not
provide a compiler specification named `default`.

Those settings, the caller-supplied entry and any separate base, and
`language_selection: caller-supplied-v1` are committed in the analysis profile.
A different entry, base, or architecture is a different profile; snapshots from header-detected targets
do not replay.

The mapped start is independent of Ghidra's program image base, which remains
`0x0` for BinaryLoader. Ghidra may report additional language-defined entry
points, including unmapped ARM vectors. Load-image verification requires the
caller-supplied entry and preserves those other entries as observations.
For 6502, BinaryLoader maps the file before adding its language-defined zero-page
and stack blocks. Conflicting default blocks are skipped; low-address files stay
in the default address space rather than an overlay. Non-conflicting uninitialized
blocks remain observations, not file-backed bytes.
Independent raw verification streams the complete private snapshot digest and
extent with bounded memory and supports cancellation during the read.
It also requires the source-backed block to be initialized, loaded, and
non-overlay in the bound language's default address space. Contradictory mapping
observations are retained with `mismatch`, even when the source hashes agree.

Hopper and IDA refuse raw-binary targets, and there is no rizin analysis
provider, so `open_binary` with `format: "raw-binary"` is served by Ghidra only
(`provider_id: "rizin"` is refused as an unknown provider). For a second
decoder, run one-shot rizin commands on the same file with the matching
decoder and load address, for example
`rea execute-rizin-command ./display.bin 'aaa; afl' --arch arm --bits 32 --base-address 0x20100000`
(`--arch rx`, `xtensa` and others name rizin plugins, not REA families); see
[reverse-engineering tools](reverse-engineering-tools.md). Windows Ghidra P0 admits native PE
applications/DLLs and explicitly selected raw 6502 images. Other raw CPU families
remain outside the Windows boundary. Native path admission, private DACLs, Job
Object ownership, immutable snapshots, and the no-mutation policy still apply.

## NMOS 6502

```bash
rea function /absolute/path/to/image.bin 0x8001 --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/image.bin --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
```

Select only headerless NMOS 6502 code with a known entry at file offset 0.
The built-in Ghidra processor supplies static instructions, functions,
pseudocode, and references. Evidence preserves `architecture: "6502"`, the
selected language, entry, file digest, and verified source mapping. Register and
calling conventions are analysis conventions, not a recovered source ABI.

This lane does not interpret iNES headers, cartridge mappers, bank switching,
or other console-specific memory layouts. 65C02 and 65816 programs need different
processor semantics and are not admitted as those variants. REA does not infer
the CPU from the file suffix, guess the reset vector, or emulate the target.

`npm run verify:ghidra:6502` assembles and links the source-owned fixture with
`ca65` and `ld65` (tested from cc65 tag `V2.19`, whose tools report `V2.18`).
Set `REA_CA65` and `REA_LD65` to explicit executable paths if needed. The lane
checks real CLI/MCP load-image parity, mapped bytes, decoded calls, decompilation,
invalid mappings, unchanged source bytes and runtime cleanup.
Low-memory checks include a file spanning the zero-page/stack boundary at `0xff`
and a complete 64-KiB image at `0x0`, with verified default-space mappings through
both CLI and MCP. On Windows, the lane also checks that a caller-selected
junction path is rejected at snapshot admission through CLI and MCP, with
unchanged source bytes and complete runtime cleanup. Windows requires the
matching native addon; the POSIX provider path has not been exercised by the
Windows run.

## Motorola 68000

```bash
rea function /absolute/path/to/image.bin 0x1000 --target-format raw-binary --architecture m68k --entry-point 0x1000 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/image.bin --target-format raw-binary --architecture m68k --entry-point 0x1000 --provider ghidra --json
```

Select only headerless big-endian 68000-family code with a known, even entry at
file offset 0. Ghidra's `68000:BE:32:default` language decodes the 68040
superset in the 32-bit `ram` address space. Instructions that a real MC68000
would not execute are therefore not rejected, and 68020, 68030, CPU32, and
ColdFire programs are not admitted as those variants. Addresses are not masked
to the MC68000 24-bit bus. Evidence preserves `architecture: "m68k"`, the
selected language, entry, file digest, and verified source mapping. Register and
calling conventions are analysis conventions, not a recovered source ABI.

This lane does not interpret Amiga hunks, Atari ST, or other container headers,
cartridge or console memory maps, or bank switching. REA does not read the
initial stack pointer and reset vector from the first eight bytes; select the
entry explicitly. Windows Ghidra P0 does not admit m68k.

`npm run verify:ghidra:m68k` uses a source-owned 22-byte fixture written as
annotated hex in the verifier, so it needs no assembler. The lane checks real
CLI/MCP load-image parity, mapped bytes, a decoded call, decompilation by address
and file offset, misaligned and out-of-range mappings, unchanged source bytes and
runtime cleanup. It has been run with Ghidra 12.1.4 on macOS; Linux has not been
exercised.

## Renesas RX

```bash
rea function /absolute/path/to/rom.bin 0xfff8fbdb --target-format raw-binary --architecture rx --base-address 0xfff80000 --entry-point 0xfff8fbdb --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/rom.bin --target-format raw-binary --architecture rx --base-address 0xfff80000 --entry-point 0xfff8fbdb --provider ghidra --json
```

Select only headerless little-endian Renesas RX code (RXv1 and RXv2) with a
known entry. RX ROM images usually start with constant data and end with the
fixed vector table, so pass the ROM start as `base_address` and the reset
handler as `entry_point`. Instructions are 1 to 8 bytes and byte-aligned, so
any entry inside the image is admitted.

Ghidra does not ship an RX language. This lane binds `rx62t:LE:32:default`
with compiler specification `default` in the `ram` address space, from the
community RX SLEIGH module
([stefan00lpf/rx-proc-ghidra](https://github.com/stefan00lpf/rx-proc-ghidra)).
Install its `data/languages` files into the selected Ghidra installation's
catalog, under `Ghidra/Processors/<module>/data/languages/` or
`Ghidra/Extensions/<module>/data/languages/`, and compile `rx62t.slaspec` with
that installation's `support/sleigh`. REA does not install, build, or update
the module. When the language or its `default` compiler specification is
absent from the catalog, REA refuses the target with `capability_unavailable`
before starting Ghidra and names the installation and catalog roots it checked.

The analysis profile records `language_catalog: installed-community-module-v1`.
Evidence and load-image attestations carry a limitation stating that the
language is not shipped with Ghidra and that REA has not established its
instruction decoding, p-code, or decompilation fidelity. The profile does not
fingerprint the module's files: reinstalling a different module version under
the same Ghidra does not invalidate cached analysis, so close and reopen the
target after changing the module. Evidence preserves `architecture: "rx"`, the
selected language, base, entry, file digest, and verified source mapping.

This lane does not model RXv3 instructions, on-chip RAM, peripheral I/O
registers, data flash, the C runtime's `.data` copy-down, or the relocatable
interrupt vector table, and REA does not read the reset vector. References to
RAM and I/O addresses therefore appear unmapped. Seed further functions with
`REA_GHIDRA_SEED_FILE`. Windows Ghidra P0 does not admit rx.

`npm run verify:ghidra:rx` uses a source-owned 56-byte fixture written as
annotated hex in the verifier, with data at `base_address` and the entry inside
the image. See [testing](testing.md) for its checks. It has been run with Ghidra
12.1.4 on Linux x64; macOS has not been exercised.

## ARMv8-M (Cortex-M, Thumb)

```bash
rea inspect /absolute/path/to/flash.bin --target-format raw-binary --architecture armv8m --base-address 0x8000000 --entry-point 0x80011a8 --provider ghidra --json
```

`armv8m` binds Ghidra's `ARM:LE:32:v8-m` language, whose `ARMCortex.pspec`
starts disassembly in Thumb mode (`TMode=1`); it decodes ARMv8-M Mainline and
Baseline and, in practice, ARMv7-M/ARMv6-M Thumb code. The `arm` family stays
`ARM:LE:32:v7` (ARM state at the entry, 4-byte aligned) for A- and R-profile
images. A Cortex-M vector table stores handler addresses with bit 0 set; clear
it for `entry_point` (2-byte alignment is enforced, so `0x80011a9` is refused).
REA does not read the vector table, copy `.data`/RAM code, or map SRAM, the
system region or peripherals; code copied to RAM by the reset handler needs its
own raw open at its run address.

## Xtensa and the RT600 HiFi4 DSP

```bash
rea inspect /absolute/path/to/dsp_text.bin --target-format raw-binary --architecture xtensa --base-address 0x200000 --entry-point 0x21c360 --provider ghidra --json
rea inspect /absolute/path/to/dsp_text.bin --target-format raw-binary --architecture xtensa-hifi4 --base-address 0x200000 --entry-point 0x21c360 --provider ghidra --json
```

`xtensa` binds Ghidra's stock little-endian `Xtensa:LE:32:default`, which
decodes the base and common optional instructions but not FLIX bundles or
HiFi operations: code built for a HiFi DSP decompiles to `flix()` and
`halt_baddata()` at the first bundle. `xtensa-hifi4` binds
`Xtensa:LE:32:rt600hifi4`, a language generated for the NXP RT600 HiFi4 DSP
configuration (base ISA, FLIX formats, HiFi4/FPU operations) from Cadence's
MIT-licensed `xtensa-modules.c` by `tools/xtensa_sleigh_gen.py` in
github.com/Reid-n0rc/FT-710_Firmware. It is not shipped with Ghidra: install
its `xtensa_rt600hifi4.*` files into `Ghidra/Processors/Xtensa/data/languages/`
and compile the slaspec with that installation's `support/sleigh`. Like `rx`,
it is admitted only when the installation catalog defines it with a `default`
compiler specification, refused with `capability_unavailable`
(`GHIDRA_LANGUAGE_UNAVAILABLE`) otherwise, and recorded with
`language_catalog: installed-community-module-v1` and an unverified-language
limitation. Other Xtensa configurations (other HiFi versions, ESP32, LX7
cores with different TIE) and big-endian Xtensa are unsupported. Xtensa
instructions are 2 or 3 bytes and FLIX bundles 4 to 16, so entries may be
byte-aligned. Windowed-ABI calls, L32R literal pools and the vector base are
decoded as the language defines them; REA maps one file, so TCM and SRAM
images of one DSP need separate opens.

`npm run verify:ghidra:firmware` checks `armv8m`, `xtensa` and `xtensa-hifi4`
with source-owned fixtures (a hand-encoded Thumb-2 image, and an Xtensa call0
image assembled once with the Zephyr SDK and embedded as annotated hex);
`-- xtensa` and the other lane names select lanes. A lane whose language is not
installed prints `skipped:`. Checked with Ghidra 12.1.4 on Linux x64.

## Read-only ranges

```bash
REA_GHIDRA_RAW_READONLY_RANGES=0x200000-0x206fff \
  rea decompile /absolute/path/to/dsp_text.bin 0x22c5b0 --target-format raw-binary --architecture xtensa-hifi4 --base-address 0x200000 --entry-point 0x21c360 --provider ghidra --json
```

BinaryLoader maps the whole file as one writable block, so Ghidra's
decompiler does not fold values read from it: literal pools, `.rodata`
constants and switch tables stay `DAT_` loads, and jump tables whose bounds or
targets come from there may not be recovered. `REA_GHIDRA_RAW_READONLY_RANGES`
lists comma-separated, inclusive `0xstart-0xend` load-address ranges that the
raw pre-script splits from the file block and marks non-writable before
auto-analysis. Ranges are sorted, must not overlap (at most 64), and must lie
inside the mapped image, or profile resolution fails with a
`ConfigurationError` naming the setting. The canonical ranges are committed as
`readonly_ranges` in the analysis profile (a profile without them is unchanged),
and a session whose committed ranges differ from the setting refuses to open.
The setting is process-wide and applies only to raw-binary imports; set it per
CLI invocation, or restart the MCP server to change it.

`inspect_native_load_image` then attests the contiguous pieces the ranges
select instead of one mapping: each piece's addresses, file offset, length and
digest, and `writable: false` for each read-only piece, with a limitation
naming the ranges. Read-only is the caller's assertion about the firmware, not
a fact recovered from the image; a range that the program writes at run time
yields wrong constants. Uninitialized RAM or peripheral blocks are not added.

`npm run verify:ghidra:firmware -- armv8m-readonly` checks this with a Thumb
fixture whose entry loads a word from a table through a literal: with the
literal and table read-only, the entry decompiles to `return 0x11223344;`,
and the same import without the setting does not fold it.

## Limitations

- Headers are not discovered from file bytes. REA does not guess load
  addresses, vector tables, or memory maps; `base_address` and `entry_point`
  are caller-supplied.
- Big-endian ARM, separate ARMv6-M/ARMv7-M languages (use `armv8m`), and other
  Ghidra processor variants are unsupported. m68k is the only big-endian family.
- Reset vectors, memory-mapped I/O, and firmware boot sequences are not
  emulated.
- Independent load-image verification covers source identity, mapped file
  bytes, the bound language, the caller-supplied base, and the entry. Original bytes
  stay unchanged.
