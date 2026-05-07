# SFC — Self-Describing Resilient Container

A C++ library and CLI implementing the **SFC format**: a binary container designed for
reliable storage and transport under adverse conditions — partial data loss, corruption,
or out-of-order delivery.

Try the [WASM demo online](https://tnxbutno.github.io/sfc).
A desktop GUI is available in the [sfc-gui](https://github.com/tnxbutno/sfc-gui).

## Why SFC exists

Some data needs to survive the worst possible conditions: satellite uplinks that drop
mid-transfer, USB sticks hand-carried across conflict zones, radio transmissions with no
guarantee of delivery order or completeness.

ZIP, tar, and HDF5 all pack data into a single monolithic stream with no checksums at
the chunk level. A corrupted byte in a zip central directory makes the whole archive
unreadable. Lose any part of a tar stream and you lose everything after it. None of them
can reconstruct missing pieces or handle delivery out of order. They assume the channel
delivers every byte, intact, in sequence — SFC does not.

I built this because I wanted to make something genuinely useful: for researchers in remote
field stations, humanitarian operations with intermittent connectivity, or anyone moving
large amounts of data through unreliable paths. Turns out designing for adversarial delivery
conditions is also just interesting engineering.

## Key Features

| Feature | Detail |
|---------|--------|
| Erasure coding | GF(2¹⁶) RS via systematic Cauchy matrix; configurable N data chunks + M recovery chunks |
| Integrity | BLAKE3 per-chunk + per-file |
| Compression | zstd · brotli · LZ4 · none (passthrough) |
| Split transport | Distribute one file across independent carriers; reorder-tolerant, missing-carrier-tolerant |
| Multi-file directory | Bundle multiple named files with per-file BLAKE3 and UTF-8 paths |
| Error model | `std::expected` throughout; no exceptions; typed error codes |

## Out of scope

Two profiles defined in the spec are not implemented:

- **HTTP delivery hints** — the spec allows storing per-chunk byte offsets in the file so HTTP clients can fetch individual chunks via Range requests without scanning. Implementing this requires HTTP server integration, which is outside the scope of a file-format library.
- **Format preprocessing** — the spec allows encoders to convert content before packing (e.g. JPEG → JPEG XL, MP4 with index at end → fragmented MP4) and record the original format in metadata. Implementing this requires bundling external format converters.

Both profiles are optional in the spec. The flag bits and TLV tags for both are defined and validated by the decoder.

## Prerequisites

| Tool | Minimum |
|------|---------|
| Clang or GCC | Clang ≥ 16 / GCC ≥ 13 |
| CMake | 3.25 |
| pkg-config | any — `brew install pkg-config` / `apt install pkg-config` |
| zstd | any — `brew install zstd` / `apt install libzstd-dev` |
| brotli | any — `brew install brotli` / `apt install libbrotli-dev` |
| LZ4 | any — `brew install lz4` / `apt install liblz4-dev` |

BLAKE3 and GoogleTest are fetched automatically by CMake.

## WASM Web Demo

Try it [online](https://tnxbutno.github.io/sfc) — pack, unpack, info and verify SFC files directly in the browser, no installation required. The entire SFC library is compiled to WebAssembly via Emscripten; no data leaves your device.

To build and test the WASM module locally:

```bash
# Requires Emscripten (https://emscripten.org/docs/getting_started/downloads.html)
emcmake cmake -S wasm -B wasm/build -DCMAKE_BUILD_TYPE=Release
cmake --build wasm/build          # output: web/sfc_wasm.js
node wasm/test_wasm.js            # Node.js encode/decode/info/verify test suite
open web/index.html               # browser UI (no server needed — WASM is inlined)
```

All dependencies (zstd, brotli, lz4, blake3) are fetched and compiled automatically; no system packages required. 

## Installation

```bash
git clone https://github.com/tnxbutno/sfc && cd sfc
cmake -S . -B build
cmake --build build
```

Produces `build/sfc` (CLI) and `build/libsfc_lib.a` (static library).

## CLI Usage

```bash
# Pack
sfc pack photo.jpg                         # zstd compression, no erasure coding
sfc pack photo.jpg -m 2                    # 2 recovery chunks (survives losing any 2)
sfc pack archive.tar -n 4 -m 2 -o out     # split across 4 independent carrier files
sfc pack ./mission-data/ -o mission.sfc   # directory

# Unpack
sfc unpack photo.jpg.sfc
sfc unpack seg.000.sfc seg.002.sfc -o out/  # segments in any order, some missing is fine

# Info / verify / repair
sfc info payload.sfc
sfc verify payload.sfc
sfc repair corrupt.sfc seg.001.sfc -o repaired.sfc
```

### Full option reference

```
sfc pack <input> [options]
  -o, --output       Output path (default: <input>.sfc; for -n>1: base name for segments)
  -n, --segments     Split into N independent carrier files (default: 1)
  -m, --recovery     Recovery chunks M (default: 0)
  -s, --chunk-size   Chunk size in bytes, must be even (default: 65536)
      --algo         zstd | brotli | lz4 | none (default: zstd)
      --timestamp    Unix epoch timestamp (default: now)
      --filename     Inner filename stored in container
      --format-id    Inner Format ID hex (e.g. 0x0010)
      --author       Author name (metadata)
      --description  Description (metadata)
      --location     Location: place name or geo string (metadata)
      --software     Creating software name (metadata)
      --comment      Free-form comment (metadata)

sfc unpack <input>... [-o output]   # output: file path or directory (default: stdout / cwd)
sfc verify <input>...
sfc info   <input>...
sfc repair <input>... [-o output]   # output: file path or directory (default: cwd)
```

## Library Usage

All types live in the `sfc` namespace. Every fallible function returns `sfc::Result<T>`
(`std::expected<T, sfc::SfcError>`). Check the result before using the value:

```cpp
auto result = sfc::encode(content, params);
if (!result) {
    std::println(stderr, "encode failed: {}", result.error().detail);
    return;
}
```

### Single-file encode and decode

```cpp
#include "sfc/encoder.h"
#include "sfc/decoder.h"

sfc::EncodeParams params{
    .m         = 2,
    .s         = 4096,
    .algo      = sfc::CompressionAlgo::Zstd,
    .uuid      = make_random_uuid(),   // see Best Practices below
    .timestamp = unix_now(),
    .format_id = 0x0001,
    .filename  = "payload.bin",
};
auto enc = sfc::encode(payload_bytes, params);
auto dec = sfc::decode(std::span{*enc});
// dec->content — reassembled bytes
// dec->status  — FullyVerified | ContentVerified | Partial
```

### Split transport

Split one file across N independent carrier files. Any M can be lost and the content
is still fully recoverable (requires M recovery chunks to be set in params):

```cpp
#include "sfc/split_encoder.h"
#include "sfc/split_decoder.h"

auto segs   = sfc::encode_split(payload, params, /*num_segments=*/4);
auto result = sfc::decode_split(std::span{*segs});  // any order; tolerates up to M missing segments
```

Use `decode_multi` when you have a mix of regular files and split-transport segments —
it groups them by UUID automatically:

```cpp
auto entries = sfc::decode_multi(std::span{files});
```

### Multi-file directory

Bundle multiple named files into one container with per-file integrity:

```cpp
#include "sfc/directory.h"

std::vector<sfc::DirectoryInputFile> inputs = {
    { .path = "docs/readme.txt", .content = readme_bytes, .format_id = 0x0010 },
    { .path = "data/sample.bin", .content = data_bytes,   .format_id = 0x0001 },
};
auto enc = sfc::encode_directory(std::move(inputs), params);
auto dec = sfc::decode(std::span{*enc});
auto dir = sfc::extract_directory_full(std::span{dec->content});
for (const auto& file : dir->files) { /* file.path, file.content, file.format_id */ }
```

To split a directory across multiple carrier files, use `encode_directory_split`.

Path constraints: UTF-8, forward-slash separators, no leading/trailing `/`, no `..` or `.` components, no case collisions.

### Error handling

```cpp
auto r = sfc::decode(bad_bytes);
if (!r) {
    // r.error().code ranges:
    // 1xxx → file-level (halt)        2xxx → chunk-level (discard, continue)
    // 3xxx → content-level            4xxx → warnings (non-fatal)
    // 9xxx → invalid argument
}
```

## API Reference

```cpp
Result<vector<uint8_t>>          encode(span<const uint8_t>, const EncodeParams&);
Result<ReassemblyResult>         decode(span<const uint8_t>);

Result<vector<vector<uint8_t>>>  encode_split(span<const uint8_t>, const EncodeParams&, uint32_t num_segments);
Result<ReassemblyResult>         decode_split(span<const vector<uint8_t>> segments);
Result<vector<MultiDecodeEntry>> decode_multi(span<const vector<uint8_t>> files);

Result<vector<uint8_t>>            encode_directory(vector<DirectoryInputFile>, EncodeParams);
Result<vector<vector<uint8_t>>>    encode_directory_split(vector<DirectoryInputFile>, EncodeParams, uint32_t num_segments);
Result<DirectoryExtractResult>     extract_directory_full(span<const uint8_t> inner_content);
Result<DirectoryExtractResult>     extract_directory_partial(const vector<ParsedChunk>&, const GlobalHeader&);
```

## Fuzzing

```bash
make fuzz   # builds and runs 50k iterations per target
```

Two targets: `fuzz_decode` (full decode pipeline) and `fuzz_global_header` (header/chunk/manifest parsers independently).

## Testing

```bash
make test        # standard suite
make test-asan   # AddressSanitizer + UndefinedBehaviorSanitizer
make test-tsan   # ThreadSanitizer
```

## Static Build

Pass `-DSFC_STATIC=ON` to embed the compression libs into the binary with no Homebrew/apt runtime required on the target machine.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSFC_STATIC=ON
cmake --build build --target sfc_cli
```

**macOS** — result depends only on macOS system libraries. Verify with `otool -L build/sfc`.

**Linux** — links C++ runtime statically; binary still requires glibc. For fully static (no glibc), build on Alpine Linux and add `-DCMAKE_EXE_LINKER_FLAGS="-static"`. Verify with `ldd build/sfc`.

**Windows** — use vcpkg with the `x64-windows-static` triplet; see `.github/workflows/build.yml` for the exact cmake invocation.

## Best Practices

**UUID** — The library requires you to supply a random UUID per file. The CLI generates
one automatically, but when using the library you own this: the same UUID must be shared
across all segments of a split-transport file (it is the key used to group them on decode).
Supply a fresh random value for every new file:

```cpp
#include <random>

sfc::FileUuid make_random_uuid() {
    sfc::FileUuid uuid;
    std::random_device rd;
    std::generate(uuid.bytes.begin(), uuid.bytes.end(),
                  [&]{ return static_cast<uint8_t>(rd()); });
    return uuid;
}
```

**Choosing N, M, S**
- S must be even; 4096–65536 is a reasonable range.
- M = maximum chunk losses expected in transit. M = 0 disables erasure coding.
- N + M must not exceed 65535 (GF(2¹⁶) field limit).
