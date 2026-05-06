# SFC — Self-Describing Resilient Container

A C++23 library and CLI implementing the **SFC format**: a binary container designed for
reliable storage and transport under adverse conditions — partial data loss, corruption,
or out-of-order delivery.

A desktop GUI is available at [tnxbutno/sfc-gui](https://github.com/tnxbutno/sfc-gui).

## Why SFC exists

Some data needs to survive the worst possible conditions: satellite uplinks that drop
mid-transfer, USB sticks hand-carried across conflict zones, radio transmissions with no
guarantee of delivery order or completeness. Existing formats — zip, tar, HDF5 — assume
a reliable channel. SFC does not.

I built this because I wanted to make something genuinely useful: for researchers in remote
field stations, humanitarian operations with intermittent connectivity, or anyone moving
large amounts of data through unreliable paths. Turns out designing for adversarial delivery
conditions is also just interesting engineering.

## Key Features

| Feature | Detail |
|---------|--------|
| Erasure coding | GF(2¹⁶) RS via systematic Cauchy matrix; configurable N and M |
| Integrity | BLAKE3 per-chunk + per-file + per-entry (P5) |
| Compression | zstd · brotli · LZ4 · identity |
| **P2 Split Transport** | Segment one file across independent carriers; reorder-tolerant |
| **P5 Directory** | Bundle multiple named files with per-file BLAKE3 and UTF-8 paths |
| Error model | `std::expected` throughout; no exceptions; typed error codes |
| C++ standard | C++23 (`std::expected`, `std::span`, `std::format`, constexpr) |

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
sfc pack archive.tar -n 4 -m 2 -o out     # 4 independent P2 segments
sfc pack ./mission-data/ -o mission.sfc   # directory

# Unpack
sfc unpack photo.jpg.sfc
sfc unpack seg.000.sfc seg.002.sfc -o out/  # segments in any order, some missing is fine

# Inspect / verify / repair
sfc info payload.sfc
sfc verify payload.sfc
sfc repair corrupt.sfc seg.001.sfc -o repaired.sfc
```

### Full option reference

```
sfc pack <input> [options]
  -o, --output       Output path (default: <input>.sfc)
  -n, --segments     Split into N P2 segments (default: 1)
  -m, --recovery     Recovery chunks M (default: 0)
  -s, --chunk-size   Chunk size in bytes, must be even (default: 65536)
      --algo         zstd | brotli | lz4 | none (default: zstd)
      --filename     Inner filename stored in container
      --format-id    Inner Format ID hex (e.g. 0x0010)
      --author       Author name (metadata)
      --description  Description (metadata)
      --location     Location: place name or geo string (metadata)
      --software     Creating software name (metadata)
      --comment      Free-form comment (metadata)

sfc unpack <input>... [-o output]
sfc verify <input>...
sfc info   <input>...
sfc repair <input>... [-o output]
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
    .uuid      = my_random_uuid(),
    .timestamp = unix_now(),
    .format_id = 0x0001,
    .filename  = "payload.bin",
};
auto enc = sfc::encode(payload_bytes, params);
auto dec = sfc::decode(std::span{*enc});
// dec->content — reassembled bytes
// dec->status  — FullyVerified | ContentVerified | Partial
```

### P2 Split Transport

```cpp
#include "sfc/split_encoder.h"
#include "sfc/split_decoder.h"

auto segs   = sfc::encode_split(payload, params, /*num_segments=*/4);
auto result = sfc::decode_split(std::span{*segs});  // any order; can drop up to M segments
```

Use `decode_multi` for a mixed bag of regular files and P2 segments — it groups by UUID automatically.

### P5 Directory

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

Result<vector<uint8_t>>          encode_directory(vector<DirectoryInputFile>, EncodeParams);
Result<DirectoryExtractResult>   extract_directory_full(span<const uint8_t> inner_content);
Result<DirectoryExtractResult>   extract_directory_partial(const vector<ParsedChunk>&, const GlobalHeader&);
```

## Fuzzing

```bash
make fuzz   # builds and runs 50k iterations per target
```

Two targets: `fuzz_decode` (full decode pipeline) and `fuzz_global_header` (header/chunk/manifest parsers independently).

## Testing

```bash
make test        # standard suite (306 tests)
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

**UUID** — supply a cryptographically random value per file:

```cpp
sfc::FileUuid uuid;
arc4random_buf(uuid.bytes.data(), 16);  // macOS / BSDs
// getrandom(uuid.bytes.data(), 16, 0); // Linux
```

**Choosing N, M, S**
- S must be even; 4096–65536 is a reasonable range.
- M = maximum chunk losses expected in transit. M = 0 disables erasure coding.
- N + M must not exceed 65535 (GF(2¹⁶) field limit).

