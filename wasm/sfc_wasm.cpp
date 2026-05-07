#include <emscripten/bind.h>
#include <emscripten/val.h>

#include "sfc/decoder.h"
#include "sfc/encoder.h"
#include "sfc/global_header.h"
#include "sfc/tlv.h"
#include "sfc/trailer.h"
#include "sfc/types.h"
#include "sfc/validation.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

using namespace emscripten;

// Helpers

static std::vector<uint8_t> from_js(const val& v) {
    const unsigned n = v["length"].as<unsigned>();
    std::vector<uint8_t> buf(n);
    val view{typed_memory_view(n, buf.data())};
    view.call<void>("set", v);
    return buf;
}

static val to_js(const std::vector<uint8_t>& v) {
    val view{typed_memory_view(v.size(), v.data())};
    return val::global("Uint8Array").new_(view);
}

static uint32_t read_u32_le(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint32_t>(b[off])
         | (static_cast<uint32_t>(b[off + 1]) << 8)
         | (static_cast<uint32_t>(b[off + 2]) << 16)
         | (static_cast<uint32_t>(b[off + 3]) << 24);
}

// Parse global header from raw file bytes (skips the 8-byte preamble).
static sfc::Result<sfc::GlobalHeader> parse_hdr(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 12)
        return std::unexpected(sfc::SfcError{sfc::ErrorCode::HeaderLengthOutOfBounds,
                                             "file too small"});
    auto preamble_res = sfc::validate_preamble(
        std::span<const uint8_t, 8>{bytes.data(), 8});
    if (!preamble_res) return std::unexpected(preamble_res.error());

    const uint32_t h = read_u32_le(bytes, 8);
    if (bytes.size() < static_cast<size_t>(h) + 12)
        return std::unexpected(sfc::SfcError{sfc::ErrorCode::HeaderLengthOutOfBounds,
                                             "truncated header"});
    return sfc::parse_global_header(
        std::span<const uint8_t>{bytes}.subspan(8, static_cast<size_t>(h) + 4));
}

static std::string inner_filename(const sfc::GlobalHeader& hdr) {
    const auto& raw = hdr.inner_filename;
    auto end = std::find(raw.begin(), raw.end(), uint8_t{0});
    return std::string(raw.begin(), end);
}

static std::string compression_name(uint8_t id) {
    switch (static_cast<sfc::CompressionAlgo>(id)) {
        case sfc::CompressionAlgo::Identity:  return "none";
        case sfc::CompressionAlgo::Zstd:      return "zstd";
        case sfc::CompressionAlgo::Brotli:    return "brotli";
        case sfc::CompressionAlgo::Lz4Frame:  return "lz4";
        default:                              return "unknown";
    }
}

static uint16_t format_id_from_filename(const std::string& filename) {
    std::string ext = std::filesystem::path(filename).extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    using F = sfc::InnerFormatId;
    if (ext == ".txt" || ext == ".md" || ext == ".csv" || ext == ".json" || ext == ".xml")
        return static_cast<uint16_t>(F::PlainText);
    if (ext == ".jpg" || ext == ".jpeg")
        return static_cast<uint16_t>(F::JpegBaseline);
    if (ext == ".jxl")
        return static_cast<uint16_t>(F::JpegXl);
    if (ext == ".jp2" || ext == ".j2k")
        return static_cast<uint16_t>(F::Jpeg2000);
    if (ext == ".png")
        return static_cast<uint16_t>(F::PngNonInterlaced);
    if (ext == ".webp")
        return static_cast<uint16_t>(F::WebP);
    if (ext == ".mp4" || ext == ".m4v")
        return static_cast<uint16_t>(F::FragmentedMp4);
    if (ext == ".webm" || ext == ".mkv")
        return static_cast<uint16_t>(F::MatroskaWebm);
    if (ext == ".zip")
        return static_cast<uint16_t>(F::Zip);
    if (ext == ".gz")
        return static_cast<uint16_t>(F::Gzip);
    if (ext == ".zst")
        return static_cast<uint16_t>(F::ZstdData);
    if (ext == ".pdf")
        return static_cast<uint16_t>(F::Pdf);
    if (ext == ".epub")
        return static_cast<uint16_t>(F::EPub);
    if (ext == ".sfc")
        return static_cast<uint16_t>(F::NestedSfc);
    return static_cast<uint16_t>(F::ArbitraryBinary);
}

static std::string format_id_name(uint16_t id) {
    switch (static_cast<sfc::InnerFormatId>(id)) {
        case sfc::InnerFormatId::Unknown:          return "Unknown";
        case sfc::InnerFormatId::ArbitraryBinary:  return "ArbitraryBinary";
        case sfc::InnerFormatId::PlainText:        return "PlainText";
        case sfc::InnerFormatId::LineOriented:     return "LineOriented";
        case sfc::InnerFormatId::JpegBaseline:     return "JpegBaseline";
        case sfc::InnerFormatId::JpegProgressive:  return "JpegProgressive";
        case sfc::InnerFormatId::Jpeg2000:         return "Jpeg2000";
        case sfc::InnerFormatId::JpegXl:           return "JpegXl";
        case sfc::InnerFormatId::PngNonInterlaced: return "PngNonInterlaced";
        case sfc::InnerFormatId::PngAdam7:         return "PngAdam7";
        case sfc::InnerFormatId::WebP:             return "WebP";
        case sfc::InnerFormatId::FragmentedMp4:    return "FragmentedMp4";
        case sfc::InnerFormatId::MatroskaWebm:     return "MatroskaWebm";
        case sfc::InnerFormatId::Zip:              return "Zip";
        case sfc::InnerFormatId::Gzip:             return "Gzip";
        case sfc::InnerFormatId::ZstdData:         return "ZstdData";
        case sfc::InnerFormatId::TarZstd:          return "TarZstd";
        case sfc::InnerFormatId::SfcDirectory:     return "SfcDirectory";
        case sfc::InnerFormatId::NestedSfc:        return "NestedSfc";
        case sfc::InnerFormatId::Pdf:              return "Pdf";
        case sfc::InnerFormatId::EPub:             return "EPub";
        default:                                   return "Unknown";
    }
}

static std::string profile_name(uint16_t flags) {
    using F = sfc::FlagBit;
    if (flags & (1u << static_cast<uint16_t>(F::SplitProfile)))      return "split transport";
    if (flags & (1u << static_cast<uint16_t>(F::DirectoryProfile)))  return "directory";
    if (flags & (1u << static_cast<uint16_t>(F::ImageProfile)))      return "image";
    if (flags & (1u << static_cast<uint16_t>(F::HttpProfile)))       return "http delivery";
    if (flags & (1u << static_cast<uint16_t>(F::PreprocessProfile))) return "preprocessed";
    return "regular";
}

static std::string status_name(sfc::ReassemblyStatus status) {
    switch (status) {
        case sfc::ReassemblyStatus::FullyVerified:   return "verified";
        case sfc::ReassemblyStatus::ContentVerified: return "content-verified";
        case sfc::ReassemblyStatus::Partial:         return "partial";
    }
    return "unknown";
}

static std::string format_uuid(const sfc::FileUuid& uuid) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (size_t i = 0; i < uuid.bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out.push_back('-');
        const uint8_t b = uuid.bytes[i];
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}

static bool has_trailer(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 64) return false;
    auto trailer = sfc::parse_trailer(
        std::span<const uint8_t, 64>{bytes.data() + bytes.size() - 64, 64});
    return trailer.has_value();
}

static uint64_t trailer_timestamp(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 64) return 0;
    auto trailer = sfc::parse_trailer(
        std::span<const uint8_t, 64>{bytes.data() + bytes.size() - 64, 64});
    return trailer ? trailer->timestamp : 0;
}

static std::string tlv_string(const sfc::GlobalHeader& hdr, uint16_t tag) {
    for (const auto& f : hdr.tlv_fields) {
        if (f.tag == tag) return std::string(f.value.begin(), f.value.end());
    }
    return {};
}

// Exported functions

// encode(content, m, filename, algo, uuid16) -> Uint8Array; throws on error
val js_encode(const val& content, int m, const std::string& filename,
              const std::string& algo_name, const val& uuid_js) {
    auto bytes    = from_js(content);
    auto uuid_vec = from_js(uuid_js);

    sfc::CompressionAlgo algo = sfc::CompressionAlgo::Zstd;
    if      (algo_name == "zstd")   algo = sfc::CompressionAlgo::Zstd;
    else if (algo_name == "brotli") algo = sfc::CompressionAlgo::Brotli;
    else if (algo_name == "lz4")    algo = sfc::CompressionAlgo::Lz4Frame;
    else if (algo_name == "none")   algo = sfc::CompressionAlgo::Identity;
    else throw std::runtime_error("unknown compression algorithm: " + algo_name);

    sfc::FileUuid uuid{};
    if (uuid_vec.size() == 16)
        std::copy(uuid_vec.begin(), uuid_vec.end(), uuid.bytes.begin());

    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now).count();

    sfc::EncodeParams p{
        .m         = static_cast<uint32_t>(m > 0 ? m : 0),
        .s         = 65536,
        .algo      = algo,
        .uuid      = uuid,
        .timestamp = static_cast<uint64_t>(timestamp),
        .format_id = format_id_from_filename(filename),
        .filename  = filename,
    };

    auto r = sfc::encode(std::span<const uint8_t>{bytes}, p);
    if (!r) throw std::runtime_error(r.error().detail);
    return to_js(*r);
}

// decode(sfcBytes) -> {data, filename, status, n, m}; throws on error
val js_decode(const val& sfc_bytes_js) {
    auto bytes = from_js(sfc_bytes_js);

    auto r = sfc::decode(std::span<const uint8_t>{bytes});
    if (!r) throw std::runtime_error(r.error().detail);
    if (r->status == sfc::ReassemblyStatus::Partial) {
        throw std::runtime_error("partial reassembly: unpack requires fully recoverable input");
    }

    std::string fname;
    uint32_t n = 0, m = 0;
    auto hdr = parse_hdr(bytes);
    if (hdr) { fname = inner_filename(*hdr); n = hdr->n; m = hdr->m; }

    val obj = val::object();
    obj.set("data",     to_js(r->content));
    obj.set("filename", fname.empty() ? std::string("output.bin") : fname);
    obj.set("status",   status_name(r->status));
    obj.set("n",        static_cast<int>(n));
    obj.set("m",        static_cast<int>(m));
    return obj;
}

// info(sfcBytes) -> metadata object; throws on error
val js_info(const val& sfc_bytes_js) {
    auto bytes = from_js(sfc_bytes_js);
    auto hdr = parse_hdr(bytes);
    if (!hdr) throw std::runtime_error(hdr.error().detail);

    val obj = val::object();
    obj.set("uuid",        format_uuid(hdr->uuid));
    obj.set("filename",    inner_filename(*hdr));
    obj.set("profile",     profile_name(hdr->flags));
    obj.set("n",           static_cast<int>(hdr->n));
    obj.set("m",           static_cast<int>(hdr->m));
    obj.set("s",           static_cast<int>(hdr->s));
    obj.set("innerSize",   static_cast<double>(hdr->inner_file_size));
    obj.set("formatId",    static_cast<int>(hdr->inner_format_id));
    obj.set("formatName",  format_id_name(hdr->inner_format_id));
    obj.set("compression", compression_name(hdr->compression_algo));
    obj.set("erasure",     hdr->erasure_algo == 0x01 ? std::string("RS-GF2^16")
                                                     : std::string("none"));
    obj.set("flags",       static_cast<int>(hdr->flags));
    obj.set("trailer",     has_trailer(bytes));
    obj.set("timestamp",   static_cast<double>(trailer_timestamp(bytes)));
    obj.set("author",      tlv_string(*hdr, sfc::TlvTag::kAuthor));
    obj.set("description", tlv_string(*hdr, sfc::TlvTag::kDescription));
    obj.set("location",    tlv_string(*hdr, sfc::TlvTag::kLocation));
    obj.set("software",    tlv_string(*hdr, sfc::TlvTag::kSoftware));
    obj.set("comment",     tlv_string(*hdr, sfc::TlvTag::kComment));
    return obj;
}

// verify(sfcBytes) -> {ok, status, missingChunks, recoveredSize}; throws on fatal error
val js_verify(const val& sfc_bytes_js) {
    auto bytes = from_js(sfc_bytes_js);
    auto r = sfc::decode(std::span<const uint8_t>{bytes});
    if (!r) throw std::runtime_error(r.error().detail);

    val missing = val::array();
    for (size_t i = 0; i < r->missing_chunks.size(); ++i)
        missing.set(static_cast<unsigned>(i), static_cast<int>(r->missing_chunks[i]));

    val obj = val::object();
    obj.set("ok",            r->status != sfc::ReassemblyStatus::Partial);
    obj.set("status",        status_name(r->status));
    obj.set("missingChunks", missing);
    obj.set("recoveredSize", static_cast<double>(r->content.size()));
    return obj;
}

EMSCRIPTEN_BINDINGS(sfc) {
    function("encode", &js_encode);
    function("decode", &js_decode);
    function("info",   &js_info);
    function("verify", &js_verify);
}
