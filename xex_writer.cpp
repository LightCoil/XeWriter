#include "xex_writer.hpp"
#include <openssl/sha.h>
#include <cstring>
#include <algorithm>

namespace xexlib {

XexWriter::XexWriter(uint32_t sectionAlign) noexcept
  : m_entryPoint(0)
  , m_imageBase(0x82000000)
  , m_baseFileName()
  , m_hasCert(false)
  , m_cert{}
  , m_tlsBlob()
  , m_resBlob()
  , m_imports()
  , m_exports()
  , m_sections()
  , m_compress()
  , m_sectionAlign(sectionAlign)
  , m_bigEndian(std::endian::native == std::endian::big)
  , m_reserve(true)
{
}

void XexWriter::setEntryPoint(uint32_t ep) noexcept {
    m_entryPoint = ep;
}

void XexWriter::setImageBase(uint32_t base) noexcept {
    m_imageBase = base;
}

void XexWriter::setBaseFileName(const std::u8string& name) noexcept {
    m_baseFileName = name;
}

void XexWriter::addCodeSection(std::span<const uint8_t> code) {
    m_sections.push_back({ std::vector<uint8_t>(code.begin(), code.end()),
                           uint32_t(SectionFlag::Code), 0 });
}

void XexWriter::addDataSection(std::span<const uint8_t> data) {
    m_sections.push_back({ std::vector<uint8_t>(data.begin(), data.end()),
                           uint32_t(SectionFlag::Data), 0 });
}

void XexWriter::addBssSection(uint32_t size) {
    uint32_t a = alignUp(size, m_sectionAlign);
    m_sections.push_back({ {}, uint32_t(SectionFlag::Bss), a });
}

void XexWriter::setImportLibraries(const std::map<std::string, std::vector<std::string>>& libs) {
    m_imports = libs;
}

void XexWriter::setExportLibraries(const std::map<std::string, std::vector<std::string>>& libs) {
    m_exports = libs;
}

void XexWriter::setTlsInfo(const std::vector<uint8_t>& b) {
    m_tlsBlob = b;
}

void XexWriter::setResourceInfo(const std::vector<uint8_t>& b) {
    m_resBlob = b;
}

void XexWriter::setCertificateParams(uint32_t t, uint32_t d,
                                     uint8_t cl, uint8_t f,
                                     uint8_t m, uint8_t v,
                                     const std::vector<uint8_t>& key)
{
    if (key.size() != sizeof(m_cert.LanKey))
        throw std::invalid_argument("LanKey must be 16 bytes");

    m_cert.Size          = sizeof(XexCertificate);
    m_cert.TimeDateStamp = static_cast<uint32_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    m_cert.TitleID       = t;
    m_cert.DeviceID      = d;
    m_cert.ConsoleLimit  = cl;
    m_cert.Flags         = f;
    m_cert.MediaID       = m;
    m_cert.Version       = v;
    std::memcpy(m_cert.LanKey, key.data(), sizeof(m_cert.LanKey));
    std::memset(m_cert.Signature, 0, sizeof(m_cert.Signature));
    m_hasCert = true;
}

void XexWriter::setCompressionFunction(std::function<bool(const std::vector<uint8_t>&,
                                                         std::vector<uint8_t>&)> fn) noexcept
{
    m_compress = std::move(fn);
}

void XexWriter::setBigEndian(bool b) noexcept {
    m_bigEndian = b;
}

void XexWriter::setReserveEnabled(bool enable) noexcept {
    m_reserve = enable;
}

size_t XexWriter::estimateSize() const noexcept {
    return 512 + m_sections.size() * static_cast<size_t>(m_sectionAlign)
         + m_tlsBlob.size() + m_resBlob.size();
}

void XexWriter::writeU32(std::vector<uint8_t>& buf, uint32_t v) const {
    if (m_bigEndian) {
        buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
        buf.push_back(static_cast<uint8_t>( v        & 0xFF));
    } else {
        buf.push_back(static_cast<uint8_t>( v        & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    }
}

void XexWriter::patchU32(std::vector<uint8_t>& buf, size_t pos, uint32_t v) const {
    if (pos + 4 > buf.size()) throw std::out_of_range("patchU32 OOB");
    if (m_bigEndian) {
        buf[pos  ] = static_cast<uint8_t>((v >> 24) & 0xFF);
        buf[pos+1] = static_cast<uint8_t>((v >> 16) & 0xFF);
        buf[pos+2] = static_cast<uint8_t>((v >>  8) & 0xFF);
        buf[pos+3] = static_cast<uint8_t>( v        & 0xFF);
    } else {
        buf[pos  ] = static_cast<uint8_t>( v        & 0xFF);
        buf[pos+1] = static_cast<uint8_t>((v >>  8) & 0xFF);
        buf[pos+2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        buf[pos+3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    }
}

void XexWriter::writePadding(std::vector<uint8_t>& buf, size_t a) {
    size_t p = (a - (buf.size() % a)) % a;
    buf.insert(buf.end(), p, 0);
}

uint32_t XexWriter::alignUp(uint32_t v, uint32_t a) {
    return (v + a - 1) & ~(a - 1);
}

void XexWriter::computeSHA1(const std::vector<uint8_t>& data, uint8_t out[20]) {
    SHA1(data.data(), data.size(), out);
}

void XexWriter::writeUTF16LE(std::vector<uint8_t>& buf, const std::u8string& s) const {
    // Manual UTF-8 to UTF-16LE conversion; invalid sequences become U+FFFD
    for (size_t i = 0; i < s.size();) {
        uint32_t cp = static_cast<uint8_t>(s[i]);
        size_t len = 1;
        if ((cp & 0xE0) == 0xC0 && i + 1 < s.size()) {
            len = 2; cp = ((cp & 0x1F) << 6) | (static_cast<uint8_t>(s[i+1]) & 0x3F);
        } else if ((cp & 0xF0) == 0xE0 && i + 2 < s.size()) {
            len = 3; cp = ((cp & 0x0F) << 12)
                      | ((static_cast<uint8_t>(s[i+1]) & 0x3F) << 6)
                      |  (static_cast<uint8_t>(s[i+2]) & 0x3F);
        } else if ((cp & 0xF8) == 0xF0 && i + 3 < s.size()) {
            len = 4; cp = ((cp & 0x07) << 18)
                      | ((static_cast<uint8_t>(s[i+1]) & 0x3F) << 12)
                      | ((static_cast<uint8_t>(s[i+2]) & 0x3F) << 6)
                      |  (static_cast<uint8_t>(s[i+3]) & 0x3F);
        }
        if (cp <= 0xFFFF) {
            buf.push_back(static_cast<uint8_t>(cp & 0xFF));
            buf.push_back(static_cast<uint8_t>((cp >> 8) & 0xFF));
        } else {
            cp -= 0x10000;
            char16_t hi = char16_t((cp >> 10) + 0xD800);
            char16_t lo = char16_t((cp & 0x3FF) + 0xDC00);
            buf.push_back(static_cast<uint8_t>(hi & 0xFF));
            buf.push_back(static_cast<uint8_t>((hi >> 8) & 0xFF));
            buf.push_back(static_cast<uint8_t>(lo & 0xFF));
            buf.push_back(static_cast<uint8_t>((lo >> 8) & 0xFF));
        }
        i += len;
    }
    // Null terminator
    buf.push_back(0); buf.push_back(0);
}

void XexWriter::serializeCertificate(std::vector<uint8_t>& B, bool inc) const {
    writeU32(B, m_cert.Size);
    writeU32(B, m_cert.TimeDateStamp);
    writeU32(B, m_cert.TitleID);
    writeU32(B, m_cert.DeviceID);
    B.push_back(m_cert.ConsoleLimit);
    B.push_back(m_cert.Flags);
    B.push_back(m_cert.MediaID);
    B.push_back(m_cert.Version);
    B.insert(B.end(), m_cert.LanKey,   m_cert.LanKey   + 16);
    if (inc) {
        B.insert(B.end(), m_cert.Signature, m_cert.Signature + 20);
    } else {
        B.insert(B.end(), 20, 0);
    }
}

void XexWriter::fillCertificateSignature(const std::vector<uint8_t>& /*fullImg*/, std::string& /*err*/) {
    // Create a temp copy of the certificate with Signature zeroed
    std::vector<uint8_t> tmp(sizeof(XexCertificate));
    std::memcpy(tmp.data(), &m_cert, sizeof(XexCertificate));
    std::fill(tmp.begin() + offsetof(XexCertificate, Signature), tmp.end(), 0);
    // Compute SHA-1 over the certificate structure (with zeroed signature)
    computeSHA1(tmp, m_cert.Signature);
}

bool XexWriter::write(std::vector<uint8_t>& out, std::string& err) {
    err.clear();
    if (!m_entryPoint || !m_hasCert || m_baseFileName.empty()) {
        err = "Missing parameters";
        return false;
    }

    // 1. Primary headers
    std::vector<uint8_t> header;
    header.reserve(64);
    writeU32(header, uint32_t(OptKey::EntryPoint));
    writeU32(header, 4);
    writeU32(header, m_entryPoint);
    writeU32(header, uint32_t(OptKey::ImageBase));
    writeU32(header, 4);
    writeU32(header, m_imageBase);

    std::vector<uint8_t> fn;
    writeUTF16LE(fn, m_baseFileName);
    writeU32(header, uint32_t(OptKey::BaseFileName));
    writeU32(header, uint32_t(fn.size()));
    header.insert(header.end(), fn.begin(), fn.end());

    // Terminator for headers
    writeU32(header, 0);

    // 2. Sections (body)
    std::vector<uint8_t> image = header;
    for (auto& sec : m_sections) {
        writePadding(image, m_sectionAlign);
        if (sec.flags == uint32_t(SectionFlag::Bss)) {
            // No data for BSS in image
            continue;
        }
        if (m_compress) {
            std::vector<uint8_t> cmp;
            if (!m_compress(sec.data, cmp)) {
                err = "Compression failed";
                return false;
            }
            image.insert(image.end(), cmp.begin(), cmp.end());
        } else {
            image.insert(image.end(), sec.data.begin(), sec.data.end());
        }
    }
    // Final alignment after last section
    writePadding(image, m_sectionAlign);

    // 3. Certificate signature (SHA-1)
    fillCertificateSignature(image, err);

    // 4. Optional fields
    std::vector<OptEntry> opts;

    // SectionTable
    {
        std::vector<uint8_t> tbl;
        uint32_t rva = 0;
        for (auto& sec : m_sections) {
            writePadding(tbl, m_sectionAlign);
            XexSectionEntry e;
            e.RVA = rva;
            e.Size = (sec.flags == uint32_t(SectionFlag::Bss)) ? sec.bssSize : static_cast<uint32_t>(sec.data.size());
            e.Flags = sec.flags;
            writeU32(tbl, e.RVA);
            writeU32(tbl, e.Size);
            writeU32(tbl, e.Flags);
            rva = static_cast<uint32_t>(tbl.size());
        }
        opts.push_back({ uint32_t(OptKey::SectionTable), std::move(tbl) });
    }

    // Imports
    if (!m_imports.empty()) {
        std::vector<uint8_t> imp;
        writeU32(imp, uint32_t(m_imports.size()));
        for (auto& kv : m_imports) {
            writeUTF16LE(imp, std::u8string(kv.first.begin(), kv.first.end()));
            writeU32(imp, uint32_t(kv.second.size()));
            for (auto& fn : kv.second) {
                writeUTF16LE(imp, std::u8string(fn.begin(), fn.end()));
            }
        }
        opts.push_back({ uint32_t(OptKey::ImportLibraries), std::move(imp) });
    }

    // Exports
    if (!m_exports.empty()) {
        std::vector<uint8_t> exp;
        writeU32(exp, uint32_t(m_exports.size()));
        for (auto& kv : m_exports) {
            writeUTF16LE(exp, std::u8string(kv.first.begin(), kv.first.end()));
            writeU32(exp, uint32_t(kv.second.size()));
            for (auto& fn : kv.second) {
                writeUTF16LE(exp, std::u8string(fn.begin(), fn.end()));
            }
        }
        opts.push_back({ uint32_t(OptKey::ExportLibraries), std::move(exp) });
    }

    // TLS/Resource
    if (!m_tlsBlob.empty()) {
        opts.push_back({ uint32_t(OptKey::TlsInfo), m_tlsBlob });
    }
    if (!m_resBlob.empty()) {
        opts.push_back({ uint32_t(OptKey::ResourceInfo), m_resBlob });
    }

    // Certificate (including signature)
    {
        std::vector<uint8_t> cb;
        serializeCertificate(cb, true);
        opts.push_back({ uint32_t(OptKey::Certificate), std::move(cb) });
    }

    // CompressionInfo (if used)
    if (m_compress) {
        std::vector<uint8_t> ci;
        writeU32(ci, 1);      // algorithm (dummy value)
        writeU32(ci, 0x8000); // block size
        writeU32(ci, 0x2000); // threshold
        opts.push_back({ uint32_t(OptKey::CompressionInfo), std::move(ci) });
    }

    // SecurityInfo (SHA-1 of image)
    {
        uint8_t h[20];
        computeSHA1(image, h);
        opts.push_back({ uint32_t(OptKey::SecurityInfo),
                         std::vector<uint8_t>(h, h+20) });
    }

    // 5. Final assembly
    std::vector<uint8_t> finalB;
    finalB.reserve(header.size() + image.size() + 256);

    // Signature "XEX2" (in little-endian yields 'X','E','X','2')
    writeU32(finalB, 0x32584558);
    // Version = 2
    writeU32(finalB, 2);
    // Placeholder for total size
    size_t pos = finalB.size();
    writeU32(finalB, 0);
    // Number of opt entries
    writeU32(finalB, uint32_t(opts.size()));
    // Write each opt entry: key, size, data
    for (auto& o : opts) {
        writeU32(finalB, o.key);
        writeU32(finalB, uint32_t(o.data.size()));
        finalB.insert(finalB.end(), o.data.begin(), o.data.end());
    }
    // Terminator for opt entries
    writeU32(finalB, 0);
    // Align to section
    writePadding(finalB, m_sectionAlign);
    // Append section image
    finalB.insert(finalB.end(), image.begin(), image.end());
    // Patch in final size
    patchU32(finalB, pos, uint32_t(finalB.size()));

    out = std::move(finalB);
    return true;
}

} // namespace xexlib
