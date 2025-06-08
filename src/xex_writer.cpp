#include "xex_writer.hpp"

namespace xexlib {

XexWriter::XexWriter(uint32_t sectionAlign) noexcept
  : m_sectionAlign(sectionAlign),
    m_bigEndian(std::endian::native == std::endian::big),
    m_reserve(true)
{}

void XexWriter::setEntryPoint(uint32_t ep) noexcept { m_entryPoint = ep; }
void XexWriter::setImageBase(uint32_t base) noexcept  { m_imageBase  = base; }
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

void XexWriter::setImportLibraries(const auto& libs) {
    m_imports = libs;
}

void XexWriter::setExportLibraries(const auto& libs) {
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
    m_cert.TimeDateStamp = uint32_t(std::chrono::system_clock::to_time_t(
                                  std::chrono::system_clock::now()));
    m_cert.TitleID       = t;
    m_cert.DeviceID      = d;
    m_cert.ConsoleLimit  = cl;
    m_cert.Flags         = f;
    m_cert.MediaID       = m;
    m_cert.Version       = v;
    std::memcpy(m_cert.LanKey, key.data(), 16);
    std::memset(m_cert.Signature, 0, 20);
    m_hasCert = true;
}

void XexWriter::setCompressionFunction(auto fn) noexcept {
    m_compress = std::move(fn);
}

void XexWriter::setBigEndian(bool b) noexcept {
    m_bigEndian = b;
}

size_t XexWriter::estimateSize() const noexcept {
    return 512 + m_sections.size()*m_sectionAlign
             + m_tlsBlob.size() + m_resBlob.size();
}

void XexWriter::writeU32(std::vector<uint8_t>& buf, uint32_t v) {
    if (m_bigEndian) {
        buf.push_back((v>>24)&0xFF);
        buf.push_back((v>>16)&0xFF);
        buf.push_back((v>>8)&0xFF);
        buf.push_back(v&0xFF);
    } else {
        buf.push_back(v&0xFF);
        buf.push_back((v>>8)&0xFF);
        buf.push_back((v>>16)&0xFF);
        buf.push_back((v>>24)&0xFF);
    }
}

void XexWriter::patchU32(std::vector<uint8_t>& buf, size_t pos, uint32_t v) {
    if (pos+4 > buf.size()) throw std::out_of_range("patchU32 OOB");
    if (m_bigEndian) {
        buf[pos]   = (v>>24)&0xFF;
        buf[pos+1] = (v>>16)&0xFF;
        buf[pos+2] = (v>>8)&0xFF;
        buf[pos+3] = v&0xFF;
    } else {
        buf[pos]   = v&0xFF;
        buf[pos+1] = (v>>8)&0xFF;
        buf[pos+2] = (v>>16)&0xFF;
        buf[pos+3] = (v>>24)&0xFF;
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

void XexWriter::computeSHA256(const std::vector<uint8_t>& data, uint8_t out[32]) {
    SHA256(data.data(), data.size(), out);
}

void XexWriter::writeUTF16LE(std::vector<uint8_t>& buf, const std::u8string& s) {
    for (size_t i=0; i<s.size();) {
        uint32_t cp = (uint8_t)s[i];
        size_t len = 1;
        if ((cp & 0x80) != 0 && i+1<s.size() && (s[i]&0xE0)==0xC0) {
            len = 2; cp = ((cp&0x1F)<<6)|(s[i+1]&0x3F);
        } else if ((cp & 0xF0)==0xE0 && i+2<s.size()) {
            len = 3; cp = ((cp&0x0F)<<12)|((s[i+1]&0x3F)<<6)|(s[i+2]&0x3F);
        } else if ((cp & 0xF8)==0xF0 && i+3<s.size()) {
            len = 4;
            cp = ((cp&0x07)<<18)|((s[i+1]&0x3F)<<12)
               |((s[i+2]&0x3F)<<6)|(s[i+3]&0x3F);
        }
        if (cp <= 0xFFFF) {
            buf.push_back(cp & 0xFF);
            buf.push_back((cp>>8)&0xFF);
        } else {
            cp -= 0x10000;
            char16_t high = char16_t((cp>>10)+0xD800);
            char16_t low  = char16_t((cp&0x3FF)+0xDC00);
            buf.push_back(high & 0xFF);
            buf.push_back((high>>8)&0xFF);
            buf.push_back(low & 0xFF);
            buf.push_back((low>>8)&0xFF);
        }
        i += len;
    }
    buf.push_back(0);
    buf.push_back(0);
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
    B.insert(B.end(), m_cert.LanKey, m_cert.LanKey+16);
    if (inc) {
        B.insert(B.end(), m_cert.Signature, m_cert.Signature+20);
    } else {
        B.insert(B.end(), 20, 0);
    }
}

void XexWriter::fillCertificateSignature(const std::vector<uint8_t>& /*img*/,
                                         std::string& /*err*/) {
    // Для Freeboot — SHA-1 сертификата без поля Signature
    std::vector<uint8_t> tmp(sizeof(XexCertificate), 0);
    std::memcpy(tmp.data(), &m_cert, sizeof(XexCertificate));
    std::fill(tmp.begin() + offsetof(XexCertificate, Signature),
              tmp.end(), 0);
    computeSHA1(tmp, m_cert.Signature);
}

bool XexWriter::write(std::vector<uint8_t>& out, std::string& err) {
    err.clear();
    if (!m_entryPoint || !m_hasCert || m_baseFileName.empty()) {
        err = "Missing parameters"; return false;
    }

    // 1) Header primary
    std::vector<uint8_t> header;
    header.reserve(64);
    // EntryPoint
    writeU32(header, uint32_t(OptKey::EntryPoint));
    writeU32(header, 4);
    writeU32(header, m_entryPoint);
    // ImageBase
    writeU32(header, uint32_t(OptKey::ImageBase));
    writeU32(header, 4);
    writeU32(header, m_imageBase);
    // BaseFileName
    std::vector<uint8_t> fn;
    writeUTF16LE(fn, m_baseFileName);
    writeU32(header, uint32_t(OptKey::BaseFileName));
    writeU32(header, uint32_t(fn.size()));
    header.insert(header.end(), fn.begin(), fn.end());
    // Terminator
    writeU32(header, 0);

    // 2) Body (sections)
    std::vector<uint8_t> image = header;
    for (auto& sec : m_sections) {
        writePadding(image, m_sectionAlign);
        if (sec.flags == uint32_t(SectionFlag::Bss)) continue;
        if (m_compress) {
            std::vector<uint8_t> cmp;
            if (!m_compress(sec.data, cmp)) {
                err = "Compression failed"; return false;
            }
            image.insert(image.end(), cmp.begin(), cmp.end());
        } else {
            image.insert(image.end(), sec.data.begin(), sec.data.end());
        }
    }
    writePadding(image, m_sectionAlign);

    // 3) Certificate signature
    fillCertificateSignature(image, err);

    // 4) Build opt entries
    std::vector<OptEntry> opts;

    // SectionTable
    {
        std::vector<uint8_t> tbl;
        uint32_t rva = 0;
        for (auto& sec : m_sections) {
            writePadding(tbl, m_sectionAlign);
            XexSectionEntry e{ rva,
                (sec.flags==uint32_t(SectionFlag::Bss) ? sec.bssSize : uint32_t(sec.data.size())),
                sec.flags };
            writeU32(tbl, e.RVA);
            writeU32(tbl, e.Size);
            writeU32(tbl, e.Flags);
            rva = uint32_t(tbl.size());
        }
        opts.push_back({ uint32_t(OptKey::SectionTable), std::move(tbl) });
    }

    // ImportLibraries
    if (!m_imports.empty()) {
        std::vector<uint8_t> imp;
        // Формат: [count][DLLName0\0][func0\0][func1\0]...[DLLName1\0]...
        uint32_t libCount = uint32_t(m_imports.size());
        writeU32(imp, libCount);
        for (auto& [dll, funcs] : m_imports) {
            // DLL name as UTF-16LE
            std::u8string ud(dll.begin(), dll.end());
            writeUTF16LE(imp, ud);
            // function count
            writeU32(imp, uint32_t(funcs.size()));
            for (auto& fnm : funcs) {
                std::u8string uf(fnm.begin(), fnm.end());
                writeUTF16LE(imp, uf);
            }
        }
        opts.push_back({ uint32_t(OptKey::ImportLibraries), std::move(imp) });
    }

    // ExportLibraries (аналогично)
    if (!m_exports.empty()) {
        std::vector<uint8_t> exp;
        uint32_t libCount = uint32_t(m_exports.size());
        writeU32(exp, libCount);
        for (auto& [dll, funcs] : m_exports) {
            writeUTF16LE(exp, std::u8string(dll.begin(), dll.end()));
            writeU32(exp, uint32_t(funcs.size()));
            for (auto& fnm : funcs) {
                writeUTF16LE(exp, std::u8string(fnm.begin(), fnm.end()));
            }
        }
        opts.push_back({ uint32_t(OptKey::ExportLibraries), std::move(exp) });
    }

    // TLS
    if (!m_tlsBlob.empty())
        opts.push_back({ uint32_t(OptKey::TlsInfo), m_tlsBlob });

    // Resource
    if (!m_resBlob.empty())
        opts.push_back({ uint32_t(OptKey::ResourceInfo), m_resBlob });

    // Certificate
    {
        std::vector<uint8_t> cb;
        serializeCertificate(cb, true);
        opts.push_back({ uint32_t(OptKey::Certificate), std::move(cb) });
    }

    // CompressionInfo
    if (m_compress) {
        std::vector<uint8_t> ci;
        writeU32(ci, 1);      // алгоритм
        writeU32(ci, 0x8000); // block size
        writeU32(ci, 0x2000); // threshold
        opts.push_back({ uint32_t(OptKey::CompressionInfo), std::move(ci) });
    }

    // SecurityInfo (SHA-1 от image)
    {
        uint8_t hash[20];
        computeSHA1(image, hash);
        opts.push_back({ uint32_t(OptKey::SecurityInfo),
            std::vector<uint8_t>(hash, hash+20) });
    }

    // 5) Собираем финальный buffer
    std::vector<uint8_t> finalBuf;
    finalBuf.reserve(header.size() + image.size() + 256);
    writeU32(finalBuf, 0x58455832); // 'XEX2'
    writeU32(finalBuf, 2);          // version
    size_t posSize = finalBuf.size();
    writeU32(finalBuf, 0);          // placeholder for total size
    writeU32(finalBuf, uint32_t(opts.size()));
    for (auto& o : opts) {
        writeU32(finalBuf, o.key);
        writeU32(finalBuf, uint32_t(o.data.size()));
        finalBuf.insert(finalBuf.end(), o.data.begin(), o.data.end());
    }
    writeU32(finalBuf, 0); // terminator
    writePadding(finalBuf, m_sectionAlign);
    finalBuf.insert(finalBuf.end(), image.begin(), image.end());
    patchU32(finalBuf, posSize, uint32_t(finalBuf.size()));

    out = std::move(finalBuf);
    return true;
}

} // namespace xexlib
