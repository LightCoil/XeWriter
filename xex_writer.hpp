#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <span>
#include <bit>        // for std::endian
#include <chrono>
#include <stdexcept>
#include <algorithm>

namespace xexlib {

// Default section alignment (0x1000 = 4 KB)
static constexpr uint32_t kDefaultSectionAlign = 0x1000;

// Optional header keys for XEX2 format
enum class OptKey : uint32_t {
    EntryPoint      = 0x000002FF,
    ImageBase       = 0x00000300,
    BaseFileName    = 0x00000500,
    SectionTable    = 0x00000400,
    ImportLibraries = 0x00000800,
    ExportLibraries = 0x00000C00,
    TlsInfo         = 0x00000600,
    ResourceInfo    = 0x00000700,
    Certificate     = 0x00003000,
    SecurityInfo    = 0x00001000,
    CompressionInfo = 0x00004000
};

// Section flags for XEX sections
enum class SectionFlag : uint32_t {
    Code = 0x20,
    Data = 0x40,
    Bss  = 0x80
};

// XEX Certificate structure (packed, 1-byte alignment)
#pragma pack(push,1)
struct XexCertificate {
    uint32_t Size;
    uint32_t TimeDateStamp;
    uint32_t TitleID;
    uint32_t DeviceID;
    uint8_t  ConsoleLimit;
    uint8_t  Flags;
    uint8_t  MediaID;
    uint8_t  Version;
    uint8_t  LanKey[16];
    uint8_t  Signature[20];
};
#pragma pack(pop)

// Section entry (packed, 1-byte alignment)
#pragma pack(push,1)
struct XexSectionEntry {
    uint32_t RVA;
    uint32_t Size;
    uint32_t Flags;
};
#pragma pack(pop)

// XexWriter: class for building XEX2 (Freeboot-style) files
class XexWriter {
public:
    explicit XexWriter(uint32_t sectionAlign = kDefaultSectionAlign) noexcept;

    // Basic settings
    void setEntryPoint(uint32_t ep) noexcept;
    void setImageBase(uint32_t base) noexcept;
    void setBaseFileName(const std::u8string& name) noexcept;
    void addCodeSection(std::span<const uint8_t> code);
    void addDataSection(std::span<const uint8_t> data);
    void addBssSection(uint32_t size);

    // Import/Export libraries
    void setImportLibraries(const std::map<std::string, std::vector<std::string>>& libs);
    void setExportLibraries(const std::map<std::string, std::vector<std::string>>& libs);

    // TLS and Resource info
    void setTlsInfo(const std::vector<uint8_t>& tlsBlob);
    void setResourceInfo(const std::vector<uint8_t>& resBlob);

    // Certificate parameters (Freeboot SHA-1 certificate)
    void setCertificateParams(uint32_t titleID, uint32_t deviceID,
                              uint8_t consoleLimit, uint8_t flags,
                              uint8_t mediaID, uint8_t version,
                              const std::vector<uint8_t>& lanKey);

    // Compression function (optional; should produce compressed data)
    void setCompressionFunction(std::function<bool(const std::vector<uint8_t>&, std::vector<uint8_t>&)> fn) noexcept;

    // Byte order and reserve flag
    void setBigEndian(bool big) noexcept;
    void setReserveEnabled(bool enable) noexcept;

    // Build XEX; returns true on success, output in 'out', error message in 'error'
    bool write(std::vector<uint8_t>& out, std::string& error);

private:
    struct OptEntry { uint32_t key; std::vector<uint8_t> data; };
    struct Section  { std::vector<uint8_t> data; uint32_t flags; uint32_t bssSize; };

    uint32_t m_entryPoint = 0;
    uint32_t m_imageBase  = 0x82000000;  // default Freeboot base
    std::u8string m_baseFileName;
    bool m_hasCert = false;
    XexCertificate m_cert{};
    std::vector<uint8_t> m_tlsBlob, m_resBlob;
    std::map<std::string, std::vector<std::string>> m_imports, m_exports;
    std::vector<Section> m_sections;
    std::function<bool(const std::vector<uint8_t>&, std::vector<uint8_t>&)> m_compress;
    uint32_t m_sectionAlign;
    bool m_bigEndian;
    bool m_reserve;

    // Helper methods
    void writeU32(std::vector<uint8_t>& buf, uint32_t v) const;
    void patchU32(std::vector<uint8_t>& buf, size_t pos, uint32_t v) const;
    static void writePadding(std::vector<uint8_t>& buf, size_t align);
    static uint32_t alignUp(uint32_t val, uint32_t align);
    static void computeSHA1(const std::vector<uint8_t>& data, uint8_t out[20]);
    void writeUTF16LE(std::vector<uint8_t>& buf, const std::u8string& s) const;
    void serializeCertificate(std::vector<uint8_t>& buf, bool includeSig) const;
    void fillCertificateSignature(const std::vector<uint8_t>& fullImg, std::string& error);
    size_t estimateSize() const noexcept;
};

} // namespace xexlib
