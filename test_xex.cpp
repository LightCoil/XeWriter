#include "xex_writer.hpp"
#include <gtest/gtest.h>

using namespace xexlib;

TEST(BasicCreation, GeneratesXex2) {
    XexWriter w; 
    w.setEntryPoint(0x1000);
    w.setImageBase(0x82000000);
    w.setBaseFileName(u8"Hello");
    std::vector<uint8_t> lan(16, 0xAA);
    w.setCertificateParams(0x1234, 0x5678, 1, 2, 3, 4, lan);
    w.addDataSection({0xDE, 0xAD, 0xBE, 0xEF});

    std::vector<uint8_t> out;
    std::string err;
    ASSERT_TRUE(w.write(out, err)) << err;
    ASSERT_GE(out.size(), 16u);
    EXPECT_EQ(out[0], 'X');
    EXPECT_EQ(out[1], 'E');
    EXPECT_EQ(out[2], 'X');
    EXPECT_EQ(out[3], '2');
}

TEST(SectionTable, Present) {
    XexWriter w; 
    w.setEntryPoint(1);
    w.setImageBase(1);
    w.setBaseFileName(u8"Sec");
    std::vector<uint8_t> lan(16, 0x00);
    w.setCertificateParams(1, 1, 1, 1, 1, 1, lan);
    w.addCodeSection({0x00});
    w.addDataSection({0x11});
    w.addBssSection(0x20);

    std::vector<uint8_t> out;
    std::string err;
    ASSERT_TRUE(w.write(out, err));
    bool found = false;
    for (size_t i = 0; i + 3 < out.size(); ++i) {
        uint32_t k = out[i] | (out[i+1]<<8) | (out[i+2]<<16) | (out[i+3]<<24);
        if (k == uint32_t(OptKey::SectionTable)) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST(ImportExport, Present) {
    XexWriter w; 
    w.setEntryPoint(2);
    w.setImageBase(2);
    w.setBaseFileName(u8"IE");
    std::vector<uint8_t> lan(16, 0x00);
    w.setCertificateParams(2, 2, 1, 1, 1, 1, lan);
    w.setImportLibraries({ {"XAM", {"Func1", "Func2"}} });
    w.setExportLibraries({ {"MyExp", {"E1", "E2"}} });

    std::vector<uint8_t> out;
    std::string err;
    ASSERT_TRUE(w.write(out, err));
    bool hasImp = false, hasExp = false;
    for (size_t i = 0; i + 3 < out.size(); ++i) {
        uint32_t k = out[i] | (out[i+1]<<8) | (out[i+2]<<16) | (out[i+3]<<24);
        if (k == uint32_t(OptKey::ImportLibraries)) hasImp = true;
        if (k == uint32_t(OptKey::ExportLibraries)) hasExp = true;
    }
    EXPECT_TRUE(hasImp);
    EXPECT_TRUE(hasExp);
}

TEST(CompressionInfo, Present) {
    XexWriter w; 
    w.setEntryPoint(3);
    w.setImageBase(3);
    w.setBaseFileName(u8"Comp");
    std::vector<uint8_t> lan(16, 0x00);
    w.setCertificateParams(3, 3, 1, 1, 1, 1, lan);
    w.setCompressionFunction([](auto& src, auto& dst){ dst = src; return true; });

    std::vector<uint8_t> out;
    std::string err;
    ASSERT_TRUE(w.write(out, err));
    bool found = false;
    for (size_t i = 0; i + 3 < out.size(); ++i) {
        uint32_t k = out[i] | (out[i+1]<<8) | (out[i+2]<<16) | (out[i+3]<<24);
        if (k == uint32_t(OptKey::CompressionInfo)) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST(SecurityInfo, Present) {
    XexWriter w; 
    w.setEntryPoint(4);
    w.setImageBase(4);
    w.setBaseFileName(u8"SecI");
    std::vector<uint8_t> lan(16, 0x00);
    w.setCertificateParams(4, 4, 1, 1, 1, 1, lan);

    std::vector<uint8_t> out;
    std::string err;
    ASSERT_TRUE(w.write(out, err));
    bool found = false;
    for (size_t i = 0; i + 3 < out.size(); ++i) {
        uint32_t k = out[i] | (out[i+1]<<8) | (out[i+2]<<16) | (out[i+3]<<24);
        if (k == uint32_t(OptKey::SecurityInfo)) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}
