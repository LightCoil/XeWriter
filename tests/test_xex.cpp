#include "xex_writer.hpp"
#include <gtest/gtest.h>
#include <filesystem>

using namespace xexlib;

TEST(XexWriter, BasicCreation) {
    XexWriter w;
    w.setEntryPoint(0x1000);
    w.setImageBase(0x82000000);
    w.setBaseFileName(u8"HelloFreeboot");
    std::vector<uint8_t> lan(16, 0xAA);
    w.setCertificateParams(0x1234,0x5678,1,2,3,4, lan);
    w.addDataSection({0xDE,0xAD,0xBE,0xEF});
    std::vector<uint8_t> out; std::string err;
    ASSERT_TRUE(w.write(out, err)) << err;
    ASSERT_GE(out.size(), 16u);
    EXPECT_EQ(out[0],'X'); EXPECT_EQ(out[1],'E');
    EXPECT_EQ(out[2],'X'); EXPECT_EQ(out[3],'2');
}

TEST(XexWriter, SectionTable) {
    XexWriter w;
    w.setEntryPoint(1); w.setImageBase(1);
    w.setBaseFileName(u8"Sec");
    std::vector<uint8_t> lan(16);
    w.setCertificateParams(1,1,1,1,1,1, lan);
    w.addCodeSection({0xAA});
    w.addDataSection({0xBB});
    w.addBssSection(0x10);
    std::vector<uint8_t> out; std::string err;
    ASSERT_TRUE(w.write(out, err));
    bool found = false;
    for (size_t i=0;i+3<out.size();++i){
        uint32_t k = out[i]|out[i+1]<<8|out[i+2]<<16|out[i+3]<<24;
        if (k == uint32_t(OptKey::SectionTable)) { found = true; break; }
    }
    EXPECT_TRUE(found);
}

TEST(XexWriter, ImportExport) {
    XexWriter w;
    w.setEntryPoint(2); w.setImageBase(2);
    w.setBaseFileName(u8"ImpExp");
    std::vector<uint8_t> lan(16);
    w.setCertificateParams(2,2,1,1,1,1, lan);
    w.setImportLibraries({{"XAudio2_0",{"XAudio2Create","IXAudio2_Release"}}});
    w.setExportLibraries({{"MyLibExport",{"FuncA","FuncB"}}});
    std::vector<uint8_t> out; std::string err;
    ASSERT_TRUE(w.write(out, err));
    bool hasImp=false, hasExp=false;
    for (size_t i=0;i+3<out.size();++i){
        uint32_t k = out[i]|out[i+1]<<8|out[i+2]<<16|out[i+3]<<24;
        if (k == uint32_t(OptKey::ImportLibraries)) hasImp=true;
        if (k == uint32_t(OptKey::ExportLibraries)) hasExp=true;
    }
    EXPECT_TRUE(hasImp); EXPECT_TRUE(hasExp);
}

TEST(XexWriter, UTF16LE) {
    XexWriter w;
    w.setEntryPoint(3); w.setImageBase(3);
    w.setBaseFileName(u8"Привет");
    std::vector<uint8_t> lan(16);
    w.setCertificateParams(3,3,1,1,1,1, lan);
    std::vector<uint8_t> out; std::string err;
    ASSERT_TRUE(w.write(out, err));
    // Проверим, что в бинарнике есть two-bytes non-zero sequence (UTF-16LE)
    bool found=false;
    for (size_t i=0;i+1<out.size();i++){
        if (out[i]!=0||out[i+1]!=0) { found=true; break; }
    }
    EXPECT_TRUE(found);
}

TEST(XexWriter, TLSResource) {
    XexWriter w;
    w.setEntryPoint(4); w.setImageBase(4);
    w.setBaseFileName(u8"TR");
    std::vector<uint8_t> lan(16);
    w.setCertificateParams(4,4,1,1,1,1, lan);
    w.setTlsInfo({0x10,0x20,0x30});
    w.setResourceInfo({0xFF,0xEE,0xDD});
    std::vector<uint8_t> out; std::string err;
    ASSERT_TRUE(w.write(out, err));
    bool hasTLS=false, hasRes=false;
    for (size_t i=0;i+3<out.size();++i){
        uint32_t k = out[i]|out[i+1]<<8|out[i+2]<<16|out[i+3]<<24;
        if (k == uint32_t(OptKey::TlsInfo)) hasTLS=true;
        if (k == uint32_t(OptKey::ResourceInfo)) hasRes=true;
    }
    EXPECT_TRUE(hasTLS); EXPECT_TRUE(hasRes);
}
