#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace process {

    struct RttiInfo {
        std::string name;
        uintptr_t type_descriptor;
        uintptr_t class_hierarchy_descriptor;
        std::vector<std::string> base_classes;
    };

    // تم تعديل الأحجام لتناسب x64
    struct TypeDescriptor {
        uintptr_t vftable;
        uintptr_t spare;
        char name[256];
    };

    struct RttiCompleteObjectLocatorX64 {
        uint32_t signature; // 0 for x86, 1 for x64
        uint32_t offset;
        uint32_t cd_offset;
        int32_t  type_descriptor_offset;  // Image Base Offset
        int32_t  class_descriptor_offset; // Image Base Offset
        int32_t  self_offset;             // Image Base Offset
    };

    struct RttiClassHierarchyDescriptor {
        uint32_t signature;
        uint32_t attributes;
        uint32_t numBaseClasses;
        uint32_t pBaseClassArray; // Image Base Offset
    };

    struct RttiBaseClassDescriptor {
        uint32_t pTypeDescriptor; // Image Base Offset
        uint32_t numContainedBases;
        int32_t  mdisp;
        int32_t  pdisp;
        int32_t  vdisp;
        uint32_t attributes;
        uint32_t pClassDescriptor; // Image Base Offset
    };

    class Rtti {
    public:
        // البحث عن كلاس معين داخل مساحة ذاكرة (مثل Instance)
        static auto find(uintptr_t base_address, const std::string& target_class,
            size_t max_offset = 0x1000, size_t alignment = 8) -> std::optional<size_t>;

        static auto scan_rtti(uintptr_t address) -> std::optional<RttiInfo>;

        static auto find_all(uintptr_t base_address, const std::string& target_class,
            size_t max_offset = 0x1000, size_t alignment = 8) -> std::vector<size_t>;

        // البحث مع فك مرجعي مزدوج (Double Dereference)
        static auto find_deref(uintptr_t base_address, const std::string& target_class,
            size_t max_offset = 0x1000, size_t alignment = 8) -> std::optional<size_t>;

        static auto get_all_names(uintptr_t address) -> std::vector<std::string>;

    private:
        // دالة مساعدة لتنظيف أسماء الكلاسات من رموز MSVC (Demangling)
        static auto clean_class_name(std::string raw_name) -> std::string;
    };

} // namespace process