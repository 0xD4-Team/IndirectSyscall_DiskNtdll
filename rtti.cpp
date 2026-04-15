#include "rtti.h"
#include "memory.h"
#include <cstring>
#include <spdlog/spdlog.h>

namespace process {

    auto Rtti::clean_class_name(std::string raw_name) -> std::string {
        // تنظيف بادئة ".?AV" (Class) أو ".?AU" (Struct)
        if (raw_name.size() > 4 && (raw_name.substr(0, 4) == ".?AV" || raw_name.substr(0, 4) == ".?AU")) {
            raw_name = raw_name.substr(4);
        }

        // إزالة اللاحقة "@@" وما بعدها
        size_t at_pos = raw_name.find("@@");
        if (at_pos != std::string::npos) {
            raw_name = raw_name.substr(0, at_pos);
        }

        return raw_name;
    }

    auto Rtti::scan_rtti(uintptr_t address) -> std::optional<RttiInfo> {
        // 1. قراءة الـ vtable
        auto vtable = Memory::read<uintptr_t>(address);
        if (!vtable || *vtable < 0x10000) return std::nullopt;

        // 2. الـ COL يقع قبل الـ vtable بـ 8 بايت في x64
        auto col_ptr = Memory::read<uintptr_t>(*vtable - 0x8);
        if (!col_ptr || *col_ptr < 0x10000) return std::nullopt;

        // 3. قراءة الـ COL structure بالكامل
        auto col = Memory::read<RttiCompleteObjectLocatorX64>(*col_ptr);
        if (!col || col->signature != 1) return std::nullopt; // signature 1 = x64

        // 4. حساب Image Base (العنوان الأساسي للموديل)
        // في x64، الـ self_offset يخبرنا أين يقع الـ COL بالنسبة لبداية الملف
        uintptr_t module_base = *col_ptr - col->self_offset;

        RttiInfo info{};
        info.type_descriptor = module_base + col->type_descriptor_offset;
        info.class_hierarchy_descriptor = module_base + col->class_descriptor_offset;

        // 5. قراءة اسم الكلاس من الـ Type Descriptor
        auto td_name_ptr = info.type_descriptor + offsetof(TypeDescriptor, name);
        auto raw_name_opt = Memory::read_string(td_name_ptr, 255);

        if (raw_name_opt) {
            info.name = clean_class_name(*raw_name_opt);
            // 6. جلب أسماء الكلاسات الموروثة (Base Classes)
            info.base_classes = get_all_names(address);
            return info;
        }

        return std::nullopt;
    }

    auto Rtti::get_all_names(uintptr_t address) -> std::vector<std::string> {
        std::vector<std::string> names;

        auto vtable = Memory::read<uintptr_t>(address);
        if (!vtable) return names;

        auto col_ptr = Memory::read<uintptr_t>(*vtable - 0x8);
        if (!col_ptr) return names;

        auto col = Memory::read<RttiCompleteObjectLocatorX64>(*col_ptr);
        if (!col || col->signature != 1) return names;

        uintptr_t module_base = *col_ptr - col->self_offset;

        auto hierarchy = Memory::read<RttiClassHierarchyDescriptor>(module_base + col->class_descriptor_offset);
        if (!hierarchy || hierarchy->numBaseClasses == 0 || hierarchy->numBaseClasses > 64)
            return names;

        uintptr_t base_class_table = module_base + hierarchy->pBaseClassArray;

        for (uint32_t i = 0; i < hierarchy->numBaseClasses; i++) {
            auto base_offset = Memory::read<uint32_t>(base_class_table + (sizeof(uint32_t) * i));
            if (!base_offset) break;

            auto base_class_desc = Memory::read<RttiBaseClassDescriptor>(module_base + *base_offset);
            if (!base_class_desc) continue;

            auto td_ptr = module_base + base_class_desc->pTypeDescriptor;
            auto raw_name = Memory::read_string(td_ptr + offsetof(TypeDescriptor, name), 255);

            if (raw_name) {
                names.push_back(clean_class_name(*raw_name));
            }
        }

        return names;
    }

    auto Rtti::find(uintptr_t base_address, const std::string& target_class, size_t max_offset, size_t alignment) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            auto pointer_value = Memory::read<uintptr_t>(base_address + offset);
            if (!pointer_value || *pointer_value < 0x10000) continue;

            auto rtti = scan_rtti(base_address + offset);
            if (rtti && (rtti->name == target_class)) {
                return offset;
            }
        }
        return std::nullopt;
    }

    auto Rtti::find_all(uintptr_t base_address, const std::string& target_class, size_t max_offset, size_t alignment) -> std::vector<size_t> {
        std::vector<size_t> matches;
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            auto rtti = scan_rtti(base_address + offset);
            if (rtti && (rtti->name == target_class)) {
                matches.push_back(offset);
            }
        }
        return matches;
    }

    auto Rtti::find_deref(uintptr_t base_address, const std::string& target_class, size_t max_offset, size_t alignment) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            auto ptr = Memory::read<uintptr_t>(base_address + offset);
            if (!ptr || *ptr < 0x10000) continue;

            // فك التشفير المزدوج غالباً ما يستخدم في هياكل مثل GameObject -> Instance
            auto rtti = scan_rtti(*ptr);
            if (rtti) {
                if (rtti->name.find(target_class) != std::string::npos) return offset;

                for (const auto& base_name : rtti->base_classes) {
                    if (base_name.find(target_class) != std::string::npos) return offset;
                }
            }
        }
        return std::nullopt;
    }

} // namespace process