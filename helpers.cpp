#include "helpers.h"
#include "rtti.h"
#include <spdlog/spdlog.h>
#include <algorithm>

namespace roblox {

    auto Instance::is_valid() const -> bool {
        return m_address != 0 && m_address > 0x10000 && m_address < 0x7FFFFFFFFFFF;
    }

    auto Instance::get_address() const -> uint64_t {
        return m_address;
    }


    // 1. الحصول على الاسم (ديناميكياً عبر البحث عن SSO String)
    auto Instance::get_name() const -> std::optional<std::string> {
        if (!is_valid()) return std::nullopt;

        // محاولة القراءة باستخدام الأوفست الافتراضي أولاً (Name = 0x48)
        auto name_ptr = process::Memory::read<uintptr_t>(m_address + 0x48);
        if (name_ptr && *name_ptr > 0x10000) {
            auto name = process::Memory::read_sso_string(*name_ptr);
            if (name) return name;
        }

        // إذا فشل، يمكن استخدام RTTI Scan للبحث عن أوفست الاسم (اختياري للأداء)
        return std::nullopt;
    }

    // 2. الحصول على اسم الكلاس (باستخدام محرك الـ RTTI الخاص بك)
    auto Instance::get_class_name() const -> std::optional<std::string> {
        if (!is_valid()) return std::nullopt;

        // نستخدم كلاس Rtti الذي عرفته أنت في مشروعك لعمل Scan مباشر
        auto rtti_info = process::Rtti::scan_rtti(m_address);
        if (rtti_info) {
            return rtti_info->name;
        }

        // كخطة بديلة (Fallback) نستخدم الأوفست التقليدي من الـ Descriptor
        auto descriptor = process::Memory::read<uintptr_t>(m_address + 0x18);
        if (descriptor && *descriptor > 0x10000) {
            auto class_name_ptr = process::Memory::read<uintptr_t>(*descriptor + 0x18);
            if (class_name_ptr) return process::Memory::read_sso_string(*class_name_ptr);
        }

        return std::nullopt;
    }

    // 3. الحصول على الأب (باستخدام المنطق الديناميكي لضمان التوافق)
    auto Instance::get_parent() const -> std::optional<Instance> {
        if (!is_valid()) return std::nullopt;

        static uintptr_t dynamic_parent_offset = 0;

        // إذا لم نجد الأوفست بعد، نبحث عنه مرة واحدة
        if (dynamic_parent_offset == 0) {
            for (uintptr_t off = 0x10; off < 0x120; off += 8) {
                auto potential_parent = process::Memory::read<uintptr_t>(m_address + off);
                if (!potential_parent || *potential_parent < 0x10000) continue;

                // نتحقق إذا كان الكائن الحالي موجود في أبناء هذا الأب المحتمل
                Instance test_parent(*potential_parent);
                auto children = test_parent.get_children();
                for (const auto& child : children) {
                    if (child.get_address() == m_address) {
                        dynamic_parent_offset = off;
                        break;
                    }
                }
                if (dynamic_parent_offset != 0) break;
            }
        }

        uintptr_t target_offset = (dynamic_parent_offset != 0) ? dynamic_parent_offset : 0x60;
        auto parent_addr = process::Memory::read<uintptr_t>(m_address + target_offset);

        if (parent_addr && *parent_addr > 0x10000)
            return Instance(*parent_addr);

        return std::nullopt;
    }

    // 4. الحصول على الأبناء (تم دمج منطق الـ Vector والـ Syscalls)
    auto Instance::get_children() const -> std::vector<Instance> {
        std::vector<Instance> children;
        if (!is_valid()) return children;

        // الأوفست الافتراضي للـ Children Vector هو 0x50
        auto children_vector_ptr = process::Memory::read<uintptr_t>(m_address + 0x50);
        if (!children_vector_ptr || *children_vector_ptr < 0x10000) return children;

        // في x64 الـ Vector يتكون من: [Start PTR][End PTR][Capacity PTR]
        auto start = process::Memory::read<uintptr_t>(*children_vector_ptr);
        auto end = process::Memory::read<uintptr_t>(*children_vector_ptr + 8);

        if (!start || !end || *start == 0 || *end <= *start) return children;

        uintptr_t current = *start;
        uintptr_t finish = *end;

        // تحديد الحد الأقصى لعدد الأبناء لمنع التعليق
        size_t count = (finish - current) / 16;
        if (count > 10000) count = 10000;

        for (size_t i = 0; i < count; ++i) {
            auto child_inst_ptr = process::Memory::read<uintptr_t>(current);
            if (child_inst_ptr && *child_inst_ptr > 0x10000) {
                children.emplace_back(*child_inst_ptr);
            }
            current += 16; // قفزة بمقدار 16 بايت (shared_ptr structure)
        }

        return children;
    }

    auto Instance::find_first_child(std::string_view name) const -> std::optional<Instance> {
        for (const auto& child : get_children()) {
            if (auto child_name = child.get_name(); child_name && *child_name == name)
                return child;
        }
        return std::nullopt;
    }
}

namespace process::helpers {

    auto find_pointer_by_rtti(std::string_view section_name,
        const std::vector<std::string>& class_names,
        size_t alignment)
        -> std::unordered_map<std::string, std::optional<size_t>> {

        std::unordered_map<std::string, std::optional<size_t>> results;
        std::unordered_map<std::string, std::vector<uintptr_t>> all_matches;

        auto section = g_process.get_section(section_name);
        if (!section) {
            spdlog::error("Section {} not found!", section_name);
            return results;
        }

        auto [section_start, section_size] = *section;
        uintptr_t module_base = g_process.get_module_base();

        // قراءة السيكشن بالكامل لتسريع عملية المسح
        auto buffer = Memory::read_bytes(section_start, section_size);
        if (buffer.empty()) return results;

        for (size_t offset = 0; offset <= buffer.size() - sizeof(uintptr_t); offset += alignment) {
            uintptr_t potential_ptr = *reinterpret_cast<uintptr_t*>(&buffer[offset]);
            if (potential_ptr < 0x10000) continue;

            auto rtti = Rtti::scan_rtti(potential_ptr);
            if (!rtti) continue;

            for (const auto& target : class_names) {
                bool match = (rtti->name == target);
                // فحص الكلاسات الموروثة أيضاً
                if (!match) {
                    for (const auto& base : rtti->base_classes) {
                        if (base == target) { match = true; break; }
                    }
                }

                if (match) {
                    all_matches[target].push_back((section_start + offset) - module_base);
                }
            }
        }

        for (const auto& name : class_names) {
            auto& matches = all_matches[name];
            if (matches.empty()) continue;

            // منطق خاص للـ DataModel
            if (name == "DataModel" || name == "DataModel@RBX") {
                std::sort(matches.begin(), matches.end(), std::greater<uintptr_t>());
                if (matches.size() >= 2) results[name] = matches[1];
                else results[name] = matches[0];
            }
            else {
                results[name] = matches[0];
            }
        }

        return results;
    }

    auto find_sso_string_offset(uintptr_t base_address, const std::string& target_string,
        size_t max_offset, size_t alignment, bool direct)
        -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            uintptr_t addr = base_address + offset;
            if (!direct) {
                auto ptr = Memory::read<uintptr_t>(addr);
                if (!ptr || *ptr < 0x10000) continue;
                addr = *ptr;
            }

            auto str = Memory::read_sso_string(addr);
            if (str && *str == target_string) return offset;
        }
        return std::nullopt;
    }

    auto find_string_offset(uintptr_t base_address, const std::string& target_string,
        size_t max_offset, size_t alignment, size_t max_string_length,
        bool direct) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            uintptr_t addr = base_address + offset;
            if (!direct) {
                auto ptr = Memory::read<uintptr_t>(addr);
                if (!ptr || *ptr < 0x10000) continue;
                addr = *ptr;
            }

            auto str = Memory::read_string(addr, max_string_length);
            if (str && *str == target_string) return offset;
        }
        return std::nullopt;
    }

} // namespace process::helpers
