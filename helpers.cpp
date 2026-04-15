#include "helpers.h"
#include "rtti.h"
#include <spdlog/spdlog.h>
#include <algorithm>

namespace roblox {

    auto Instance::is_valid() const -> bool {
        return m_address != 0 && m_address > 0x10000;
    }

    auto Instance::get_address() const -> uint64_t {
        return m_address;
    }

    auto Instance::get_name() const -> std::optional<std::string> {
        if (!is_valid()) return std::nullopt;
        auto name_ptr = process::Memory::read<uintptr_t>(m_address + Offsets::Name);
        if (!name_ptr || *name_ptr < 0x10000) return std::nullopt;
        return process::Memory::read_sso_string(*name_ptr);
    }

    auto Instance::get_class_name() const -> std::optional<std::string> {
        if (!is_valid()) return std::nullopt;
        auto descriptor = process::Memory::read<uintptr_t>(m_address + Offsets::ClassDescriptor);
        if (!descriptor || *descriptor < 0x10000) return std::nullopt;

        auto class_name_ptr = process::Memory::read<uintptr_t>(*descriptor + Offsets::ClassName);
        if (!class_name_ptr || *class_name_ptr < 0x10000) return std::nullopt;

        return process::Memory::read_sso_string(*class_name_ptr);
    }

    auto Instance::get_parent() const -> std::optional<Instance> {
        if (!is_valid()) return std::nullopt;
        auto parent_addr = process::Memory::read<uintptr_t>(m_address + Offsets::Parent);
        if (!parent_addr || *parent_addr < 0x10000) return std::nullopt;
        return Instance(*parent_addr);
    }

    auto Instance::get_children() const -> std::vector<Instance> {
        std::vector<Instance> children;
        if (!is_valid()) return children;

        auto children_ptr = process::Memory::read<uintptr_t>(m_address + Offsets::ChildrenStart);
        if (!children_ptr || *children_ptr < 0x10000) return children;

        auto start = process::Memory::read<uintptr_t>(*children_ptr);
        auto end = process::Memory::read<uintptr_t>(*children_ptr + Offsets::ChildrenEnd);

        if (!start || !end || *start == 0) return children;

        uintptr_t current = *start;
        uintptr_t last = *end;

        // حماية: روبلوكس قد يحتوي على آلاف الأبناء، نضع حداً لمنع تجميد البرنامج
        for (int i = 0; i < 10000 && current < last; ++i) {
            auto child_inst = process::Memory::read<uintptr_t>(current);
            if (child_inst && *child_inst > 0x10000) {
                children.emplace_back(*child_inst);
            }
            current += 16; // x64 vector padding (shared_ptr size)
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