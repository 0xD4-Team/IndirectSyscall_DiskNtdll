#include "helpers.h"
#include "offsets.h"
#include "rtti.h"
#include <algorithm>
#include <spdlog/spdlog.h> // تأكد من وجود مكتبة spdlog أو استبدلها بـ printf

namespace process::helpers {

    auto Instance::is_valid() const -> bool { return m_address != 0; }

    auto Instance::get_name() const -> std::optional<std::string> {
        if (!is_valid()) {
            return std::nullopt;
        }

        const auto name_pointer =
            process::Memory::read<uintptr_t>(m_address + offsets::Instance::Name);
        if (!name_pointer) {
            return std::nullopt;
        }

        return process::Memory::read_sso_string(*name_pointer);
    }

    auto Instance::get_class_name() const -> std::optional<std::string> {
        if (!is_valid()) {
            return std::nullopt;
        }

        const auto class_descriptor =
            process::Memory::read<uintptr_t>(m_address + offsets::Instance::ClassDescriptor);

        if (!class_descriptor) {
            return std::nullopt;
        }

        const auto class_name_pointer =
            process::Memory::read<uintptr_t>(*class_descriptor + offsets::Instance::ClassName);

        if (!class_name_pointer) {
            return std::nullopt;
        }

        return process::Memory::read_sso_string(*class_name_pointer);
    }

    auto Instance::get_children() const -> std::vector<Instance> {
        std::vector<Instance> children;

        if (!is_valid()) {
            return children;
        }

        const auto start =
            process::Memory::read<uintptr_t>(m_address + offsets::Instance::ChildrenStart);
        if (!start) {
            return children;
        }

        const auto end = process::Memory::read<uintptr_t>(*start + offsets::Instance::ChildrenEnd);
        if (!end) {
            return children;
        }

        auto current = process::Memory::read<uintptr_t>(*start);
        if (!current) {
            return children;
        }

        constexpr size_t MAX = 8192;
        size_t iterations = 0;
        auto current_addr = *current;
        const auto end_addr = *end;

        while (current_addr != end_addr && iterations < MAX) {
            auto child_addr = process::Memory::read<uintptr_t>(current_addr);
            if (child_addr && *child_addr) {
                children.emplace_back(*child_addr);
            }

            current_addr += 0x10;
            ++iterations;
        }

        return children;
    }

    auto Instance::get_parent() const -> std::optional<Instance> {
        return process::Memory::read<Instance>(m_address + offsets::Instance::Parent);
    }

    auto Instance::find_first_child(std::string_view name) const -> std::optional<Instance> {
        if (!is_valid()) {
            return std::nullopt;
        }

        for (const auto& child : get_children()) {
            const auto child_name = child.get_name();
            if (child_name && *child_name == name) {
                return child;
            }
        }

        return std::nullopt;
    }

    auto Instance::get_address() const -> std::uint64_t { return m_address; };
    ///////////////////////////////////////////////////////////////////////////////////
    auto find_pointer_by_rtti(std::string_view section_name,
        const std::vector<std::string>& class_names, size_t alignment)
        -> std::unordered_map<std::string, std::optional<size_t>> {
        std::unordered_map<std::string, std::optional<size_t>> results;
        std::unordered_map<std::string, std::vector<uintptr_t>> all_matches;

        for (const auto& class_name : class_names) {
            results[class_name] = std::nullopt;
            all_matches[class_name] = {};
        }

        auto section = process::g_process.get_section(section_name);
        if (!section) {
            spdlog::error("Failed to find section: {}", section_name);
            return results;
        }

        auto [section_start, section_size] = *section;
        auto module_base = process::g_process.get_module_base();

        for (size_t offset = 0; offset < section_size; offset += alignment) {
            auto potential_ptr = process::Memory::read<uintptr_t>(section_start + offset);
            if (!potential_ptr || *potential_ptr < 0x10000) {
                continue;
            }

            auto rtti = process::Rtti::scan_rtti(*potential_ptr);
            if (!rtti) {
                continue;
            }

            for (const auto& class_name : class_names) {
                if (rtti->name == class_name) {
                    size_t final_offset = (section_start + offset) - module_base;
                    all_matches[class_name].push_back(final_offset);
                }
            }
        }

        for (const auto& class_name : class_names) {
            auto& matches = all_matches[class_name];

            if (matches.empty()) {
                spdlog::warn("Failed to find class: {}", class_name);
                continue;
            }

            if (class_name == "DataModel@RBX") {
                std::sort(matches.begin(), matches.end(),
                    [](uintptr_t a, uintptr_t b) { return a > b; });

                if (matches.size() >= 2) {
                    results[class_name] = matches[1];
                }
                else {
                    spdlog::warn("Found DataModel but not enough instances");
                }
            }
            else {
                results[class_name] = matches[0];
            }
        }

        return results;
    }

    auto find_sso_string_offset(uintptr_t base_address, const std::string& target_string,
        size_t max_offset, size_t alignment, bool direct)
        -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            if (direct) {
                auto str = Memory::read_sso_string(base_address + offset);
                if (str && *str == target_string) {
                    return offset;
                }
            }
            else {
                auto string_ptr = Memory::read<uintptr_t>(base_address + offset);
                if (!string_ptr || *string_ptr < 0x10000) {
                    continue;
                }

                auto str = Memory::read_sso_string(*string_ptr);
                if (str && *str == target_string) {
                    return offset;
                }
            }
        }

        return std::nullopt;
    }

    auto find_string_offset(uintptr_t base_address, const std::string& target_string,
        size_t max_offset, size_t alignment, size_t max_string_length,
        bool direct) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            if (direct) {
                auto str = Memory::read_string(base_address + offset, max_string_length);
                if (str && *str == target_string) {
                    return offset;
                }
            }
            else {
                auto string_ptr = Memory::read<uintptr_t>(base_address + offset);
                if (!string_ptr || *string_ptr < 0x10000) {
                    continue;
                }

                auto str = Memory::read_string(*string_ptr, max_string_length);
                if (str && *str == target_string) {
                    return offset;
                }
            }
        }

        return std::nullopt;
    }

    auto find_string_by_regex(uintptr_t base_address, const std::string& regex_pattern,
        size_t max_offset, size_t alignment, size_t max_string_length,
        bool direct) -> std::optional<size_t> {
        std::regex pattern(regex_pattern);

        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            if (direct) {
                auto str = Memory::read_string(base_address + offset, max_string_length);
                if (str && std::regex_match(*str, pattern)) {
                    return offset;
                }
            }
            else {
                auto string_ptr = Memory::read<uintptr_t>(base_address + offset);
                if (!string_ptr || *string_ptr < 0x10000) {
                    continue;
                }

                auto str = Memory::read_string(*string_ptr, max_string_length);
                if (str && std::regex_match(*str, pattern)) {
                    return offset;
                }
            }
        }

        return std::nullopt;
    }

    auto find_pointer_offset(uintptr_t base_address, uintptr_t target_pointer, size_t max_offset,
        size_t alignment) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            auto ptr = Memory::read<uintptr_t>(base_address + offset);
            if (ptr && *ptr == target_pointer) {
                return offset;
            }
        }
        return std::nullopt;
    }

    auto find_color3_offset(const std::vector<uintptr_t>& addresses,
        std::function<std::tuple<uint8_t, uint8_t, uint8_t>(size_t)> get_rgb,
        size_t max_offset) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += 1) {
            bool all_match = true;

            for (size_t i = 0; i < addresses.size(); i++) {
                auto [exp_r, exp_g, exp_b] = get_rgb(i);

                auto r = Memory::read<uint8_t>(addresses[i] + offset);
                auto g = Memory::read<uint8_t>(addresses[i] + offset + 1);
                auto b = Memory::read<uint8_t>(addresses[i] + offset + 2);

                if (!r || !g || !b || *r != exp_r || *g != exp_g || *b != exp_b) {
                    all_match = false;
                    break;
                }
            }

            if (all_match) {
                return offset;
            }
        }

        return std::nullopt;
    }

} // namespace process::helpers
