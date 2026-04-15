#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <regex>
#include <cmath>

// تضمين ملف الذاكرة لضمان رؤية كلاس Memory قبل الـ Templates
#include "memory.h"

namespace roblox {

    class Instance {
    public:
        // الأوفستات الافتراضية لروبلوكس (تأكد من تحديثها إذا تغيرت نسخة اللعبة)


        Instance() = default;
        explicit Instance(uint64_t address) : m_address(address) {};

        auto is_valid() const -> bool;
        auto get_address() const -> uint64_t;

        auto get_name() const -> std::optional<std::string>;
        auto get_class_name() const -> std::optional<std::string>;
        auto get_parent() const -> std::optional<Instance>;
        auto get_children() const -> std::vector<Instance>;

        auto find_first_child(std::string_view name) const -> std::optional<Instance>;

        template <typename T = Instance>
        auto find_first_child_of_class(std::string_view class_name) const -> std::optional<T> {
            for (const auto& child : get_children()) {
                const auto name = child.get_class_name();
                if (name && *name == class_name) {
                    return T(child.get_address());
                }
            }
            return std::nullopt;
        }

    private:
        uint64_t m_address = 0;
    };

} // namespace roblox

namespace process::helpers {

    // البحث عن عناوين الكلاسات باستخدام RTTI
    auto find_pointer_by_rtti(std::string_view section_name,
        const std::vector<std::string>& class_names,
        size_t alignment = 8)
        -> std::unordered_map<std::string, std::optional<size_t>>;

    // البحث عن نصوص SSO (Small String Optimization)
    auto find_sso_string_offset(uintptr_t base_address, const std::string& target_string,
        size_t max_offset = 0x1000, size_t alignment = 8,
        bool direct = false) -> std::optional<size_t>;

    // البحث عن النصوص العادية
    auto find_string_offset(uintptr_t base_address, const std::string& target_string,
        size_t max_offset = 0x1000, size_t alignment = 8,
        size_t max_string_length = 256, bool direct = false) -> std::optional<size_t>;

    // قالب البحث عن القيم (Generic Offset Finder)
    template <typename T>
    auto find_offset(uintptr_t base_address, const T& value, size_t max_offset = 0x1000,
        size_t alignment = 8) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            // استخدام template لتجنب خطأ C7510
            auto read_value = process::Memory::template read<T>(base_address + offset);
            if (read_value.has_value() && read_value.value() == value) {
                return offset;
            }
        }
        return std::nullopt;
    }

    // تخصص للفلوت (Float Specialty) للتعامل مع الفوارق البسيطة
    template <>
    inline auto find_offset<float>(uintptr_t base_address, const float& value, size_t max_offset,
        size_t alignment) -> std::optional<size_t> {
        constexpr float TOLERANCE = 0.0001f;
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            auto read_value = process::Memory::read<float>(base_address + offset);
            if (read_value.has_value()) {
                float val = read_value.value();
                if (!std::isnan(val) && std::abs(val - value) < TOLERANCE)
                    return offset;
            }
        }
        return std::nullopt;
    }

} // namespace process::helpers
