#pragma once
#define NOMINMAX
#include <Windows.h>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <algorithm>
#include "syscalls.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef LONG KPRIORITY;




// ============================================================================
// CLASSES
// ============================================================================
namespace process {

    class Process {
    public:
        Process() : m_handle(nullptr), m_pid(0), m_module_base(0), m_attached(false) {}
        ~Process() { if (m_handle) CloseHandle(m_handle); }

        bool attach(std::string_view process_name);
        HANDLE get_handle() const { return m_handle; }
        uintptr_t get_module_base() const { return m_module_base; }
        DWORD get_pid() const { return m_pid; }

        std::optional<std::pair<uintptr_t, size_t>> get_section(std::string_view section_name) const;
        HWND get_window_handle() const;

    private:
        HANDLE m_handle;
        DWORD m_pid;
        uintptr_t m_module_base;
        bool m_attached;

        std::optional<DWORD> find_process_by_id(std::string_view process_name);
        HANDLE nt_open_process(DWORD pid);
        bool cache_module_info();
    };

    // الكائن العمومي
    extern Process g_process;

    class Memory {
    public:
        static auto read_sso_string(uintptr_t address) -> std::optional<std::string>;
        static auto read_bytes(uintptr_t address, size_t size) -> std::vector<uint8_t>;
        static auto write_bytes(uintptr_t address, const std::vector<uint8_t>& data) -> bool;
        static auto read_string(uintptr_t address, size_t max_length) -> std::optional<std::string>;
        static auto scan_string(const std::string& target, std::string_view section = "") -> std::vector<uintptr_t>;

        template <typename T>
        static auto read(uintptr_t address) -> std::optional<T> {
            auto bytes = read_bytes(address, sizeof(T));
            if (bytes.size() != sizeof(T)) return std::nullopt;
            return *reinterpret_cast<T*>(bytes.data());
        }
    };

} // namespace process