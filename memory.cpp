#include "memory.h"
#define NOMINMAX
#include <Windows.h>
#include <cwctype>
#include <sstream>
#include <iomanip>
#include <Zydis/Zydis.h> 
#include <corecrt_io.h>

// تعريف الـ Struct بشكل يدوي لضمان عدم وجود نقص في الأعضاء

#pragma comment(lib, "Zydis.lib")
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER QuitOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER QuitTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

namespace process {

    // تعريف الكائن العمومي
    Process g_process;



    auto Memory::read_bytes(uintptr_t address, size_t size) -> std::vector<uint8_t> {
        if (!address || size == 0) return {};

        PrepSyscall("NtReadVirtualMemory");

        std::vector<uint8_t> buffer(size);
        SIZE_T bytes_read = 0;

        NTSTATUS status = memRead(g_process.get_handle(), reinterpret_cast<PVOID>(address),
            buffer.data(), size, &bytes_read);

        // تصحيح: حتى لو فشل السيسكال، نتحقق مما إذا تم قراءة أي بيانات
        if (!NT_SUCCESS(status) || bytes_read == 0) return {};

        // إذا تم قراءة جزء فقط من البيانات، نقوم بتقليص الـ vector للحجم الفعلي
        if (bytes_read != size) buffer.resize(bytes_read);

        return buffer;
    }

    auto Memory::write_bytes(uintptr_t address, const std::vector<uint8_t>& data) -> bool {
        if (!address || data.empty()) return false;

        PrepSyscall("NtWriteVirtualMemory");

        SIZE_T bytes_written = 0;
        NTSTATUS status = memWrite(g_process.get_handle(), reinterpret_cast<PVOID>(address),
            const_cast<uint8_t*>(data.data()), data.size(), &bytes_written);

        return NT_SUCCESS(status) && bytes_written == data.size();
    }

    auto Memory::read_string(uintptr_t address, size_t max_length) -> std::optional<std::string> {
        if (!address) return std::nullopt;

        auto bytes = read_bytes(address, max_length);
        if (bytes.empty()) return std::nullopt;

        // البحث عن نهاية النص (Null terminator)
        auto null_pos = std::find(bytes.begin(), bytes.end(), '\0');
        return std::string(bytes.begin(), null_pos);
    }

    auto Memory::read_sso_string(uintptr_t address) -> std::optional<std::string> {
        if (!address) return std::nullopt;

        // قراءة الـ Length والـ Capacity أولاً
        auto length = read<size_t>(address + 0x10);
        auto capacity = read<size_t>(address + 0x18);

        if (!length || *length == 0 || *length > 0xFFFF) return std::nullopt;

        // إذا كان النص طويل (Large String)
        if (capacity && *capacity >= 16) {
            auto remote_buffer = read<uintptr_t>(address);
            if (!remote_buffer) return std::nullopt;

            return read_string(*remote_buffer, *length);
        }

        // إذا كان النص قصير (Small String Optimization)
        return read_string(address, *length);
    }

    auto Memory::scan_string(const std::string& target, std::string_view section) -> std::vector<uintptr_t> {
        std::vector<uintptr_t> matches;
        if (target.empty()) return matches;

        // الحالة الأولى: البحث داخل سيكشن معين (أسرع بكثير)
        if (!section.empty()) {
            auto sec = g_process.get_section(section);
            if (!sec) return matches;

            auto buffer = read_bytes(sec->first, sec->second);
            if (buffer.size() < target.size()) return matches;

            for (size_t offset = 0; offset <= buffer.size() - target.size(); offset++) {
                if (std::memcmp(buffer.data() + offset, target.data(), target.size()) == 0) {
                    matches.push_back(sec->first + offset);
                }
            }
            return matches;
        }

        // الحالة الثانية: المسح الكامل للذاكرة (Full Memory Scan)
        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t current = 0; // يفضل البدء من 0 للمسح الشامل أو module base للسرعة
        SIZE_T res_len = 0;

        while (true) {
            PrepSyscall("NtQueryVirtualMemory");
            NTSTATUS status = memQueryVirtual(g_process.get_handle(), reinterpret_cast<PVOID>(current),
                MemoryBasicInformation, &mbi, sizeof(mbi), &res_len);

            if (!NT_SUCCESS(status)) break;

            // التحقق من صلاحيات المنطقة: متصلة، ليست حامية، وقابلة للقراءة
            if (mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_GUARD) &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

                auto buffer = read_bytes(reinterpret_cast<uintptr_t>(mbi.BaseAddress), mbi.RegionSize);

                if (buffer.size() >= target.size()) {
                    for (size_t offset = 0; offset <= buffer.size() - target.size(); offset++) {
                        if (std::memcmp(buffer.data() + offset, target.data(), target.size()) == 0) {
                            matches.push_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + offset);
                        }
                    }
                }
            }

            uintptr_t next_address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (next_address <= current) break; // منع الحلقات اللانهائية
            current = next_address;
        }
        return matches;
    }

    // ========================================================================
    // دوال Process
    // ========================================================================
    auto Process::attach(std::string_view process_name) -> bool {
        if (m_attached && m_handle) {
            CloseHandle(m_handle);
            m_handle = nullptr;
        }

        const auto pid = find_process_by_id(process_name);
        if (!pid) return false;

        m_pid = *pid;
        m_handle = nt_open_process(m_pid);

        if (!m_handle) return false;

        if (!cache_module_info()) {
            CloseHandle(m_handle);
            m_handle = nullptr;
            return false;
        }

        m_attached = true;
        return true;
    }

    auto Process::find_process_by_id(std::string_view process_name) -> std::optional<DWORD> {
        PrepSyscall("NtQuerySystemInformation");

        ULONG size = 0;
        memQuerySysInfo(SystemProcessInformation, nullptr, 0, &size);

        auto buffer = std::make_unique<uint8_t[]>(size);
        if (!NT_SUCCESS(memQuerySysInfo(SystemProcessInformation, buffer.get(), size, &size)))
            return std::nullopt;

        auto current = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.get());
        std::wstring target_name(process_name.begin(), process_name.end());

        while (true) {
            if (current->ImageName.Buffer && _wcsicmp(current->ImageName.Buffer, target_name.c_str()) == 0)
                return static_cast<DWORD>(reinterpret_cast<uintptr_t>(current->UniqueProcessId));

            if (!current->NextEntryOffset) break;
            current = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>((uint8_t*)current + current->NextEntryOffset);
        }
        return std::nullopt;
    }

    auto Process::nt_open_process(DWORD pid) -> HANDLE {
        PrepSyscall("NtOpenProcess");

        OBJECT_ATTRIBUTES obj_attr{};
        obj_attr.Length = sizeof(obj_attr);
        CLIENT_ID client_id{ (HANDLE)static_cast<uintptr_t>(pid), nullptr };

        HANDLE h = nullptr;
        NTSTATUS status = memOpen(&h, PROCESS_ALL_ACCESS, &obj_attr, &client_id);
        return NT_SUCCESS(status) ? h : nullptr;
    }

    auto Process::cache_module_info() -> bool {
        PrepSyscall("NtQueryInformationProcess");

        PROCESS_BASIC_INFORMATION pbi{};
        ULONG len = 0;
        if (!NT_SUCCESS(memQueryInfoProcess(m_handle, ProcessBasicInformation, &pbi, sizeof(pbi), &len)))
            return false;

        // قراءة ImageBaseAddress من الـ PEB مباشرة عبر السيسكال
        // Offset 0x10 في الـ PEB للـ x64 هو ImageBaseAddress
        auto base = Memory::read<uintptr_t>(reinterpret_cast<uintptr_t>(pbi.PebBaseAddress) + 0x10);
        if (base) {
            m_module_base = *base;
            return true;
        }
        return false;
    }

    auto Process::get_section(std::string_view section_name) const -> std::optional<std::pair<uintptr_t, size_t>> {
        if (!m_module_base) return std::nullopt;

        auto dos = Memory::read<IMAGE_DOS_HEADER>(m_module_base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

        auto nt = Memory::read<IMAGE_NT_HEADERS64>(m_module_base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return std::nullopt;

        uintptr_t section_addr = m_module_base + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64);

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            auto sec = Memory::read<IMAGE_SECTION_HEADER>(section_addr + (i * sizeof(IMAGE_SECTION_HEADER)));
            if (!sec) continue;

            char name[9]{};
            std::memcpy(name, sec->Name, 8);
            if (section_name == name)
                return std::make_pair(m_module_base + sec->VirtualAddress, sec->Misc.VirtualSize);
        }
        return std::nullopt;
    }

    auto Process::get_window_handle() const -> HWND {
        // FindWindowA و EnumWindows لا تترك أثراً في ذاكرة العملية المستهدفة
        // لذا هي آمنة نسبياً للاستخدام العادي.
        HWND hwnd = FindWindowA(nullptr, "Roblox");
        if (hwnd) {
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == m_pid) return hwnd;
        }
        return nullptr;
    }
} // namespace process