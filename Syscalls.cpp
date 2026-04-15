#include "syscalls.h"
#include <iostream>
#include <vector>
#include <algorithm>

// تعريف المتغيرات العالمية للربط مع الـ ASM
extern "C" DWORD SSN = 0;
extern "C" unsigned __int64 SYSCALLADDR = 0;

static std::unordered_map<std::string, ZW_ATTR> g_zwFunctions;

// دالة مساعدة لتحويل العناوين من الذاكرة (RVA) إلى مكانها في الملف على القرص (Offset)
static DWORD RvaToOffset(PIMAGE_NT_HEADERS nt, DWORD rva) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= section[i].VirtualAddress && rva < (section[i].VirtualAddress + section[i].Misc.VirtualSize)) {
            return (rva - section[i].VirtualAddress) + section[i].PointerToRawData;
        }
    }
    return 0;
}

std::unordered_map<std::string, ZW_ATTR> InitSyscallsFromDisk() {
    g_zwFunctions.clear();

    // 1. الحصول على مسار ntdll.dll من نظام التشغيل
    WCHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryW(ntdllPath, MAX_PATH);
    wcscat_s(ntdllPath, L"\\ntdll.dll");

    // 2. قراءة الملف من القرص كـ Binary
    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    DWORD fileSize = GetFileSize(hFile, NULL);
    std::vector<BYTE> fileBuffer(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, fileBuffer.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    PBYTE base = fileBuffer.data();
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    // الحصول على عنوان ntdll المحملة حالياً لاستخراج عنوان الـ syscall (0F 05) الحقيقي
    uintptr_t currentNtdll = (uintptr_t)GetModuleHandleW(L"ntdll.dll");

    DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(base + RvaToOffset(nt, exportRva));

    PDWORD namePtrs = (PDWORD)(base + RvaToOffset(nt, expDir->AddressOfNames));
    PDWORD funcPtrs = (PDWORD)(base + RvaToOffset(nt, expDir->AddressOfFunctions));
    PWORD ordPtrs = (PWORD)(base + RvaToOffset(nt, expDir->AddressOfNameOrdinals));

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        const char* funcName = (const char*)(base + RvaToOffset(nt, namePtrs[i]));

        // نبحث عن الدوال التي تبدأ بـ Zw لأنها تحتوي على أرقام السيسكال (SSN)
        if (funcName[0] == 'Z' && funcName[1] == 'w') {
            DWORD funcRva = funcPtrs[ordPtrs[i]];
            PBYTE funcCode = base + RvaToOffset(nt, funcRva);

            DWORD ssn = 0;
            bool foundSsn = false;

            // نمط 1: يبدأ بـ mov eax, SSN (B8 XX XX XX XX)
            if (funcCode[0] == 0xB8) {
                ssn = *(PDWORD)(funcCode + 1);
                foundSsn = true;
            }
            // نمط 2: يبدأ بـ mov r10, rcx ثم mov eax, SSN (4C 8B D1 B8 XX XX XX XX)
            else if (funcCode[0] == 0x4C && funcCode[1] == 0x8B && funcCode[2] == 0xD1 && funcCode[3] == 0xB8) {
                ssn = *(PDWORD)(funcCode + 4);
                foundSsn = true;
            }

            if (foundSsn) {
                // البحث عن تعليمة الـ syscall (0F 05) في الذاكرة الحقيقية
                PBYTE realFuncCode = (PBYTE)(currentNtdll + funcRva);
                PVOID syscallAddr = nullptr;

                for (int j = 0; j < 32; j++) {
                    if (realFuncCode[j] == 0x0F && realFuncCode[j + 1] == 0x05) {
                        syscallAddr = &realFuncCode[j];
                        break;
                    }
                }

                ZW_ATTR attr = { ssn, (PVOID)realFuncCode, syscallAddr };

                // تخزين الدالة باسمها الأصلي (Zw...)
                g_zwFunctions[funcName] = attr;

                // تخزين نفس الدالة باسم (Nt...) لسهولة الاستدعاء في الكود
                std::string ntName = funcName;
                ntName[0] = 'N'; ntName[1] = 't';
                g_zwFunctions[ntName] = attr;
            }
        }
    }

    std::cout << "[+] Successfully indexed " << g_zwFunctions.size() << " syscalls from disk." << std::endl;
    return g_zwFunctions;
}

void PrepSyscall(const char* funcName) {
    auto it = g_zwFunctions.find(funcName);
    if (it != g_zwFunctions.end()) {
        SSN = it->second.ssn;
        SYSCALLADDR = (unsigned __int64)it->second.syscallc;
    }
    else {
        SSN = 0;
        SYSCALLADDR = 0;
    }
}
