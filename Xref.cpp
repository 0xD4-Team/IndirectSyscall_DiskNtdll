#include "Xref.h"
#include "memory.h"
#include <spdlog/spdlog.h>

namespace process {

    Xref::Xref() {
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
            spdlog::error("Xref: Failed to initialize Zydis decoder!");
        }
    }

    auto Xref::decode(const uint8_t* buffer, size_t length,
        ZydisDecodedInstruction& out_instruction,
        ZydisDecodedOperand* out_operands) const -> bool {
        return ZYAN_SUCCESS(
            ZydisDecoderDecodeFull(&m_decoder, buffer, length, &out_instruction, out_operands));
    }

    auto Xref::scan(uintptr_t address) const -> std::vector<uintptr_t> {
        std::vector<uintptr_t> xrefs;

        // الحصول على منطقة الـ .text للبحث فيها عن مراجع
        auto section = g_process.get_section(".text");
        if (!section) {
            spdlog::error("Xref: Could not find .text section");
            return xrefs;
        }

        const uintptr_t section_start = section->first;
        const uintptr_t section_end = section_start + section->second;

        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t current = section_start;

        while (current < section_end) {
            SIZE_T return_len = 0;

            // استخدام السيسكال بدلاً من VirtualQueryEx
            PrepSyscall("NtQueryVirtualMemory");
            NTSTATUS status = memQueryVirtual(
                g_process.get_handle(),
                reinterpret_cast<PVOID>(current),
                MemoryBasicInformation,
                &mbi,
                sizeof(mbi),
                &return_len
            );

            if (!NT_SUCCESS(status)) break;

            const uintptr_t region_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t region_end = std::min(region_start + mbi.RegionSize, section_end);

            // التحقق من صلاحيات المنطقة (يجب أن تكون مملوءة وقابلة للقراءة)
            if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)) {

                // قراءة بيانات المنطقة بالكامل (تستخدم السيسكال داخلياً)
                auto buffer = Memory::read_bytes(region_start, region_end - region_start);

                if (!buffer.empty()) {
                    uintptr_t offset = 0;
                    while (offset < buffer.size()) {
                        ZydisDecodedInstruction instruction;
                        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

                        // فك تشفير التعليمة الحالية
                        if (!decode(buffer.data() + offset, buffer.size() - offset, instruction, operands)) {
                            offset++; // في حال فشل الفك ننتقل للبايت التالي
                            continue;
                        }

                        // فحص الأوبيراندس للبحث عن إشارات للعنوان المطلوب
                        for (int i = 0; i < instruction.operand_count_visible; i++) {
                            const auto& operand = operands[i];

                            // الحالة الأولى: الوصول للذاكرة بالنسبة لـ RIP (X64 Displacement)
                            if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                operand.mem.base == ZYDIS_REGISTER_RIP &&
                                operand.mem.disp.has_displacement) {

                                uintptr_t absolute = (region_start + offset) + instruction.length + operand.mem.disp.value;
                                if (absolute == address) {
                                    xrefs.push_back(region_start + offset);
                                }
                            }
                            // الحالة الثانية: العناوين النسبية (Relative Immediate) مثل الـ CALL/JMP
                            else if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative) {
                                ZyanU64 absolute = 0;
                                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operand,
                                    region_start + offset,
                                    &absolute))) {
                                    if (absolute == address) {
                                        xrefs.push_back(region_start + offset);
                                    }
                                }
                            }
                        }

                        offset += instruction.length;
                    }
                }
            }
            current = region_end;
        }

        spdlog::info("Xref: Found {} references for address 0x{:X}", xrefs.size(), address);
        return xrefs;
    }

    auto Xref::instruction_scan(
        uintptr_t start, const std::vector<uint8_t>& buffer,
        const std::function<bool(const ZydisDecodedInstruction&, const ZydisDecodedOperand*)>&
        predicate) const -> std::optional<InstructionMatch> {

        uintptr_t offset = 0;

        while (offset < buffer.size()) {
            ZydisDecodedInstruction instruction;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            if (!decode(buffer.data() + offset, buffer.size() - offset, instruction, operands)) {
                offset++;
                continue;
            }

            if (predicate(instruction, operands)) {
                InstructionMatch match{};
                match.address = start + offset;
                match.instruction = instruction;
                std::memcpy(match.operands, operands, sizeof(operands));
                return match;
            }

            offset += instruction.length;
        }

        return std::nullopt;
    }

} // namespace process