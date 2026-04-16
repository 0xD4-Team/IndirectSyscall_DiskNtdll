; Syscalls.asm - الالتزام بنفس هيكل المشروع المرسل مع دعم الـ Indirect Jump
.data
    EXTERN SSN: DWORD
    EXTERN SYSCALLADDR: QWORD

.code 

memQueryVirtual PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
memQueryVirtual ENDP

memAllocate PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
memAllocate ENDP

memWrite PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
memWrite ENDP

memProtect PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
memProtect ENDP

memCreateTEx PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
memCreateTEx ENDP

memRead PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
memRead  ENDP

memOpen PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
memOpen  ENDP

memQuerySysInfo PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
memQuerySysInfo  ENDP

memQueryInfoProcess PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
memQueryInfoProcess  ENDP



; إضافة دالة عامة لاستدعاء أي شيء آخر (مثل QuerySystemInformation)
InternalIndirectSyscall PROC
    mov r10, rcx
    mov eax, SSN
    jmp SYSCALLADDR
InternalIndirectSyscall ENDP

end
