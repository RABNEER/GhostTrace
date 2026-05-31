default rel

section .text

global gt_hook_install
global gt_hook_remove
global gt_syscall_trampoline
global gt_trampoline_nop_sled
global gt_cmpxchg_patch32

extern gt_ring_write

%define SYS_mprotect 10
%define PROT_READ    1
%define PROT_WRITE   2
%define PROT_EXEC    4
; int gt_hook_install(void *target, void *replacement, uint8_t saved[16])
; Installs a 5-byte JMP rel32 patch on user-mapped executable memory.
; Hardened Linux kernels will reject attempts to use this against kernel
; addresses from user space, and the negative errno is returned to C.
gt_hook_install:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14

    test rdi, rdi
    jz .einval
    test rsi, rsi
    jz .einval
    test rdx, rdx
    jz .einval

    mov r12, rdi                    ; target
    mov r13, rsi                    ; replacement
    mov r14, rdx                    ; saved bytes

    mov rdi, r12
    and rdi, -4096
    mov rsi, 4096
    mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC
    mov rax, SYS_mprotect
    syscall
    test rax, rax
    js .done

    xor ecx, ecx
.save_loop:
    mov al, [r12 + rcx]
    mov [r14 + rcx], al
    inc ecx
    cmp ecx, 5
    jne .save_loop

    mov rax, r13
    sub rax, r12
    sub rax, 5
    mov byte [r12], 0xe9
    mov dword [r12 + 1], eax
    mfence

    mov rdi, r12
    and rdi, -4096
    mov rsi, 4096
    mov rdx, PROT_READ | PROT_EXEC
    mov rax, SYS_mprotect
    syscall
    test rax, rax
    js .done
    xor eax, eax
    jmp .done

.einval:
    mov rax, -22

.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; int gt_hook_remove(void *target, const uint8_t saved[16])
gt_hook_remove:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    test rdi, rdi
    jz .remove_einval
    test rsi, rsi
    jz .remove_einval

    mov r12, rdi                    ; target
    mov r13, rsi                    ; saved bytes

    mov rdi, r12
    and rdi, -4096
    mov rsi, 4096
    mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC
    mov rax, SYS_mprotect
    syscall
    test rax, rax
    js .remove_done

    xor ecx, ecx
.restore_loop:
    mov al, [r13 + rcx]
    mov [r12 + rcx], al
    inc ecx
    cmp ecx, 5
    jne .restore_loop
    mfence

    mov rdi, r12
    and rdi, -4096
    mov rsi, 4096
    mov rdx, PROT_READ | PROT_EXEC
    mov rax, SYS_mprotect
    syscall
    test rax, rax
    js .remove_done
    xor eax, eax
    jmp .remove_done

.remove_einval:
    mov rax, -22

.remove_done:
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Generic recording trampoline. It preserves caller-save registers, records
; a syscall-like event, then jumps to gt_trampoline_resume. Production syscall
; patching requires a kernel component to provide a valid resume address.
gt_syscall_trampoline:
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rdx
    push rcx
    push rax

    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r9, rax
    rdtscp
    shl rdx, 32
    or rax, rdx
    lfence

    mov r9, rax                     ; timestamp cycles
    mov rdi, [rsp]                  ; syscall number
    mov rsi, [rsp + 32]             ; arg0
    mov rdx, [rsp + 24]             ; arg1
    mov rcx, [rsp + 16]             ; arg2
    xor r8d, r8d                    ; pid unavailable in this generic recorder
    call gt_ring_write

    pop rax
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    jmp qword [gt_trampoline_resume]

align 16
gt_trampoline_nop_sled:
    pause
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ret

; int gt_cmpxchg_patch32(uint32_t *ptr, uint32_t expected, uint32_t desired)
gt_cmpxchg_patch32:
    mov eax, esi
    lock cmpxchg dword [rdi], edx
    sete al
    movzx eax, al
    ret

section .data
align 8
gt_trampoline_resume:
    dq 0

section .note.GNU-stack noalloc noexec nowrite progbits
