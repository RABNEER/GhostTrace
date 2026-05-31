default rel

section .text

global gt_scan_region

; int64_t gt_scan_region(void *start, size_t len, const uint8_t *pattern, size_t pat_len)
; System V ABI: rdi=start, rsi=len, rdx=pattern, rcx=pat_len
gt_scan_region:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    test rdi, rdi
    jz .not_found
    test rdx, rdx
    jz .not_found
    test rcx, rcx
    jz .not_found
    cmp rsi, rcx
    jb .not_found

    mov r12, rdi                    ; base
    mov r13, rsi                    ; len
    mov r14, rdx                    ; pattern
    mov r15, rcx                    ; pat_len

    movzx eax, byte [r14]
    movd xmm0, eax
    vpbroadcastb ymm0, xmm0

    xor rbx, rbx                    ; offset
    mov r10, r13
    sub r10, r15                    ; last valid offset

.avx_loop:
    mov rax, rbx
    add rax, 32
    cmp rax, r10
    ja .sse_tail

    vmovdqu ymm1, [r12 + rbx]
    vpcmpeqb ymm2, ymm1, ymm0
    vpmovmskb eax, ymm2
    test eax, eax
    jz .avx_next

.candidate_loop:
    bsf ecx, eax
    mov r9d, ecx
    mov r11, rbx
    add r11, rcx
    cmp r11, r10
    ja .avx_next
    push rax
    mov rdi, r12
    add rdi, r11
    mov rsi, r14
    mov rcx, r15
    repe cmpsb
    pop rax
    je .found_r11
    btr eax, r9d
    test eax, eax
    jnz .candidate_loop

.avx_next:
    add rbx, 32
    jmp .avx_loop

.sse_tail:
    ; SSE4.2 first-byte screening for the last partial chunk.
    mov r8, rbx
.sse_loop:
    cmp r8, r10
    ja .not_found_vzu
    mov r9, r10
    sub r9, r8
    inc r9
    cmp r9, 16
    jb .scalar_tail

    movdqu xmm1, [r12 + r8]
    movzx eax, byte [r14]
    movd xmm0, eax
    mov eax, 1
    mov edx, 16
    pcmpestri xmm0, xmm1, 0x00
    cmp ecx, 16
    jae .sse_advance
    mov r11, r8
    add r11, rcx
    push r8
    mov rdi, r12
    add rdi, r11
    mov rsi, r14
    mov rcx, r15
    repe cmpsb
    pop r8
    je .found_r11
.sse_advance:
    inc r8
    jmp .sse_loop

.scalar_tail:
    cmp r8, r10
    ja .not_found_vzu
    mov al, [r14]
    cmp [r12 + r8], al
    jne .scalar_next
    mov r11, r8
    push r8
    mov rdi, r12
    add rdi, r11
    mov rsi, r14
    mov rcx, r15
    repe cmpsb
    pop r8
    je .found_r11
.scalar_next:
    inc r8
    jmp .scalar_tail

.found_r11:
    vzeroupper
    mov rax, r11
    jmp .done

.not_found_vzu:
    vzeroupper
.not_found:
    mov rax, -1

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
