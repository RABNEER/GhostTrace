default rel

section .text

global gt_pmu_read_fixed
global gt_pmu_init_counters

%define SYS_prctl      157
%define PR_SET_TSC     26
%define PR_TSC_ENABLE  1

; uint64_t gt_pmu_read_fixed(uint32_t counter_index)
gt_pmu_read_fixed:
    lfence
    mov ecx, edi
    or ecx, 0x40000000
    rdpmc
    shl rdx, 32
    or rax, rdx
    lfence
    ret

; long gt_pmu_init_counters(void)
gt_pmu_init_counters:
    mov eax, SYS_prctl
    mov edi, PR_SET_TSC
    mov esi, PR_TSC_ENABLE
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
