    .text
    .global gt_hook_install_arm64
    .global gt_hook_remove_arm64
    .global gt_trampoline_arm64

// ARM64 kernel patching requires a kernel-resident component. These exported
// symbols assemble cleanly for packaging and fail closed when called directly.
gt_hook_install_arm64:
    mov x0, #-95
    ret

gt_hook_remove_arm64:
    mov x0, #-95
    ret

gt_trampoline_arm64:
    ret

    .section .note.GNU-stack,"",@progbits
