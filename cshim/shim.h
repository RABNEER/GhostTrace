#ifndef GHOSTTRACE_SHIM_H
#define GHOSTTRACE_SHIM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GT_RING_SIZE 65536u
#define GT_EVENT_SIZE 64u

enum gt_event_type {
    GT_EVENT_SYSCALL = 1,
    GT_EVENT_MEM = 2,
    GT_EVENT_PROCESS = 3
};

struct gt_ring_buffer {
    volatile uint64_t head;
    volatile uint64_t tail;
    uint8_t data[GT_RING_SIZE];
};

struct gt_event {
    uint8_t data[GT_EVENT_SIZE];
};

// CGo-callable bridge functions:
// int gt_ring_read(struct gt_event *out);
// struct gt_ring_buffer *gt_ring_ptr(void);
// int gt_hook_install_all(void);
// int gt_hook_remove_all(void);

struct gt_ring_buffer *gt_ring_ptr(void);
int gt_ring_read(struct gt_event *out);
int gt_ring_dropped(uint64_t *out);
int gt_hook_install_all(void);
int gt_hook_remove_all(void);

void gt_ring_write(uint32_t syscall_nr, uint64_t arg0, uint64_t arg1,
                   uint64_t arg2, uint32_t pid, uint64_t timestamp_ns);

int64_t gt_scan_region(void *start, size_t len, const uint8_t *pattern, size_t pat_len);
uint64_t gt_pmu_read_fixed(uint32_t counter_index);
long gt_pmu_init_counters(void);

int gt_hook_install(void *target, void *replacement, uint8_t saved[16]);
int gt_hook_remove(void *target, const uint8_t saved[16]);
void gt_syscall_trampoline(void);

#ifdef __cplusplus
}
#endif

#endif
