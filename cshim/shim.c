#define _GNU_SOURCE

#include "shim.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define GT_FRAME_MASK (GT_RING_SIZE - 1u)
#define GT_MAX_HOOKS 8u

struct gt_hook_record {
    char name[64];
    void *addr;
    uint8_t saved[16];
    int installed;
};

static struct gt_ring_buffer *g_ring;
static volatile uint64_t g_dropped;
static struct gt_hook_record g_hooks[GT_MAX_HOOKS];
static size_t g_hook_count;

static void gt_log_errno(const char *operation, int err)
{
    fprintf(stderr, "ghosttrace shim: %s failed: %s (%d)\n", operation, strerror(err), err);
}

static void gt_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void gt_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void gt_put_u64(uint8_t *p, uint64_t v)
{
    for (unsigned int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (i * 8u)) & 0xffu);
    }
}

static void gt_copy_in(uint64_t offset, const uint8_t frame[GT_EVENT_SIZE])
{
    uint64_t pos = offset & GT_FRAME_MASK;
    uint64_t first = GT_RING_SIZE - pos;
    if (first >= GT_EVENT_SIZE) {
        memcpy(&g_ring->data[pos], frame, GT_EVENT_SIZE);
        return;
    }
    memcpy(&g_ring->data[pos], frame, first);
    memcpy(&g_ring->data[0], frame + first, GT_EVENT_SIZE - first);
}

static void gt_copy_out(uint64_t offset, uint8_t frame[GT_EVENT_SIZE])
{
    uint64_t pos = offset & GT_FRAME_MASK;
    uint64_t first = GT_RING_SIZE - pos;
    if (first >= GT_EVENT_SIZE) {
        memcpy(frame, &g_ring->data[pos], GT_EVENT_SIZE);
        return;
    }
    memcpy(frame, &g_ring->data[pos], first);
    memcpy(frame + first, &g_ring->data[0], GT_EVENT_SIZE - first);
}

__attribute__((constructor))
static void gt_ring_init(void)
{
    void *mem = mmap(NULL, sizeof(struct gt_ring_buffer), PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        gt_log_errno("mmap ring buffer", errno);
        g_ring = NULL;
        return;
    }
    g_ring = (struct gt_ring_buffer *)mem;
    memset(g_ring, 0, sizeof(*g_ring));
}

__attribute__((destructor))
static void gt_ring_destroy(void)
{
    if (g_ring != NULL) {
        if (munmap(g_ring, sizeof(*g_ring)) != 0) {
            gt_log_errno("munmap ring buffer", errno);
        }
        g_ring = NULL;
    }
}

struct gt_ring_buffer *gt_ring_ptr(void)
{
    return g_ring;
}

int gt_ring_dropped(uint64_t *out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = __atomic_load_n(&g_dropped, __ATOMIC_RELAXED);
    return 0;
}

void gt_ring_write(uint32_t syscall_nr, uint64_t arg0, uint64_t arg1,
                   uint64_t arg2, uint32_t pid, uint64_t timestamp_ns)
{
    if (g_ring == NULL) {
        __atomic_add_fetch(&g_dropped, 1, __ATOMIC_RELAXED);
        return;
    }

    uint8_t frame[GT_EVENT_SIZE];
    memset(frame, 0, sizeof(frame));
    gt_put_u16(frame, (uint16_t)GT_EVENT_SYSCALL);
    gt_put_u16(frame + 2, (uint16_t)GT_EVENT_SIZE);
    gt_put_u32(frame + 4, syscall_nr);
    gt_put_u32(frame + 8, pid);
    gt_put_u64(frame + 16, arg0);
    gt_put_u64(frame + 24, arg1);
    gt_put_u64(frame + 32, arg2);
    gt_put_u64(frame + 40, timestamp_ns);

    uint64_t head = __atomic_load_n(&g_ring->head, __ATOMIC_RELAXED);
    uint64_t tail = __atomic_load_n(&g_ring->tail, __ATOMIC_ACQUIRE);
    if ((head - tail) > (GT_RING_SIZE - GT_EVENT_SIZE)) {
        __atomic_add_fetch(&g_dropped, 1, __ATOMIC_RELAXED);
        return;
    }

    gt_copy_in(head, frame);
    __atomic_store_n(&g_ring->head, head + GT_EVENT_SIZE, __ATOMIC_RELEASE);
}

int gt_ring_read(struct gt_event *out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (g_ring == NULL) {
        errno = ENODEV;
        return -1;
    }

    uint64_t tail = __atomic_load_n(&g_ring->tail, __ATOMIC_RELAXED);
    uint64_t head = __atomic_load_n(&g_ring->head, __ATOMIC_ACQUIRE);
    if (tail == head) {
        return 0;
    }

    gt_copy_out(tail, out->data);
    __atomic_store_n(&g_ring->tail, tail + GT_EVENT_SIZE, __ATOMIC_RELEASE);
    return 1;
}

static int gt_symbol_interesting(const char *name)
{
    static const char *wanted[] = {
        "__x64_sys_execve",
        "__x64_sys_execveat",
        "__x64_sys_mmap",
        "__x64_sys_mprotect",
        "__x64_sys_clone",
        "__x64_sys_clone3",
        "__x64_sys_exit",
        "__x64_sys_exit_group",
    };

    for (size_t i = 0; i < sizeof(wanted) / sizeof(wanted[0]); i++) {
        if (strcmp(name, wanted[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int gt_load_kallsyms(void)
{
    FILE *fp = fopen("/proc/kallsyms", "re");
    if (fp == NULL) {
        gt_log_errno("open /proc/kallsyms", errno);
        return -errno;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL && g_hook_count < GT_MAX_HOOKS) {
        unsigned long long addr = 0;
        char name[128];
        if (sscanf(line, "%llx %*c %127s", &addr, name) != 2) {
            continue;
        }
        if (addr == 0 || !gt_symbol_interesting(name)) {
            continue;
        }

        struct gt_hook_record *rec = &g_hooks[g_hook_count++];
        memset(rec, 0, sizeof(*rec));
        size_t name_len = strnlen(name, sizeof(rec->name) - 1u);
        memcpy(rec->name, name, name_len);
        rec->name[name_len] = '\0';
        rec->addr = (void *)(uintptr_t)addr;
    }

    if (ferror(fp)) {
        int err = errno;
        fclose(fp);
        gt_log_errno("read /proc/kallsyms", err);
        return -err;
    }
    fclose(fp);

    if (g_hook_count == 0) {
        fprintf(stderr, "ghosttrace shim: no hookable syscall symbols found in /proc/kallsyms; kptr_restrict or lockdown may be enabled\n");
        return -EACCES;
    }
    return 0;
}

int gt_hook_install_all(void)
{
    if (g_hook_count == 0) {
        int rc = gt_load_kallsyms();
        if (rc != 0) {
            return rc;
        }
    }

    int installed = 0;
    for (size_t i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].installed) {
            installed++;
            continue;
        }
        int rc = gt_hook_install(g_hooks[i].addr, (void *)gt_syscall_trampoline, g_hooks[i].saved);
        if (rc != 0) {
            int err = rc < 0 ? -rc : rc;
            if (err == EFAULT || err == EACCES || err == EPERM || err == ENOMEM) {
                gt_log_errno(g_hooks[i].name, err);
                continue;
            }
            gt_log_errno(g_hooks[i].name, err);
            continue;
        }
        g_hooks[i].installed = 1;
        installed++;
    }

    if (installed == 0) {
        fprintf(stderr, "ghosttrace shim: native syscall patching was refused by the host; use --mode=ebpf or --mode=hybrid\n");
        return -EPERM;
    }
    return 0;
}

int gt_hook_remove_all(void)
{
    int first_error = 0;
    for (size_t i = 0; i < g_hook_count; i++) {
        if (!g_hooks[i].installed) {
            continue;
        }
        int rc = gt_hook_remove(g_hooks[i].addr, g_hooks[i].saved);
        if (rc != 0 && first_error == 0) {
            first_error = rc;
        }
        if (rc == 0) {
            g_hooks[i].installed = 0;
        }
    }
    return first_error;
}
