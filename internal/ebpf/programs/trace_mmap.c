#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

struct gt_bpf_event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 prot;
    __u64 addr;
    __u64 len;
    __u64 ts;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int submit_mem_event(struct trace_event_raw_sys_enter *ctx)
{
    struct gt_bpf_event *ev;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }
    ev->type = 2;
    ev->pid = pid_tgid >> 32;
    ev->ppid = 0;
    ev->prot = (__u32)ctx->args[2];
    ev->addr = (__u64)ctx->args[0];
    ev->len = (__u64)ctx->args[1];
    ev->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    return submit_mem_event(ctx);
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    return submit_mem_event(ctx);
}
