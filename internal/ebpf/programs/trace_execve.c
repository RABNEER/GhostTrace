#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    struct gt_bpf_event *ev;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }
    ev->type = 1;
    ev->pid = pid_tgid >> 32;
    ev->ppid = 0;
    ev->prot = 0;
    ev->addr = 0;
    ev->len = 0;
    ev->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_execve_exit(void *ctx)
{
    return 0;
}
