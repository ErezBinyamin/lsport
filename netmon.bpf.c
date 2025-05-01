// netmon.bpf.c - eBPF program for basic network monitoring (ring buffer version)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct net_event {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char event[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} events SEC(".maps");

static __always_inline int trace_connect(struct sock *sk, const char *evname) {
    struct net_event *ev;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = pid_tgid >> 32;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_probe_read_kernel(&ev->saddr, sizeof(ev->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&ev->daddr, sizeof(ev->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&ev->sport, sizeof(ev->sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&ev->dport, sizeof(ev->dport), &sk->__sk_common.skc_dport);

    __builtin_memcpy(&ev->event, evname, 6);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk) {
    return trace_connect(sk, "conn");
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk) {
    return trace_connect(sk, "close");
}

