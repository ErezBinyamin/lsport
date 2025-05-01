// netmon.c - userspace loader for netmon BPF program
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "netmon.skel.h"
#include "netmon.h"

static volatile sig_atomic_t exiting = 0;

void handle_signal(int sig) {
    exiting = 1;
}

static void handle_event(void *ctx, void *data, size_t len) {
    struct net_event *e = data;

    char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];

    if (e->family == AF_INET) {
        inet_ntop(AF_INET, &e->saddr_v4, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &e->daddr_v4, daddr, sizeof(daddr));
    } else if (e->family == AF_INET6) {
        inet_ntop(AF_INET6, &e->saddr_v6, saddr, sizeof(saddr));
        inet_ntop(AF_INET6, &e->daddr_v6, daddr, sizeof(daddr));
    } else {
        snprintf(saddr, sizeof(saddr), "?");
        snprintf(daddr, sizeof(daddr), "?");
    }

    const char *event_type = (e->type == 0) ? "conn" : "close";
    printf("%-6s %-5d %-16s %s:%d -> %s:%d\n",
           event_type,
           e->pid,
           e->comm,
           saddr,
           ntohs(e->sport),
           daddr,
           ntohs(e->dport));
}

int main() {
    struct netmon_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = netmon_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = netmon_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = netmon_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Running... Press Ctrl+C to stop.\n");
    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    netmon_bpf__destroy(skel);

    return 0;
}

