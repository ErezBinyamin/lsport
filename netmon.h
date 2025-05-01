#ifndef NETMON_H
#define NETMON_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct net_event {
    __u64 ts;
    __u32 pid;
    char comm[16];
    __u32 saddr_v4;
    __u32 daddr_v4;
    __u32 saddr_v6;
    __u32 daddr_v6;
    __u16 sport;
    __u16 dport;
    __u8 family;
    __u8 type;
};

#endif // NETMON_H
