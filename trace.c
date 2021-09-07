# define BPF program
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "bpf_thingy"
#endif

#include <linux/kconfig.h>
#include <linux/version.h>
#pragma GCC diagnostic ignored "-Wframe-address"
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>


struct bpf_map_def SEC("maps/tcp_rcv_event") tcp_rcv_event = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(u32),
        .max_entries = 1024,
        .pinning = 0,
        .namespace = "",
};

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs *ctx) {
    int state = (int) PT_REGS_PARM2(ctx);
    if (state != TCP_ESTABLISHED)
        return 0;

    struct rcv_event_t {
        __u16 sport;
        __u16 dport;
        __u32 saddr;
        __u32 daddr;
        __u32 rtt;
    };

    __u32 srtt;
    unsigned char old_state;
    __u32 cpu = bpf_get_smp_processor_id();
    struct sock *sk = (void*) PT_REGS_PARM1(ctx);
    bpf_probe_read(&old_state, sizeof(old_state), (void *)&sk->sk_state);

    struct tcp_sock *ts = tcp_sk(sk);
    bpf_probe_read(&srtt, sizeof(__u32), &ts->srtt_us);

    // we're interested only in connections we initialized
    if (old_state != TCP_SYN_SENT)
        return 0;

    struct rcv_event_t rcv_event = {
        .rtt = srtt >> 3,
    };

    const struct inet_sock *inet = inet_sk(sk);

    bpf_probe_read(&rcv_event.sport, sizeof(rcv_event.sport), (void *)&inet->inet_sport);
    bpf_probe_read(&rcv_event.dport, sizeof(rcv_event.dport), (void *)&inet->inet_dport);
    bpf_probe_read(&rcv_event.saddr, sizeof(rcv_event.saddr), (void *)&inet->inet_saddr);
    bpf_probe_read(&rcv_event.daddr, sizeof(rcv_event.daddr), (void *)&inet->inet_daddr);

    // IP addresses are converted in the userspace
    rcv_event.sport = ntohs(rcv_event.sport);
    rcv_event.dport = ntohs(rcv_event.dport);

    if (rcv_event.saddr == rcv_event.daddr)
        return 0;

    bpf_perf_event_output(ctx, &tcp_rcv_event, cpu, &rcv_event, sizeof(rcv_event));
    return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
