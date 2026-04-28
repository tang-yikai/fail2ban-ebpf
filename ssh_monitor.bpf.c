//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

struct ssh_fail_event {
    __u32 pid;
    __u32 remote_ip;
    __u32 ret_code;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 128);
} monitored_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10240);
} pid_to_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// --- 核心修改：在 accept 返回时获取 IP ---
// 此时进程上下文一定是 sshd 主进程
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_accept_return, struct sock *newsk) {
    if (!newsk) return 0;

    // 获取本地端口，确保是 22 端口
    // skc_num 是本地端口（主机字节序）
    __u16 lport = BPF_CORE_READ(newsk, __sk_common.skc_num);
    
    if (!bpf_map_lookup_elem(&monitored_ports, &lport)) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 daddr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);

    // 记录：sshd 主进程 PID -> 攻击者 IP
    bpf_map_update_elem(&pid_to_ip, &pid, &daddr, BPF_ANY);
    
    // 调试打印
    bpf_printk("Accept: PID=%d, LPort=%d, IP=%pI4", pid, lport, &daddr);

    return 0;
}

// --- 以下 Fork、PAM、Exit 逻辑保持不变 ---

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;

    __u32 *ip = bpf_map_lookup_elem(&pid_to_ip, &parent_pid);
    if (ip) {
        bpf_map_update_elem(&pid_to_ip, &child_pid, ip, BPF_ANY);
    }
    return 0;
}

SEC("uretprobe/pam_authenticate")
int handle_pam_auth(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 *ip = bpf_map_lookup_elem(&pid_to_ip, &pid);
    __u32 remote_ip = 0;
    if (ip) remote_ip = *ip;

    struct ssh_fail_event e = {
        .pid = pid,
        .remote_ip = remote_ip,
        .ret_code = (__u32)ret,
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&pid_to_ip, &pid);
    return 0;
}