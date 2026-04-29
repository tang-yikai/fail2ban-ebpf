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

// --- A. 记录新连接 (使用 kretprobe 确保在 sshd 进程上下文中) ---
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_accept_return, struct sock *newsk) {
    if (!newsk) return 0;

    // 获取本地端口 (skc_num 是主机字节序)
    __u16 lport = BPF_CORE_READ(newsk, __sk_common.skc_num);
    
    // 仅记录监控端口（如 22）
    if (!bpf_map_lookup_elem(&monitored_ports, &lport)) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 daddr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);

    // 记录映射：当前 sshd 主进程 PID -> 远程攻击者 IP
    bpf_map_update_elem(&pid_to_ip, &pid, &daddr, BPF_ANY);
    
    return 0;
}

// --- B. 子进程继承关系 (处理 sshd fork) ---
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

// --- C. PAM 认证判定 ---
SEC("uretprobe/pam_authenticate")
int handle_pam_auth(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 *ip = bpf_map_lookup_elem(&pid_to_ip, &pid);
    __u32 remote_ip = 0;
    if (ip) remote_ip = *ip;

    // 如果没有获取到 IP，且 ret 为 0（登录成功），通常不需要关注
    // 但为了排查，我们这里不论有没有 IP 都上报，让 Go 端过滤
    struct ssh_fail_event e = {
        .pid = pid,
        .remote_ip = remote_ip,
        .ret_code = (__u32)ret,
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

// --- D. 进程退出清理 ---
SEC("tp/sched/sched_process_exit")
int handle_exit(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&pid_to_ip, &pid);
    return 0;
}