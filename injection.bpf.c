// +build ignore
#include "injection.bpf.h"
#include "aarch64/vmlinux.h"
#include <unistd.h>
#if SC_PLATFORM == SC_PLATFORM_LINUX
#include <errno.h>
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

const volatile pid_t target_pid = 0;
const volatile char filter_path[61] = "/";

struct data_t {
    u32 ppid;
    u32 pid;
    u32 tid; 
    u32 id;
    char comm[100];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, u32);
} events SEC(".maps");

//BPF_PERF_OUTPUT(events) 
SEC("kprobe/sys_openat")
int injection_bpftrace(void *ctx)
{
    struct data_t data = {};

    // Get parent process
    struct task_struct *task;
    struct task_struct *real_parent;
    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&real_parent, sizeof(real_parent), &task->real_parent);
    bpf_probe_read(&data.ppid, sizeof(data.ppid), &real_parent->tgid);

    // Get datas of current process
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    data.tid = tid;
    u32 gid = bpf_get_current_uid_gid();
    data.id = gid;

    // Allow only children and parent process.
    if (data.ppid != target_pid && data.pid != target_pid) {
      return 0;
    }

    // Allow only file with the desired prefix.
    struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    int dirfd = PT_REGS_PARM1_CORE(real_regs);
    char *path= (char *)PT_REGS_PARM2_CORE(real_regs);
    char cmp_path_name[62];
    bpf_probe_read(&cmp_path_name, sizeof(cmp_path_name), path);
    char cmp_expected_path[62];
    bpf_probe_read(cmp_expected_path, sizeof(cmp_expected_path), filter_path);
    int filter_len = (int) (sizeof(filter_path) / sizeof(filter_path[0])) - 1;
   
    if (filter_len > 62) {
        return 0;
    }

    for (int i = 0; i < filter_len; ++i) {
      if (cmp_expected_path[i] == NULL)
        break;
      if (cmp_path_name[i] != cmp_expected_path[i])
        return 0;
    }

    // Get command name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Uncomment for debuging purpose.
    //bpf_printk("COMM: %s, Pid: %i, Tid: %i\n", &data.comm, data.pid, data.tid);
    //bpf_printk("COMM: %s, Parent Id: %i.\n", &data.comm, data.ppid);
    //bpf_printk("COMM:%s, Start injection", &data.comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);

    // Override return of process with an -ENOENT error.
    bpf_override_return(ctx, -ENOENT);

    return 0;
}

