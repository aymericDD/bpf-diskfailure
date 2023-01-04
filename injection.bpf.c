// +build ignore
#include "injection.bpf.h"
#include "aarch64/vmlinux.h"
#include <unistd.h>
#if SC_PLATFORM == SC_PLATFORM_LINUX
#include <errno.h>
#endif

struct data_t {
    u32 ppid;
    u32 pid;
    u32 tid; 
    u32 id;
    char comm[100];
};

// Example of passing data using a perf map
// Similar to bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count();}'
BPF_PERF_OUTPUT(events)
SEC("kprobe/sys_openat")
int injection_bpftrace(void *ctx)
{
    struct data_t data = {};
    struct task_struct *task;
    struct task_struct *real_parent;
    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&real_parent, sizeof(real_parent), &task->real_parent);
    bpf_probe_read(&data.ppid, sizeof(data.ppid), &real_parent->tgid);
    
    if (data.ppid != 21615) {
      return 0;
    }
     
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    data.tid = tid;
    u32 gid = bpf_get_current_uid_gid();
    data.id = gid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    //bpf_printk("COMM: %s, Pid: %i, Tid: %i\n", &data.comm, data.pid, data.tid);
    //bpf_printk("COMM: %s, Parent Id: %i.\n", &data.comm, data.ppid);
    //bpf_printk("COMM:%s, Start injection", &data.comm);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);

    bpf_override_return(ctx, -ENOENT);

    return 0;
}

