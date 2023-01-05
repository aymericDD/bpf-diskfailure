// +build ignore
#include "injection.bpf.h"
#include "aarch64/vmlinux.h"
#include <unistd.h>
#if SC_PLATFORM == SC_PLATFORM_LINUX
#include <errno.h>
#endif
#include <bpf/bpf_helpers.h>


const volatile pid_t target_pid = 0;

struct data_t {
    u32 ppid;
    u32 pid;
    u32 tid; 
    u32 id;
    char comm[100];
};

// Example of passing data using a perf map 
// Similar to bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count();}'

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

    // Filter
    // @ToDo customize pid filter
    if (data.ppid != target_pid) {
      return 0;
    }

    // Filter by path

    // Get datas of current process
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    data.tid = tid;
    u32 gid = bpf_get_current_uid_gid();
    data.id = gid;

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

