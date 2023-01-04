// +build ignore
#include "hello.bpf.h"
#include "aarch64/vmlinux.h"
#include <unistd.h>
#if SC_PLATFORM == SC_PLATFORM_LINUX
#include <errno.h>
#endif

// Example: tracing a message on a kprobe
SEC("kprobe/sys_execve")
int hello(void *ctx)
{
    //bpf_printk("I'm alive!");
    return 0;
}

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
int hello_bpftrace(void *ctx)
{
    struct data_t data = {};
    struct task_struct *task;
    struct task_struct *real_parent;
    //pid_t tgid; 
    u32 tgid; 

    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&real_parent, sizeof(real_parent), &task->real_parent);
    bpf_probe_read(&tgid, sizeof(tgid), &real_parent->tgid);
    data.ppid = tgid;
    
    if (tgid != 21615) {
	return 0;
    }
     
    //bpf_probe_read(&ppid, sizeof(ppid), &real_parent_task->tgid); 

    //u32 host_ppid = task->real_parent->tgid; 

    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    data.tid = tid;
    u32 gid = bpf_get_current_uid_gid();
    data.id = gid;

    //read_lock(&tasklist_lock);
    //p = find_task_by_vpid(pid);
    //if (p) get_task_struct(p);
    //read_unlock(&tasklist_lock);
    //if (p == NULL) {
    //    // Task not found.
    //}

    // Later, once you're finished with the task, execute:
    //put_task_struct(p);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_printk("COMM: %s, Pid: %i, Tid: %i\n", &data.comm, data.pid, data.tid);

    bpf_printk("COMM: %s, Parent Id: %i.\n", &data.comm, tgid);
	

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);

    bpf_override_return(ctx, -ENOENT);
    //fork();
    //execl("/usr/local/bin/ebpfault", "--config", "config.json", "-p", pid);

    //char buffer[200];
    //sprintf(buffer, "/usr/local/bin/ebpfault --config config.json -p %u", pid);
    //system(buffer);

    return 0;
}

