// +build ignore
#include "hello.bpf.h"

// Example: tracing a message on a kprobe
SEC("kprobe/sys_getdents64")
int block(void *ctx)
{
    char comm[16 /*TASK_COMM_LEN*/];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (__builtin_memcmp(comm, "ls", 2) == 0) {
        bpf_printk("%s was blocked", comm);
        bpf_override_return(ctx, -1);
    } else {
        bpf_printk("%s was allowed", comm);
    }
    return 0;
}
// Example of passing data using a perf map
// Similar to bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count();}'
BPF_PERF_OUTPUT(events)
SEC("raw_tracepoint/sys_enter")
int hello_bpftrace(void *ctx)
{
    char data[100];
    bpf_get_current_comm(&data, 100);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);
    return 0;
}
