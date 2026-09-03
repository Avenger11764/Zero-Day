#!/usr/bin/env python3
# This script uses eBPF/BCC to watch 8 specific syscalls and output SyscallRecord JSONs.
# Requirements: bcc (python3-bpfcc on Debian/Ubuntu), root privileges.

from bcc import BPF
import json
import time
import ctypes

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAX_STRING_SIZE 256
#define MAX_ARGS 4

struct data_t {
    u64 ts;
    u32 pid;
    u32 uid;
    u32 syscall_id; // Custom ID mapped in Python
    char comm[TASK_COMM_LEN];
    
    // We capture up to 4 arguments (as longs/pointers). 
    // For strings, we capture them explicitly if needed.
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    
    char str_arg[MAX_STRING_SIZE];
};

BPF_PERF_OUTPUT(events);

// Helper to submit the event
static inline void submit_event(struct pt_regs *ctx, u32 syscall_id, u64 a1, u64 a2, u64 a3, u64 a4, const char *str_ptr) {
    struct data_t data = {};
    
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.syscall_id = syscall_id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    data.arg1 = a1;
    data.arg2 = a2;
    data.arg3 = a3;
    data.arg4 = a4;
    
    if (str_ptr != NULL) {
        bpf_probe_read_user_str(&data.str_arg, sizeof(data.str_arg), str_ptr);
    }
    
    events.perf_submit(ctx, &data, sizeof(data));
}

// 1. open
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    submit_event((struct pt_regs *)args, 1, args->flags, args->mode, 0, 0, args->filename);
    return 0;
}

// 2. openat
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    submit_event((struct pt_regs *)args, 2, args->dfd, args->flags, args->mode, 0, args->filename);
    return 0;
}

// 3. execve
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    submit_event((struct pt_regs *)args, 3, 0, 0, 0, 0, args->filename);
    return 0;
}

// 4. execveat
TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    submit_event((struct pt_regs *)args, 4, args->fd, args->flags, 0, 0, args->filename);
    return 0;
}

// 5. connect
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    submit_event((struct pt_regs *)args, 5, args->fd, (u64)args->uservaddr, args->addrlen, 0, NULL);
    return 0;
}

// 6. setuid
TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    submit_event((struct pt_regs *)args, 6, args->uid, 0, 0, 0, NULL);
    return 0;
}

// 7. setgid
TRACEPOINT_PROBE(syscalls, sys_enter_setgid) {
    submit_event((struct pt_regs *)args, 7, args->gid, 0, 0, 0, NULL);
    return 0;
}

// 8. setresuid
TRACEPOINT_PROBE(syscalls, sys_enter_setresuid) {
    submit_event((struct pt_regs *)args, 8, args->ruid, args->euid, args->suid, 0, NULL);
    return 0;
}
"""

SYSCALL_MAP = {
    1: "open",
    2: "openat",
    3: "execve",
    4: "execveat",
    5: "connect",
    6: "setuid",
    7: "setgid",
    8: "setresuid"
}

def print_event(cpu, data, size):
    class Data(ctypes.Structure):
        _fields_ = [
            ("ts", ctypes.c_uint64),
            ("pid", ctypes.c_uint32),
            ("uid", ctypes.c_uint32),
            ("syscall_id", ctypes.c_uint32),
            ("comm", ctypes.c_char * 16),
            ("arg1", ctypes.c_uint64),
            ("arg2", ctypes.c_uint64),
            ("arg3", ctypes.c_uint64),
            ("arg4", ctypes.c_uint64),
            ("str_arg", ctypes.c_char * 256)
        ]
    
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    
    syscall_name = SYSCALL_MAP.get(event.syscall_id, "unknown")
    
    # Format arguments depending on syscall
    args_dict = {}
    if syscall_name == "open":
        args_dict = {"filename": event.str_arg.decode('utf-8', 'replace'), "flags": event.arg1, "mode": event.arg2}
    elif syscall_name == "openat":
        args_dict = {"dfd": event.arg1, "filename": event.str_arg.decode('utf-8', 'replace'), "flags": event.arg2, "mode": event.arg3}
    elif syscall_name == "execve":
        args_dict = {"filename": event.str_arg.decode('utf-8', 'replace')}
    elif syscall_name == "execveat":
        args_dict = {"fd": event.arg1, "filename": event.str_arg.decode('utf-8', 'replace'), "flags": event.arg2}
    elif syscall_name == "connect":
        args_dict = {"fd": event.arg1, "uservaddr": hex(event.arg2), "addrlen": event.arg3}
    elif syscall_name == "setuid":
        args_dict = {"uid": event.arg1}
    elif syscall_name == "setgid":
        args_dict = {"gid": event.arg1}
    elif syscall_name == "setresuid":
        args_dict = {"ruid": event.arg1, "euid": event.arg2, "suid": event.arg3}
    
    record = {
        "timestamp": event.ts / 1e9,  # seconds
        "pid": event.pid,
        "uid": event.uid,
        "comm": event.comm.decode('utf-8', 'replace'),
        "syscall": syscall_name,
        "args": args_dict
    }
    
    print(json.dumps(record))

if __name__ == '__main__':
    print("Compiling BPF program...", flush=True)
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        print("Note: This script requires Linux with kernel headers and BCC installed.")
        exit(1)
        
    b["events"].open_perf_buffer(print_event)
    
    print("Successfully attached tracepoints. Listening for events... (Press Ctrl+C to stop)", flush=True)
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Stopped.")
