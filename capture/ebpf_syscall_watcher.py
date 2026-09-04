#!/usr/bin/env python3
# This script uses eBPF/BCC to watch 12 specific syscalls and output SyscallRecord JSONs.
# Requirements: bcc (python3-bpfcc on Debian/Ubuntu), root privileges.
#
# Tracepoints hooked (12):
#   1. open          5. connect        9.  ptrace
#   2. openat        6. setuid        10.  clone
#   3. execve        7. setgid        11.  init_module
#   4. execveat      8. setresuid     12.  mount
#
# Week 4 expansion: ptrace/clone/init_module/mount added per
# docs/SYSCALLRECORD_RECONCILIATION.md (Option a) to capture
# Stage 2 process injection (T1055.008) and Stage 4 kernel
# persistence (T1547.006) from harness/host_attack_scenario.py.
#
# connect args now decoded from sockaddr_in → {family, ip, port, addrlen}.
# ppid extracted via bpf_get_current_task()->real_parent->tgid.

from bcc import BPF
import json
import time
import ctypes
import socket
import struct

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/socket.h>

#define MAX_STRING_SIZE 256
#define MAX_ARGS 4

struct data_t {
    u64 ts;
    u32 pid;
    u32 ppid;
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
    
    // Decoded sockaddr_in for connect() — 16 bytes
    u16 sa_family;
    u16 sa_port;    // network byte order
    u32 sa_addr;    // network byte order
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
    
    // Extract ppid from task->real_parent->tgid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &parent->tgid);
    
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

// 5. connect — decode sockaddr_in into sa_family/sa_port/sa_addr
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.syscall_id = 5;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Extract ppid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &parent->tgid);
    
    data.arg1 = args->fd;
    data.arg3 = args->addrlen;
    
    // Read the sockaddr struct from user space to decode family/ip/port
    if (args->addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), args->uservaddr);
        data.sa_family = sa.sin_family;
        data.sa_port = sa.sin_port;
        data.sa_addr = sa.sin_addr.s_addr;
    } else {
        // For non-AF_INET sockets, just read family
        u16 fam = 0;
        bpf_probe_read_user(&fam, sizeof(fam), args->uservaddr);
        data.sa_family = fam;
    }
    
    events.perf_submit(args, &data, sizeof(data));
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

// 9. ptrace
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    submit_event((struct pt_regs *)args, 9, args->request, args->pid, args->addr, args->data, NULL);
    return 0;
}

// 10. clone
TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    submit_event((struct pt_regs *)args, 10, args->clone_flags, args->newsp, args->parent_tidptr, args->child_tidptr, NULL);
    return 0;
}

// 11. init_module
TRACEPOINT_PROBE(syscalls, sys_enter_init_module) {
    submit_event((struct pt_regs *)args, 11, args->len, 0, 0, 0, args->umod);
    return 0;
}

// 12. mount
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    submit_event((struct pt_regs *)args, 12, args->flags, 0, 0, 0, args->dev_name);
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
    8: "setresuid",
    9: "ptrace",
    10: "clone",
    11: "init_module",
    12: "mount"
}

def print_event(cpu, data, size):
    class Data(ctypes.Structure):
        _fields_ = [
            ("ts", ctypes.c_uint64),
            ("pid", ctypes.c_uint32),
            ("ppid", ctypes.c_uint32),
            ("uid", ctypes.c_uint32),
            ("syscall_id", ctypes.c_uint32),
            ("comm", ctypes.c_char * 16),
            ("arg1", ctypes.c_uint64),
            ("arg2", ctypes.c_uint64),
            ("arg3", ctypes.c_uint64),
            ("arg4", ctypes.c_uint64),
            ("str_arg", ctypes.c_char * 256),
            ("sa_family", ctypes.c_uint16),
            ("sa_port", ctypes.c_uint16),
            ("sa_addr", ctypes.c_uint32),
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
        # Decode sockaddr_in fields from BPF struct
        family_num = event.sa_family
        family_str = "AF_INET" if family_num == socket.AF_INET else \
                     "AF_INET6" if family_num == socket.AF_INET6 else \
                     "AF_UNIX" if family_num == socket.AF_UNIX else \
                     f"AF_{family_num}"
        port = socket.ntohs(event.sa_port)
        # Convert network-order u32 to dotted-quad IP string
        ip = socket.inet_ntoa(struct.pack("!I", event.sa_addr))
        args_dict = {"fd": event.arg1, "family": family_str, "ip": ip, "port": port, "addrlen": event.arg3}
    elif syscall_name == "setuid":
        args_dict = {"uid": event.arg1}
    elif syscall_name == "setgid":
        args_dict = {"gid": event.arg1}
    elif syscall_name == "setresuid":
        args_dict = {"ruid": event.arg1, "euid": event.arg2, "suid": event.arg3}
    elif syscall_name == "ptrace":
        args_dict = {"request": event.arg1, "pid": event.arg2, "addr": hex(event.arg3), "data": hex(event.arg4)}
    elif syscall_name == "clone":
        args_dict = {"flags": hex(event.arg1), "child_stack": hex(event.arg2)}
    elif syscall_name == "init_module":
        args_dict = {"len": event.arg1, "umod": event.str_arg.decode('utf-8', 'replace')}
    elif syscall_name == "mount":
        args_dict = {"flags": event.arg1, "dev_name": event.str_arg.decode('utf-8', 'replace')}
    
    record = {
        "timestamp": event.ts / 1e9,  # seconds
        "pid": event.pid,
        "ppid": event.ppid,
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
    
    print("Successfully attached 12 tracepoints. Listening for events... (Press Ctrl+C to stop)", flush=True)
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Stopped.")
