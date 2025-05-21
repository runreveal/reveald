// SPDX-License-Identifier: GPL-3.0-or-later
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define AF_INET 2
#define AF_INET6 10

// Abbreviated version of Linux's internal task_struct.
// preserve_access_index enables CO-RE
// so exact field offsets are determined at runtime.
struct task_struct {
  int pid;
  struct task_struct *real_parent;
} __attribute__((preserve_access_index));

#define EXEC_FILENAME_SIZE 1006
#define EXEC_ARG_SIZE 1024
#define MAX_ARGS 60

#define DATA_TYPE_FORK 0
#define DATA_TYPE_EXEC 1
#define DATA_TYPE_CONNECT 2

struct tagged_data_header {
  __u64 time;
  __u32 pid;
  __u32 ppid;
  __u8 data_type;
} __attribute__((packed));

struct exec_data {
  struct tagged_data_header header;
  __u8 argc;
  char filename[EXEC_FILENAME_SIZE];
} __attribute__((packed));

struct network_data {
  struct tagged_data_header header;
  __u8 daddr[16];
  __u16 dport;
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 32768);
} events SEC(".maps");

struct exec_arg_key {
  __u64 time;
  __u32 pid;
  __u8 i;
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct exec_arg_key);
  __uint(value_size, EXEC_ARG_SIZE);
  __uint(max_entries, 512);
} exec_args SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __uint(value_size, EXEC_ARG_SIZE);
  __uint(max_entries, 1);
} exec_arg_buffer SEC(".maps");

static int get_ppid(struct task_struct *task) {
  struct task_struct *parent;
  bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
  int ppid;
  bpf_probe_read(&ppid, sizeof(ppid), &parent->pid);
  return ppid;
}

struct sys_exit_fork_context {
  __u16 common_type;
  __u8 common_flags;
  __u8 common_preempt_count;
  __s32 common_pid;

  __s32 __syscall_nr;
  __s64 ret;
};

SEC("tracepoint/syscalls/sys_exit_fork")
int syscall_exit_fork(struct sys_exit_fork_context *ctx) {
  struct tagged_data_header *result;
  result = bpf_ringbuf_reserve(&events, sizeof(struct tagged_data_header), 0);
  if (result != NULL) {
    result->data_type = DATA_TYPE_FORK;
    result->time = bpf_ktime_get_ns();
    result->pid = bpf_get_current_pid_tgid();
    result->ppid = get_ppid((struct task_struct *) bpf_get_current_task());
    bpf_ringbuf_submit(result, 0);
  }
  return 0;
}

struct sys_enter_execve_context {
  __u16 common_type;
  __u8 common_flags;
  __u8 common_preempt_count;
  __s32 common_pid;

  __s32 __syscall_nr;
  const char *filename;
  const char *const *argv;
  const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int syscall_enter_execve(struct sys_enter_execve_context *ctx) {
  struct exec_data *result;
  result = bpf_ringbuf_reserve(&events, sizeof(struct exec_data), 0);
  if (result == NULL) {
    return 0;
  }

  __u64 time = bpf_ktime_get_ns();
  result->header.data_type = DATA_TYPE_EXEC;
  result->header.time = time;
  result->header.pid = bpf_get_current_pid_tgid();
  result->header.ppid = get_ppid((struct task_struct *) bpf_get_current_task());

  long n = bpf_probe_read_user_str(&result->filename[0], EXEC_FILENAME_SIZE, ctx->filename);
  if (n < 0) {
    bpf_ringbuf_discard(result, 0);
    return 0;
  }

  __u8 argc = 0;
  struct exec_arg_key arg_key;
  int exec_arg_buffer_key = 0;
  char *arg_value = bpf_map_lookup_elem(&exec_arg_buffer, &exec_arg_buffer_key);
  if (arg_value != NULL) {
    arg_key.time = result->header.time;
    arg_key.pid = result->header.pid;
    for (argc = 0; argc < MAX_ARGS; argc++) {
      const char *argp;
      if (bpf_probe_read_user(&argp, sizeof(const char *), &ctx->argv[argc]) != 0) {
        break;
      }
      if (argp == NULL) {
        break;
      }
      n = bpf_probe_read_user_str(arg_value, EXEC_ARG_SIZE, argp);
      if (n < 0) {
        break;
      }
      arg_key.i = argc;
      if (bpf_map_update_elem(&exec_args, &arg_key, arg_value, BPF_NOEXIST) != 0) {
        break;
      }
    }
  }
  result->argc = argc;
  bpf_ringbuf_submit(result, 0);

  return 0;
}

// Converts ip4 (in host byte order) to an IPv6 ::ffff:0:0/96 address.
static void fill_4in6_address(__u8 *dst, __u32 ip4) {
  int i;
  for (i = 0; i < 10; i++) {
    dst[i] = 0;
  }
  dst[10] = 0xff;
  dst[11] = 0xff;
  dst[12] = ip4 >> 24;
  dst[13] = ip4 >> 16;
  dst[14] = ip4 >> 8;
  dst[15] = ip4;
}

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx) {
  if (ctx->type != SOCK_STREAM || ctx->family != AF_INET) {
    return 1;
  }

  struct network_data *result;
  result = bpf_ringbuf_reserve(&events, sizeof(struct network_data), 0);
  if (result != NULL) {
    result->header.data_type = DATA_TYPE_CONNECT;
    result->header.time = bpf_ktime_get_ns();
    result->header.pid = bpf_get_current_pid_tgid();
    // result->header.ppid = get_ppid((struct task_struct *) bpf_get_current_task());
    result->header.ppid = 0;

    fill_4in6_address(&result->daddr[0], bpf_ntohl(ctx->user_ip4));
    result->dport = bpf_ntohs(ctx->user_port);
    bpf_ringbuf_submit(result, 0);
  }

  return 1;
}

char __license[] SEC("license") = "GPL";
