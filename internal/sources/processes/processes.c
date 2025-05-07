// SPDX-License-Identifier: GPL-3.0-or-later
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Abbreviated version of Linux's internal task_struct.
// preserve_access_index enables CO-RE
// so exact field offsets are determined at runtime.
struct task_struct {
  int pid;
  struct task_struct *real_parent;
} __attribute__((preserve_access_index));

#define MAX_ARG_LEN 255
#define MAX_ARGS 30

struct processes_result {
  __u64 time;
  __u32 pid;
  __u32 ppid;
  char filename[MAX_ARG_LEN + 1];
  // Ideally, this would be a single buffer,
  // but it proved too tricky to get the eBPF verifier onboard with it.
  char argv[MAX_ARGS][MAX_ARG_LEN + 1];
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 32768);
} events SEC(".maps");

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
  struct processes_result *result;
  result = bpf_ringbuf_reserve(&events, sizeof(struct processes_result), 0);
  if (result != NULL) {
    result->time = bpf_ktime_get_ns();
    result->pid = bpf_get_current_pid_tgid();
    result->filename[0] = 0;
    int i;
    for (i = 0; i < MAX_ARGS; i++) {
      result->argv[i][0] = 0;
    }
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
  struct processes_result *result;
  result = bpf_ringbuf_reserve(&events, sizeof(struct processes_result), 0);
  if (result != NULL) {
    result->time = bpf_ktime_get_ns();
    result->pid = bpf_get_current_pid_tgid();
    result->ppid = get_ppid((struct task_struct *) bpf_get_current_task());

    long n = bpf_probe_read_user_str(result->filename, MAX_ARG_LEN + 1, ctx->filename);
    if (n < 0) {
      bpf_ringbuf_discard(result, 0);
      return 0;
    }

    int i;
    for (i = 0; i < MAX_ARGS; i++) {
      const char *argp;
      if (bpf_probe_read_user(&argp, sizeof(const char *), &ctx->argv[i]) != 0) {
        bpf_ringbuf_discard(result, 0);
        return 0;
      }
      if (argp == NULL) {
        result->argv[i][0] = 0;
        result->argv[i][1] = 0xff;
        break;
      }

      n = bpf_probe_read_user_str(&result->argv[i][0], MAX_ARG_LEN + 1, argp);
      if (n < 0) {
        bpf_ringbuf_discard(result, 0);
        return 0;
      }
      if (n == 1) {
        result->argv[i][1] = 0;
      }
    }

    bpf_ringbuf_submit(result, 0);
  }

  return 0;
}

char __license[] SEC("license") = "GPL";
