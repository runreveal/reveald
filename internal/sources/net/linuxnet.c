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

struct linuxnet_result {
  __u32 pid;
  __u8 daddr[16];
  __u16 dport;
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} connections SEC(".maps");

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

  __u32 pid = bpf_get_current_pid_tgid();
  struct linuxnet_result *result;
  result = bpf_ringbuf_reserve(&connections, sizeof(struct linuxnet_result), 0);
  if (result != NULL) {
    result->pid = pid;
    fill_4in6_address(&result->daddr[0], bpf_ntohl(ctx->user_ip4));
    result->dport = bpf_ntohs(ctx->user_port);
    bpf_ringbuf_submit(result, 0);
  }

  return 1;
}

char __license[] SEC("license") = "GPL";
