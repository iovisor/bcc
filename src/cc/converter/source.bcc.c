#include <linux/ptrace.h>

struct query_probe_t {
  uint64_t ts;
  pid_t pid;
  char query[100];
};

BPF_HASH(queries, struct query_probe_t, int);

int probe_mysql_query(struct pt_regs *ctx, void* thd, char* query, size_t len) {
  if (query) {
    struct query_probe_t key = {};

    key.ts = bpf_ktime_get_ns();
    key.pid = bpf_get_current_pid_tgid();

    bpf_probe_read_user_str(&key.query, sizeof(key.query), query);
    bpf_trace_printk("Hello, World! Here I did a sys_clone call! %s\n", key.query);

    int one = 1;
    queries.update(&key, &one);
  }
  return 0;
}
