#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <string.h>
#include <errno.h>

/* 67e9c74b8a873408c27ac9a8e4c1d1c8d72c93ff (4.5) */
#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

struct cgid_file_handle
{
  //struct file_handle handle;
  unsigned int handle_bytes;
  int handle_type;
  uint64_t cgid;
};

uint64_t get_cgroupid(const char *pathname) {
  struct statfs fs;
  int err;
  struct cgid_file_handle *h;
  int mount_id;
  uint64_t ret;

  err = statfs(pathname, &fs);
  if (err != 0) {
    fprintf (stderr, "statfs on %s failed: %s\n", pathname, strerror(errno));
    exit(1);
  }

  if ((fs.f_type != (typeof(fs.f_type)) CGROUP2_SUPER_MAGIC)) {
    fprintf (stderr, "File %s is not on a cgroup2 mount.\n", pathname);
    exit(1);
  }

  h = malloc(sizeof(struct cgid_file_handle));
  if (!h) {
    fprintf (stderr, "Cannot allocate memory.\n");
    exit(1);
  }

  h->handle_bytes = 8;
  err = name_to_handle_at(AT_FDCWD, pathname, (struct file_handle *)h, &mount_id, 0);
  if (err != 0) {
    fprintf (stderr, "name_to_handle_at failed: %s\n", strerror(errno));
    exit(1);
  }

  if (h->handle_bytes != 8) {
    fprintf (stderr, "Unexpected handle size: %d. \n", h->handle_bytes);
    exit(1);
  }

  ret = h->cgid;
  free(h);

  return ret;
}

void usage() {
    fprintf (stderr, "Usage: cgroupid FORMAT FILE\n");
    fprintf (stderr, "Print the cgroup id of a cgroup2 directory.\n");
    fprintf (stderr, "Example: cgroupid print-hex /sys/fs/cgroup/unified/system.slice/test.service\n");
    fprintf (stderr, "\n");
    fprintf (stderr, "Format:\n");
    fprintf (stderr, "  number    print the cgroup id as a number\n");
    fprintf (stderr, "  hex       print the cgroup id as a hexadecimal, suitable for bpftool\n");
    fprintf (stderr, "\n");
}

int main(int argc, char **argv) {
  uint64_t cgroupid;
  int i;

  if (argc != 3 || (strcmp(argv[1], "number") != 0 && strcmp(argv[1], "hex"))) {
    usage();
    exit(1);
  }

  cgroupid = get_cgroupid(argv[2]);

  if (strcmp(argv[1], "number") == 0)
    printf("%lu\n", cgroupid);

  if (strcmp(argv[1], "hex") == 0) {
    for (i=0; i<8; i++) {
      printf("%02x%s", ((unsigned char *)&cgroupid)[i], i == 7 ? "\n":" ");
    }
  }
  return 0;
}
