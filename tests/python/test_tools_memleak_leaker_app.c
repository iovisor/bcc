// This is a program that leaks memory, used for memory leak detector testing.

#include <fcntl.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void generate_leak(const char *kind, int amount) {
  void *ptr = NULL;

  if (strcmp(kind, "malloc") == 0) {
    printf("leaking via malloc, %p\n", malloc(amount));
    return;
  }

  if (strcmp(kind, "calloc") == 0) {
    printf("leaking via calloc, %p\n", calloc(amount, 1));
    return;
  }

  if (strcmp(kind, "realloc") == 0) {
    printf("leaking via realloc, %p\n", realloc(malloc(10), amount));
    return;
  }

  if (strcmp(kind, "posix_memalign") == 0) {
    posix_memalign(&ptr, 512, amount);
    printf("leaking via posix_memalign, %p\n", ptr);
    return;
  }

  if (strcmp(kind, "valloc") == 0) {
    printf("leaking via valloc, %p\n", valloc(amount));
    return;
  }

  if (strcmp(kind, "memalign") == 0) {
    printf("leaking via memalign, %p\n", memalign(512, amount));
    return;
  }

  if (strcmp(kind, "pvalloc") == 0) {
    printf("leaking via pvalloc, %p\n", pvalloc(amount));
    return;
  }

  if (strcmp(kind, "aligned_alloc") == 0) {
    printf("leaking via aligned_alloc, %p\n", aligned_alloc(512, amount));
    return;
  }

  if (strcmp(kind, "no_leak") == 0) {
    void *ptr = malloc(amount);
    printf("ptr = %p\n", ptr);
    free(ptr);
    return;
  }

  printf("unknown leak type '%s'\n", kind);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("usage: leak-userspace <kind-of-leak> [amount]\n");
    return EXIT_SUCCESS;
  }

  const char *kind = argv[1];

  int amount = 30;
  if (argc > 2) {
    amount = atoi(argv[2]);
    if (amount < 1)
      amount = 1;
  }

  // Wait for something in stdin to give external detector time to attach.
  char c;
  read(0, &c, sizeof(c));

  // Do the work.
  generate_leak(kind, amount);
  return EXIT_SUCCESS;
}
