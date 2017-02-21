#include <unistd.h>
#include <stdio.h>

static __attribute__((noinline)) int some_function(int x, int y) {
	volatile int z = x + y;
	return z;
}

int main() {
	printf("%p\n", &some_function);
	fflush(stdout);
	printf("result = %d\n", some_function(42, 11));
	sleep(1000);
	return 0;
}
