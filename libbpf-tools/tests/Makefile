# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

CC ?= cc
CFLAGS := -Wall -Wextra -Werror -g -I..

TESTS := test_datastructure_helpers

.PHONY: all clean test

all: $(TESTS)

test_datastructure_helpers: test_datastructure_helpers.c ../datastructure_helpers.c
	$(CC) $(CFLAGS) -o $@ $^

test: all
	@failed=0; \
	for t in $(TESTS); do \
		echo "Running $$t ..."; \
		./$$t || failed=$$((failed + 1)); \
	done; \
	if [ $$failed -ne 0 ]; then \
		echo "$$failed test(s) FAILED"; \
		exit 1; \
	fi

clean:
	$(RM) $(TESTS)
