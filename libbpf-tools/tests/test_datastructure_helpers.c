// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2026 LG Electronics Inc.

/*
 * test_datastructure_helpers.c - Unit tests for datastructure_helpers.
 *
 * Build and run (no BPF or kernel required):
 *   cc -o test_datastructure_helpers \
 *      test_datastructure_helpers.c datastructure_helpers.c && \
 *   ./test_datastructure_helpers
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "datastructure_helpers.h"

/* ============================================================
 * Minimal test framework
 * ============================================================ */

static int g_tests_run;
static int g_tests_failed;
static const char *g_current_suite;

#define SUITE(name) \
	do { g_current_suite = (name); printf("\n[%s]\n", name); } while (0)

#define CHECK(expr) \
	do { \
		g_tests_run++; \
		if (!(expr)) { \
			g_tests_failed++; \
			fprintf(stderr, "  FAIL  %s:%d: %s\n", \
				__FILE__, __LINE__, #expr); \
		} else { \
			printf("  PASS  %s\n", #expr); \
		} \
	} while (0)

/* ============================================================
 * vec tests
 * ============================================================ */

static int int_cmp_asc(const void *a, const void *b)
{
	int aa = *(const int *)a;
	int bb = *(const int *)b;

	return (aa > bb) - (aa < bb);
}

static void test_vec_basic(void)
{
	struct ds_vec v = {};
	int val;

	SUITE("vec: basic push_back / at / size / empty");

	ds_vec_init(&v, sizeof(int));
	CHECK(ds_vec_empty(&v));
	CHECK(ds_vec_size(&v) == 0);
	CHECK(ds_vec_at(&v, 0) == NULL);

	val = 10;
	CHECK(ds_vec_push_back(&v, &val) == 0);
	val = 20;
	CHECK(ds_vec_push_back(&v, &val) == 0);
	val = 30;
	CHECK(ds_vec_push_back(&v, &val) == 0);

	CHECK(!ds_vec_empty(&v));
	CHECK(ds_vec_size(&v) == 3);
	CHECK(*(int *)ds_vec_at(&v, 0) == 10);
	CHECK(*(int *)ds_vec_at(&v, 1) == 20);
	CHECK(*(int *)ds_vec_at(&v, 2) == 30);
	CHECK(ds_vec_at(&v, 3) == NULL);

	ds_vec_free(&v);
	CHECK(ds_vec_size(&v) == 0);
	CHECK(v.data == NULL);
}

static void test_vec_pop_back(void)
{
	struct ds_vec v = {};
	int out = 0;

	SUITE("vec: pop_back");

	ds_vec_init(&v, sizeof(int));

	/* pop on empty */
	CHECK(ds_vec_pop_back(&v, &out) == -1);

	int val = 42;
	ds_vec_push_back(&v, &val);
	val = 99;
	ds_vec_push_back(&v, &val);

	CHECK(ds_vec_pop_back(&v, &out) == 0);
	CHECK(out == 99);
	CHECK(ds_vec_size(&v) == 1);

	CHECK(ds_vec_pop_back(&v, &out) == 0);
	CHECK(out == 42);
	CHECK(ds_vec_empty(&v));

	CHECK(ds_vec_pop_back(&v, &out) == -1);

	ds_vec_free(&v);
}

static void test_vec_growth(void)
{
	struct ds_vec v = {};
	int i, val;

	SUITE("vec: growth past DS_VEC_INIT_CAP");

	ds_vec_init(&v, sizeof(int));

	/* Push more than DS_VEC_INIT_CAP (16) elements to force realloc */
	for (i = 0; i < 64; i++) {
		val = i * 3;
		CHECK(ds_vec_push_back(&v, &val) == 0);
	}

	CHECK(ds_vec_size(&v) == 64);
	for (i = 0; i < 64; i++)
		CHECK(*(int *)ds_vec_at(&v, i) == i * 3);

	ds_vec_free(&v);
}

static void test_vec_sort(void)
{
	struct ds_vec v = {};
	int vals[] = {5, 2, 8, 1, 9, 3};
	int expected[] = {1, 2, 3, 5, 8, 9};
	int i;

	SUITE("vec: sort");

	ds_vec_init(&v, sizeof(int));
	for (i = 0; i < 6; i++)
		ds_vec_push_back(&v, &vals[i]);

	ds_vec_sort(&v, int_cmp_asc);

	for (i = 0; i < 6; i++)
		CHECK(*(int *)ds_vec_at(&v, i) == expected[i]);

	ds_vec_free(&v);
}

static void test_vec_clear(void)
{
	struct ds_vec v = {};
	int val = 1;

	SUITE("vec: clear keeps capacity");

	ds_vec_init(&v, sizeof(int));
	ds_vec_push_back(&v, &val);
	ds_vec_push_back(&v, &val);

	size_t cap_before = v.capacity;
	ds_vec_clear(&v);
	CHECK(ds_vec_size(&v) == 0);
	CHECK(v.capacity == cap_before); /* capacity is preserved */

	ds_vec_free(&v);
}

static void test_vec_reserve(void)
{
	struct ds_vec v = {};

	SUITE("vec: reserve");

	ds_vec_init(&v, sizeof(int));
	CHECK(ds_vec_reserve(&v, 128) == 0);
	CHECK(v.capacity >= 128);
	CHECK(v.nr == 0);

	/* reserve smaller than current capacity is no-op */
	size_t old_cap = v.capacity;
	CHECK(ds_vec_reserve(&v, 1) == 0);
	CHECK(v.capacity == old_cap);

	ds_vec_free(&v);
}

static void test_vec_struct_elements(void)
{
	struct point { int x; int y; };
	struct ds_vec v = {};
	struct point p;

	SUITE("vec: struct elements");

	ds_vec_init(&v, sizeof(struct point));

	p.x = 1; p.y = 2; ds_vec_push_back(&v, &p);
	p.x = 3; p.y = 4; ds_vec_push_back(&v, &p);
	p.x = 5; p.y = 6; ds_vec_push_back(&v, &p);

	CHECK(((struct point *)ds_vec_at(&v, 0))->x == 1);
	CHECK(((struct point *)ds_vec_at(&v, 0))->y == 2);
	CHECK(((struct point *)ds_vec_at(&v, 2))->x == 5);
	CHECK(((struct point *)ds_vec_at(&v, 2))->y == 6);

	ds_vec_free(&v);
}

/* ============================================================
 * hashmap tests
 * ============================================================ */

static void test_hashmap_basic(void)
{
	struct ds_hashmap m = {};
	int key, val;
	int *found;

	SUITE("hashmap: basic insert / find / delete");

	CHECK(ds_hashmap_init(&m, sizeof(int), sizeof(int), 0) == 0);
	CHECK(ds_hashmap_count(&m) == 0);

	key = 1; val = 100;
	CHECK(ds_hashmap_insert(&m, &key, &val) == 0);
	key = 2; val = 200;
	CHECK(ds_hashmap_insert(&m, &key, &val) == 0);
	key = 3; val = 300;
	CHECK(ds_hashmap_insert(&m, &key, &val) == 0);

	CHECK(ds_hashmap_count(&m) == 3);

	key = 1;
	found = ds_hashmap_find(&m, &key);
	CHECK(found != NULL && *found == 100);

	key = 2;
	found = ds_hashmap_find(&m, &key);
	CHECK(found != NULL && *found == 200);

	key = 3;
	found = ds_hashmap_find(&m, &key);
	CHECK(found != NULL && *found == 300);

	/* key not present */
	key = 99;
	CHECK(ds_hashmap_find(&m, &key) == NULL);

	/* delete */
	key = 2;
	CHECK(ds_hashmap_delete(&m, &key) == 0);
	CHECK(ds_hashmap_count(&m) == 2);
	CHECK(ds_hashmap_find(&m, &key) == NULL);

	/* delete again (not present) */
	CHECK(ds_hashmap_delete(&m, &key) == -1);

	ds_hashmap_free(&m);
}

static void test_hashmap_update(void)
{
	struct ds_hashmap m = {};
	int key = 42, val;
	int *found;

	SUITE("hashmap: insert updates existing key");

	CHECK(ds_hashmap_init(&m, sizeof(int), sizeof(int), 0) == 0);

	val = 1;
	ds_hashmap_insert(&m, &key, &val);
	val = 2;
	ds_hashmap_insert(&m, &key, &val); /* update */

	CHECK(ds_hashmap_count(&m) == 1);
	found = ds_hashmap_find(&m, &key);
	CHECK(found != NULL && *found == 2);

	ds_hashmap_free(&m);
}

static void test_hashmap_iteration(void)
{
	struct ds_hashmap m = {};
	struct ds_hashmap_iter it = {};
	int key, val;
	void *k, *v;
	int sum_keys = 0, sum_vals = 0;
	int i;

	SUITE("hashmap: iteration");

	CHECK(ds_hashmap_init(&m, sizeof(int), sizeof(int), 0) == 0);

	for (i = 1; i <= 5; i++) {
		key = i;
		val = i * 10;
		ds_hashmap_insert(&m, &key, &val);
	}

	while (ds_hashmap_next(&m, &it, &k, &v)) {
		sum_keys += *(int *)k;
		sum_vals += *(int *)v;
	}

	/* 1+2+3+4+5 = 15, 10+20+30+40+50 = 150 */
	CHECK(sum_keys == 15);
	CHECK(sum_vals == 150);

	ds_hashmap_free(&m);
}

static void test_hashmap_clear(void)
{
	struct ds_hashmap m = {};
	int key = 1, val = 1;

	SUITE("hashmap: clear");

	CHECK(ds_hashmap_init(&m, sizeof(int), sizeof(int), 0) == 0);

	ds_hashmap_insert(&m, &key, &val);
	ds_hashmap_insert(&m, &key, &val);

	ds_hashmap_clear(&m);
	CHECK(ds_hashmap_count(&m) == 0);

	key = 1;
	CHECK(ds_hashmap_find(&m, &key) == NULL);

	ds_hashmap_free(&m);
}

static void test_hashmap_rehash(void)
{
	struct ds_hashmap m = {};
	int key, val, i;
	int *found;

	SUITE("hashmap: rehash on high load");

	/* Start with a small capacity to force rehash */
	CHECK(ds_hashmap_init(&m, sizeof(int), sizeof(int), 4) == 0);

	/* Insert more than 2x capacity entries to trigger bucket array growth */
	for (i = 0; i < 200; i++) {
		key = i;
		val = i * 7;
		CHECK(ds_hashmap_insert(&m, &key, &val) == 0);
	}

	CHECK(ds_hashmap_count(&m) == 200);

	/* All entries must still be retrievable after rehash */
	for (i = 0; i < 200; i++) {
		key = i;
		found = ds_hashmap_find(&m, &key);
		CHECK(found != NULL && *found == i * 7);
	}

	ds_hashmap_free(&m);
}

static void test_hashmap_u64_key(void)
{
	struct ds_hashmap m = {};
	typedef unsigned long long u64;
	u64 key;
	struct { u64 size; int count; } val, *found;

	SUITE("hashmap: u64 key with struct value");

	CHECK(ds_hashmap_init(&m, sizeof(u64), sizeof(val), 0) == 0);

	key = 0xdeadbeefcafeULL;
	val.size = 1024; val.count = 3;
	CHECK(ds_hashmap_insert(&m, &key, &val) == 0);

	key = 0x1234567890abcdefULL;
	val.size = 512; val.count = 1;
	CHECK(ds_hashmap_insert(&m, &key, &val) == 0);

	key = 0xdeadbeefcafeULL;
	found = ds_hashmap_find(&m, &key);
	CHECK(found != NULL && found->size == 1024 && found->count == 3);

	key = 0x1234567890abcdefULL;
	found = ds_hashmap_find(&m, &key);
	CHECK(found != NULL && found->size == 512 && found->count == 1);

	ds_hashmap_free(&m);
}

static void test_hashmap_char_key_u64_val(void)
{
	struct ds_hashmap m = {};
	struct ds_hashmap_iter it = {};
	char key;
	unsigned long long val, *found;
	void *kp, *vp;
	int i;

	SUITE("hashmap: char key with uint64_t value");

	CHECK(ds_hashmap_init(&m, sizeof(char), sizeof(unsigned long long), 0) == 0);

	for (i = 0; i < 5; i++) {
		key = (char)('a' + i);
		val = (unsigned long long)i * 1000000000ULL;
		CHECK(ds_hashmap_insert(&m, &key, &val) == 0);
	}

	for (i = 0; i < 5; i++) {
		key = (char)('a' + i);
		found = ds_hashmap_find(&m, &key);
		CHECK(found != NULL);
		CHECK(*found == (unsigned long long)i * 1000000000ULL);
		/* Value pointer must satisfy the alignment of uint64_t */
		CHECK(((uintptr_t)found % _Alignof(unsigned long long)) == 0);
	}

	/* Same alignment check during iteration */
	while (ds_hashmap_next(&m, &it, &kp, &vp))
		CHECK(((uintptr_t)vp % _Alignof(unsigned long long)) == 0);

	ds_hashmap_free(&m);
}

static void test_hashmap_struct_key_padding(void)
{
	struct padded_key {
		char  tag;	/* 1 byte */
		/* 3 bytes padding on all common 32/64-bit ABIs */
		int   id;	/* 4 bytes */
	};
	struct ds_hashmap m = {};
	struct padded_key stored, lookup;
	int val = 42, *found;

	SUITE("hashmap: struct key with padding bytes");

	CHECK(ds_hashmap_init(&m, sizeof(struct padded_key), sizeof(int), 0) == 0);

	/*
	 * Keys are compared with memcmp().  Struct keys must be zeroed before
	 * filling fields so that padding bytes are consistent across lookups.
	 */

	/* Correct usage: memset before filling fields */
	memset(&stored, 0, sizeof(stored));
	stored.tag = 'X';
	stored.id  = 99;
	val = 42;
	CHECK(ds_hashmap_insert(&m, &stored, &val) == 0);

	memset(&lookup, 0, sizeof(lookup));
	lookup.tag = 'X';
	lookup.id  = 99;
	found = ds_hashmap_find(&m, &lookup);
	CHECK(found != NULL && *found == 42);

	/* Without memset, garbage in padding bytes causes a lookup miss */
	memset(&lookup, 0xAB, sizeof(lookup));
	lookup.tag = 'X';
	lookup.id  = 99;
	found = ds_hashmap_find(&m, &lookup);
	CHECK(found == NULL);

	ds_hashmap_free(&m);
}

static void test_hashmap_delete_reinsert(void)
{
	struct ds_hashmap m = {};
	int key, val;
	int *found;

	SUITE("hashmap: delete then reinsert same key");

	CHECK(ds_hashmap_init(&m, sizeof(int), sizeof(int), 0) == 0);

	key = 7; val = 70;
	ds_hashmap_insert(&m, &key, &val);
	ds_hashmap_delete(&m, &key);

	/* Reinsert after delete */
	val = 77;
	CHECK(ds_hashmap_insert(&m, &key, &val) == 0);
	found = ds_hashmap_find(&m, &key);
	CHECK(found != NULL && *found == 77);
	CHECK(ds_hashmap_count(&m) == 1);

	ds_hashmap_free(&m);
}

/* ============================================================
 * Hash utility tests
 * ============================================================ */

static void test_hash_utilities(void)
{
	SUITE("hash utilities");

	/* Same bytes produce same hash */
	int a = 42, b = 42;
	CHECK(ds_hash_bytes(&a, sizeof(a)) == ds_hash_bytes(&b, sizeof(b)));

	/* Different bytes produce different hash (with high probability) */
	int c = 43;
	CHECK(ds_hash_bytes(&a, sizeof(a)) != ds_hash_bytes(&c, sizeof(c)));

	/* Same string produces same hash */
	CHECK(ds_hash_string("hello") == ds_hash_string("hello"));

	/* Different strings produce different hash (with high probability) */
	CHECK(ds_hash_string("hello") != ds_hash_string("world"));

	/* Empty string hash is defined and stable */
	unsigned long h1 = ds_hash_string("");
	unsigned long h2 = ds_hash_string("");
	CHECK(h1 == h2);

	/* combine is deterministic */
	unsigned long c1 = ds_hash_combine(0xabcdUL, 0x1234UL);
	unsigned long c2 = ds_hash_combine(0xabcdUL, 0x1234UL);
	CHECK(c1 == c2);

	/* combine(a,b) != combine(b,a) in general (order matters) */
	unsigned long c3 = ds_hash_combine(0x1234UL, 0xabcdUL);
	CHECK(c1 != c3);
}

/* ============================================================
 * main
 * ============================================================ */

int main(void)
{
	test_vec_basic();
	test_vec_pop_back();
	test_vec_growth();
	test_vec_sort();
	test_vec_clear();
	test_vec_reserve();
	test_vec_struct_elements();

	test_hashmap_basic();
	test_hashmap_update();
	test_hashmap_iteration();
	test_hashmap_clear();
	test_hashmap_rehash();
	test_hashmap_u64_key();
	test_hashmap_char_key_u64_val();
	test_hashmap_struct_key_padding();
	test_hashmap_delete_reinsert();

	test_hash_utilities();

	printf("\n========================================\n");
	printf("Results: %d/%d tests passed\n",
	       g_tests_run - g_tests_failed, g_tests_run);
	if (g_tests_failed)
		printf("FAILED: %d test(s) failed\n", g_tests_failed);
	else
		printf("ALL TESTS PASSED\n");
	printf("========================================\n");

	return g_tests_failed ? 1 : 0;
}
