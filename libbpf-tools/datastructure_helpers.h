/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 LG Electronics Inc. */
#ifndef __DATASTRUCTURE_HELPERS_H
#define __DATASTRUCTURE_HELPERS_H

#include <stdlib.h>
#include <stdbool.h>

#define DS_VEC_INIT_CAP 16
#define DS_HASHMAP_INIT_CAP 64

/*
 * ============================================================
 * Generic dynamic array (vector)
 * ============================================================
 *
 * A realloc-based dynamic array storing element data inline.
 * Each element is elem_size bytes.  Growth factor is 2x,
 * giving amortized O(1) push_back.
 *
 * Usage:
 *
 *   struct ds_vec v = {};
 *   ds_vec_init(&v, sizeof(int));
 *
 *   int val = 42;
 *   ds_vec_push_back(&v, &val);
 *
 *   int *p = ds_vec_at(&v, 0);
 *   printf("%d\n", *p);       // 42
 *   printf("size=%zu\n", v.nr);
 *
 *   ds_vec_sort(&v, int_cmp);
 *   ds_vec_free(&v);
 */

struct ds_vec {
	void *data;
	size_t nr;
	size_t capacity;
	size_t elem_size;
};

void ds_vec_init(struct ds_vec *v, size_t elem_size);
void ds_vec_free(struct ds_vec *v);
int  ds_vec_reserve(struct ds_vec *v, size_t cap);
int  ds_vec_push_back(struct ds_vec *v, const void *elem);
int  ds_vec_pop_back(struct ds_vec *v, void *out);
void *ds_vec_at(struct ds_vec *v, size_t idx);
void ds_vec_clear(struct ds_vec *v);
void ds_vec_sort(struct ds_vec *v, int (*cmp)(const void *, const void *));
size_t ds_vec_size(const struct ds_vec *v);
bool ds_vec_empty(const struct ds_vec *v);

/*
 * ============================================================
 * Generic hash map
 * ============================================================
 *
 * Separate-chaining hash map.  Each bucket holds a singly-linked
 * list of nodes; every node stores its key and value inline.
 * Uses FNV-1a for hashing.  Bucket array doubles when the average
 * chain length exceeds 2.
 *
 * Key padding rule:
 *   Keys are compared with memcmp().  If the key type is a struct with
 *   padding bytes, those bytes must be zeroed before use or lookups may
 *   silently fail.  Always initialise struct keys with memset before
 *   filling their fields:
 *
 *     struct my_key key;
 *     memset(&key, 0, sizeof(key));
 *     key.field = value;
 *
 *   This is the same requirement as for Linux eBPF map keys.
 *
 * Usage:
 *
 *   struct ds_hashmap map = {};
 *   ds_hashmap_init(&map, sizeof(__u64), sizeof(struct my_val), 0);
 *
 *   __u64 key = 123;
 *   struct my_val val = { .count = 1 };
 *   ds_hashmap_insert(&map, &key, &val);
 *
 *   struct my_val *found = ds_hashmap_find(&map, &key);
 *   if (found)
 *       found->count++;
 *
 *   ds_hashmap_delete(&map, &key);
 *
 *   // Iterate all entries:
 *   struct ds_hashmap_iter it = {};
 *   void *k, *v;
 *   while (ds_hashmap_next(&map, &it, &k, &v)) {
 *       __u64 *kp = k;
 *       struct my_val *vp = v;
 *       printf("key=%llu count=%d\n", *kp, vp->count);
 *   }
 *
 *   ds_hashmap_free(&map);
 */

/* Opaque node type; defined in datastructure_helpers.c */
struct ds_hashmap_node;

struct ds_hashmap {
	struct ds_hashmap_node **buckets;	/* array of chain head pointers */
	size_t capacity;		/* number of buckets (power of 2) */
	size_t count;
	size_t key_size;	/* original key size for memcpy/memcmp */
	size_t key_stride;	/* key_size rounded up to max alignment for NODE_VAL offset */
	size_t val_size;
};

struct ds_hashmap_iter {
	size_t idx;	/* next bucket to scan */
	void *node;	/* next node in current chain; NULL to start at idx */
};

int   ds_hashmap_init(struct ds_hashmap *m, size_t key_size, size_t val_size,
		   size_t init_cap);
void  ds_hashmap_free(struct ds_hashmap *m);
int   ds_hashmap_insert(struct ds_hashmap *m, const void *key, const void *val);
void *ds_hashmap_find(struct ds_hashmap *m, const void *key);
int   ds_hashmap_delete(struct ds_hashmap *m, const void *key);
bool  ds_hashmap_next(struct ds_hashmap *m, struct ds_hashmap_iter *it,
		   void **key_out, void **val_out);
void  ds_hashmap_clear(struct ds_hashmap *m);
size_t ds_hashmap_count(const struct ds_hashmap *m);

/* Utility hash functions */
unsigned long ds_hash_bytes(const void *key, size_t len);
unsigned long ds_hash_string(const char *str);
unsigned long ds_hash_combine(unsigned long h1, unsigned long h2);

#endif /* __DATASTRUCTURE_HELPERS_H */
