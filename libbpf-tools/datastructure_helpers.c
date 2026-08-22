// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2026 LG Electronics Inc.
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "datastructure_helpers.h"

/*
 * FNV-1a 64-bit constants (CC0 1.0 Public Domain).
 *
 * FNV_OFFSET_BASIS: the FNV-1a 64-bit offset basis (0xcbf29ce484222325).
 *   Chosen empirically by the FNV authors for good avalanche properties.
 *
 * FNV_PRIME: the FNV-1a 64-bit prime (0x00000100000001b3 = 2^40 + 2^8 + 0xb3).
 *   A prime of this specific form ensures wide bit diffusion after each
 *   multiply step.
 */
#define FNV_OFFSET_BASIS 14695981039346656037ULL
#define FNV_PRIME        1099511628211ULL

/*
 * HASH_COMBINE_GOLDEN: 2^64 / phi, where phi is the golden ratio.
 *   Adding this irrational-derived constant before XORing spreads hash
 *   values uniformly across the 64-bit space (boost::hash_combine idiom).
 */
#define HASH_COMBINE_GOLDEN 0x9e3779b97f4a7c15ULL

/*
 * NODE_KEY / NODE_VAL: access the key and value stored inline after the
 * ds_hashmap_node header.  These must be macros rather than functions
 * because struct ds_hashmap_node is an opaque type in the header; its
 * full definition (and therefore sizeof) is only available inside this
 * translation unit.  Moving the layout arithmetic into a function would
 * require exposing the struct definition in the header.
 */
#define NODE_KEY(n)      ((void *)((n) + 1))
#define NODE_VAL(n, ks)  ((void *)((char *)((n) + 1) + (ks)))

/* ============================================================
 * Vector implementation
 * ============================================================ */

void ds_vec_init(struct ds_vec *v, size_t elem_size)
{
	memset(v, 0, sizeof(*v));
	v->elem_size = elem_size;
}

void ds_vec_free(struct ds_vec *v)
{
	free(v->data);
	v->data = NULL;
	v->nr = 0;
	v->capacity = 0;
}

int ds_vec_reserve(struct ds_vec *v, size_t cap)
{
	void *tmp;

	if (cap <= v->capacity)
		return 0;

	tmp = realloc(v->data, cap * v->elem_size);
	if (!tmp)
		return -ENOMEM;

	v->data = tmp;
	v->capacity = cap;

	return 0;
}

int ds_vec_push_back(struct ds_vec *v, const void *elem)
{
	if (v->nr >= v->capacity) {
		size_t new_cap = v->capacity ? v->capacity * 2
					     : DS_VEC_INIT_CAP;
		if (ds_vec_reserve(v, new_cap))
			return -ENOMEM;
	}

	memcpy((char *)v->data + v->nr * v->elem_size, elem, v->elem_size);
	v->nr++;

	return 0;
}

int ds_vec_pop_back(struct ds_vec *v, void *out)
{
	if (!v->nr)
		return -1;

	v->nr--;
	if (out)
		memcpy(out, (char *)v->data + v->nr * v->elem_size,
		       v->elem_size);
	return 0;
}

void *ds_vec_at(struct ds_vec *v, size_t idx)
{
	if (idx >= v->nr)
		return NULL;

	return (char *)v->data + idx * v->elem_size;
}

void ds_vec_clear(struct ds_vec *v)
{
	v->nr = 0;
}

void ds_vec_sort(struct ds_vec *v, int (*cmp)(const void *, const void *))
{
	if (v->nr > 1)
		qsort(v->data, v->nr, v->elem_size, cmp);
}

size_t ds_vec_size(const struct ds_vec *v)
{
	return v->nr;
}

bool ds_vec_empty(const struct ds_vec *v)
{
	return v->nr == 0;
}

/* ============================================================
 * Hash helpers
 * ============================================================ */

/*
 * FNV-1a hash for arbitrary bytes.
 */
unsigned long ds_hash_bytes(const void *key, size_t len)
{
	const unsigned char *p = key;
	unsigned long h = FNV_OFFSET_BASIS;
	size_t i;

	for (i = 0; i < len; i++) {
		h ^= p[i];
		h *= FNV_PRIME;
	}

	return h;
}

/*
 * FNV-1a hash for null-terminated strings.
 */
unsigned long ds_hash_string(const char *str)
{
	unsigned long h = FNV_OFFSET_BASIS;

	while (*str) {
		h ^= (unsigned char)*str++;
		h *= FNV_PRIME;
	}

	return h;
}

/*
 * Combine two hash values (boost-style).
 */
unsigned long ds_hash_combine(unsigned long h1, unsigned long h2)
{
	h1 ^= h2 + HASH_COMBINE_GOLDEN + (h1 << 6) + (h1 >> 2);

	return h1;
}

/* ============================================================
 * Hashmap implementation (separate chaining)
 * ============================================================
 *
 * Each bucket holds a singly-linked list of nodes.  Every node
 * stores its key and value inline, immediately after the header:
 *
 *   [struct ds_hashmap_node] [key (key_size bytes)] [val (val_size bytes)]
 *
 * The bucket array doubles when the average chain length exceeds 2,
 * keeping expected lookup O(1).
 */

struct ds_hashmap_node {
	struct ds_hashmap_node *next;
};

static struct ds_hashmap_node *hashmap__alloc_node(const struct ds_hashmap *m,
						   const void *key, const void *val)
{
	struct ds_hashmap_node *node;

	node = malloc(sizeof(*node) + m->key_stride + m->val_size);
	if (!node)
		return NULL;

	node->next = NULL;
	memcpy(NODE_KEY(node), key, m->key_size);
	memcpy(NODE_VAL(node, m->key_stride), val, m->val_size);

	return node;
}

static size_t hashmap__bucket(const struct ds_hashmap *m, const void *key)
{
	return ds_hash_bytes(key, m->key_size) & (m->capacity - 1);
}

static int hashmap__grow(struct ds_hashmap *m)
{
	struct ds_hashmap_node **new_buckets;
	size_t new_cap = m->capacity * 2;
	size_t i;

	new_buckets = calloc(new_cap, sizeof(*new_buckets));
	if (!new_buckets)
		return -ENOMEM;

	/* Relink all existing nodes into the new bucket array */
	for (i = 0; i < m->capacity; i++) {
		struct ds_hashmap_node *node = m->buckets[i];

		while (node) {
			struct ds_hashmap_node *next = node->next;
			size_t b = ds_hash_bytes(NODE_KEY(node), m->key_size)
				   & (new_cap - 1);

			node->next = new_buckets[b];
			new_buckets[b] = node;
			node = next;
		}
	}

	free(m->buckets);
	m->buckets = new_buckets;
	m->capacity = new_cap;

	return 0;
}

int ds_hashmap_init(struct ds_hashmap *m, size_t key_size, size_t val_size,
		    size_t init_cap)
{
	size_t real_cap;

	memset(m, 0, sizeof(*m));
	m->key_size = key_size;
	m->val_size = val_size;
	/*
	 * Round key_size up to max_align_t so that NODE_VAL is always
	 * suitably aligned for any value type.  key_stride is used only
	 * for pointer arithmetic and allocation; key_size (the original
	 * value) continues to be used for memcpy and memcmp so that we
	 * never read bytes beyond the key object the caller passed.
	 */
	m->key_stride = (key_size + _Alignof(max_align_t) - 1)
			& ~(_Alignof(max_align_t) - 1);

	if (init_cap < DS_HASHMAP_INIT_CAP)
		init_cap = DS_HASHMAP_INIT_CAP;

	/* Round up to power of 2 */
	real_cap = 1;
	while (real_cap < init_cap)
		real_cap <<= 1;

	m->buckets = calloc(real_cap, sizeof(*m->buckets));
	if (!m->buckets)
		return -ENOMEM;

	m->capacity = real_cap;

	return 0;
}

void ds_hashmap_free(struct ds_hashmap *m)
{
	ds_hashmap_clear(m);
	free(m->buckets);
	m->buckets = NULL;
	m->capacity = 0;
}

int ds_hashmap_insert(struct ds_hashmap *m, const void *key, const void *val)
{
	struct ds_hashmap_node *node;
	size_t b;

	/* Grow when average chain length exceeds 2 */
	if (m->count > 2 * m->capacity) {
		if (hashmap__grow(m))
			return -ENOMEM;
	}

	b = hashmap__bucket(m, key);
	node = m->buckets[b];

	/* Walk chain: update value if key already present */
	while (node) {
		if (!memcmp(NODE_KEY(node), key, m->key_size)) {
			memcpy(NODE_VAL(node, m->key_stride), val, m->val_size);
			return 0;
		}
		node = node->next;
	}

	/* Key not found: prepend a new node to the bucket */
	node = hashmap__alloc_node(m, key, val);
	if (!node)
		return -ENOMEM;
	node->next = m->buckets[b];
	m->buckets[b] = node;
	m->count++;
	return 0;
}

void *ds_hashmap_find(struct ds_hashmap *m, const void *key)
{
	struct ds_hashmap_node *node;

	if (!m->capacity)
		return NULL;

	node = m->buckets[hashmap__bucket(m, key)];
	while (node) {
		if (!memcmp(NODE_KEY(node), key, m->key_size))
			return NODE_VAL(node, m->key_stride);
		node = node->next;
	}
	return NULL;
}

int ds_hashmap_delete(struct ds_hashmap *m, const void *key)
{
	struct ds_hashmap_node **pp;

	if (!m->capacity)
		return -1;

	pp = &m->buckets[hashmap__bucket(m, key)];
	while (*pp) {
		if (!memcmp(NODE_KEY(*pp), key, m->key_size)) {
			struct ds_hashmap_node *del = *pp;

			*pp = del->next;
			free(del);
			m->count--;
			return 0;
		}
		pp = &(*pp)->next;
	}
	return -1;
}

bool ds_hashmap_next(struct ds_hashmap *m, struct ds_hashmap_iter *it,
		     void **key_out, void **val_out)
{
	struct ds_hashmap_node *node = it->node;

	/* Advance past empty buckets if no current node */
	while (!node && it->idx < m->capacity)
		node = m->buckets[it->idx++];

	if (!node)
		return false;

	if (key_out)
		*key_out = NODE_KEY(node);
	if (val_out)
		*val_out = NODE_VAL(node, m->key_stride);
	it->node = node->next;

	return true;
}

void ds_hashmap_clear(struct ds_hashmap *m)
{
	size_t i;

	for (i = 0; i < m->capacity; i++) {
		struct ds_hashmap_node *node = m->buckets[i];

		while (node) {
			struct ds_hashmap_node *next = node->next;

			free(node);
			node = next;
		}
		m->buckets[i] = NULL;
	}
	m->count = 0;
}

size_t ds_hashmap_count(const struct ds_hashmap *m)
{
	return m->count;
}
