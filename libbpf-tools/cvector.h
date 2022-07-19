/*
 * Copyright (c) 2015 Evan Teran
 *
 * License: The MIT License (MIT)
 */

#ifndef CVECTOR_H_
#define CVECTOR_H_

#include <assert.h> /* for assert */
#include <stdlib.h> /* for malloc/realloc/free */
#include <string.h> /* for memcpy/memmove */

/* cvector heap implemented using C library malloc() */

/* in case C library malloc() needs extra protection,
 * allow these defines to be overridden.
 */
#ifndef cvector_clib_free
#define cvector_clib_free free
#endif
#ifndef cvector_clib_malloc
#define cvector_clib_malloc malloc
#endif
#ifndef cvector_clib_calloc
#define cvector_clib_calloc calloc
#endif
#ifndef cvector_clib_realloc
#define cvector_clib_realloc realloc
#endif

typedef void (*cvector_elem_destructor_t)(void *elem);

/**
 * @brief cvector_vector_type - The vector type used in this library
 */
#define cvector_vector_type(type) type *

/**
 * @brief cvector_capacity - gets the current capacity of the vector
 * @param vec - the vector
 * @return the capacity as a size_t
 */
#define cvector_capacity(vec) \
    ((vec) ? ((size_t *)(vec))[-1] : (size_t)0)

/**
 * @brief cvector_size - gets the current size of the vector
 * @param vec - the vector
 * @return the size as a size_t
 */
#define cvector_size(vec) \
    ((vec) ? ((size_t *)(vec))[-2] : (size_t)0)

/**
 * @brief cvector_set_elem_destructor - set the element destructor function
 * used to clean up removed elements
 * @param vec - the vector
 * @return elem_destructor_fn - function pointer of type cvector_elem_destructor_t
 * @return the function pointer elem_destructor_fn or NULL on error
 */
#define cvector_set_elem_destructor(vec, elem_destructor_fn)                                \
    do {                                                                                    \
        if (!(vec)) {                                                                       \
            cvector_grow((vec), 0);                                                         \
        }                                                                                   \
        ((cvector_elem_destructor_t *)&(((size_t *)(vec))[-2]))[-1] = (elem_destructor_fn); \
    } while (0)

/**
 * @brief cvector_elem_destructor - get the element destructor function used
 * to clean up elements
 * @param vec - the vector
 * @return the function pointer as cvector_elem_destructor_t
 */
#define cvector_elem_destructor(vec) \
    ((vec) ? (((cvector_elem_destructor_t *)&(((size_t *)(vec))[-2]))[-1]) : NULL)

/**
 * @brief cvector_empty - returns non-zero if the vector is empty
 * @param vec - the vector
 * @return non-zero if empty, zero if non-empty
 */
#define cvector_empty(vec) \
    (cvector_size(vec) == 0)

/**
 * @brief cvector_reserve - Requests that the vector capacity be at least enough
 * to contain n elements. If n is greater than the current vector capacity, the
 * function causes the container to reallocate its storage increasing its
 * capacity to n (or greater).
 * @param vec - the vector
 * @param n - Minimum capacity for the vector.
 * @return void
 */
#define cvector_reserve(vec, capacity)           \
    do {                                         \
        size_t cv_cap__ = cvector_capacity(vec); \
        if (cv_cap__ < (capacity)) {             \
            cvector_grow((vec), (capacity));     \
        }                                        \
    } while (0)

/**
 * @brief cvector_erase - removes the element at index i from the vector
 * @param vec - the vector
 * @param i - index of element to remove
 * @return void
 */
#define cvector_erase(vec, i)                                                                \
    do {                                                                                     \
        if ((vec)) {                                                                         \
            const size_t cv_sz__ = cvector_size(vec);                                        \
            if ((i) < cv_sz__) {                                                             \
                cvector_set_size((vec), cv_sz__ - 1);                                        \
                memmove((vec) + (i), (vec) + (i) + 1, sizeof(*(vec)) * (cv_sz__ - 1 - (i))); \
            }                                                                                \
        }                                                                                    \
    } while (0)

/**
 * @brief cvector_free - frees all memory associated with the vector
 * @param vec - the vector
 * @return void
 */
#define cvector_free(vec)                                                                                                           \
    do {                                                                                                                            \
        if ((vec)) {                                                                                                                \
            size_t *p1__                                = (size_t *)&(((cvector_elem_destructor_t *)&(((size_t *)(vec))[-2]))[-1]); \
            cvector_elem_destructor_t elem_destructor__ = cvector_elem_destructor((vec));                                           \
            if (elem_destructor__) {                                                                                                \
                size_t i__;                                                                                                         \
                for (i__ = 0; i__ < cvector_size(vec); ++i__)                                                                       \
                    elem_destructor__(&vec[i__]);                                                                                   \
            }                                                                                                                       \
            cvector_clib_free(p1__);                                                                                                \
        }                                                                                                                           \
    } while (0)

/**
 * @brief cvector_begin - returns an iterator to first element of the vector
 * @param vec - the vector
 * @return a pointer to the first element (or NULL)
 */
#define cvector_begin(vec) \
    (vec)

/**
 * @brief cvector_end - returns an iterator to one past the last element of the vector
 * @param vec - the vector
 * @return a pointer to one past the last element (or NULL)
 */
#define cvector_end(vec) \
    ((vec) ? &((vec)[cvector_size(vec)]) : NULL)

/* user request to use logarithmic growth algorithm */
#ifdef CVECTOR_LOGARITHMIC_GROWTH

/**
 * @brief cvector_compute_next_grow - returns an the computed size in next vector grow
 * size is increased by multiplication of 2
 * @param size - current size
 * @return size after next vector grow
 */
#define cvector_compute_next_grow(size) \
    ((size) ? ((size) << 1) : 1)

#else

/**
 * @brief cvector_compute_next_grow - returns an the computed size in next vector grow
 * size is increased by 1
 * @param size - current size
 * @return size after next vector grow
 */
#define cvector_compute_next_grow(size) \
    ((size) + 1)

#endif /* CVECTOR_LOGARITHMIC_GROWTH */

/**
 * @brief cvector_push_back - adds an element to the end of the vector
 * @param vec - the vector
 * @param value - the value to add
 * @return void
 */
#define cvector_push_back(vec, value)                                 \
    do {                                                              \
        size_t cv_cap__ = cvector_capacity(vec);                      \
        if (cv_cap__ <= cvector_size(vec)) {                          \
            cvector_grow((vec), cvector_compute_next_grow(cv_cap__)); \
        }                                                             \
        (vec)[cvector_size(vec)] = (value);                           \
        cvector_set_size((vec), cvector_size(vec) + 1);               \
    } while (0)

/**
 * @brief cvector_insert - insert element at position pos to the vector
 * @param vec - the vector
 * @param pos - position in the vector where the new elements are inserted.
 * @param val - value to be copied (or moved) to the inserted elements.
 * @return void
 */
#define cvector_insert(vec, pos, val)                                                                      \
    do {                                                                                                   \
        if (cvector_capacity(vec) <= cvector_size(vec) + 1) {                                              \
            cvector_grow((vec), cvector_compute_next_grow(cvector_capacity((vec))));                       \
        }                                                                                                  \
        if ((pos) < cvector_size(vec)) {                                                                   \
            memmove((vec) + (pos) + 1, (vec) + (pos), sizeof(*(vec)) * ((cvector_size(vec) + 1) - (pos))); \
        }                                                                                                  \
        (vec)[(pos)] = (val);                                                                              \
        cvector_set_size((vec), cvector_size(vec) + 1);                                                    \
    } while (0)

/**
 * @brief cvector_pop_back - removes the last element from the vector
 * @param vec - the vector
 * @return void
 */
#define cvector_pop_back(vec)                                                         \
    do {                                                                              \
        cvector_elem_destructor_t elem_destructor__ = cvector_elem_destructor((vec)); \
        if (elem_destructor__)                                                        \
            elem_destructor__(&(vec)[cvector_size(vec) - 1]);                         \
        cvector_set_size((vec), cvector_size(vec) - 1);                               \
    } while (0)

/**
 * @brief cvector_copy - copy a vector
 * @param from - the original vector
 * @param to - destination to which the function copy to
 * @return void
 */
#define cvector_copy(from, to)                                          \
    do {                                                                \
        if ((from)) {                                                   \
            cvector_grow(to, cvector_size(from));                       \
            cvector_set_size(to, cvector_size(from));                   \
            memcpy((to), (from), cvector_size(from) * sizeof(*(from))); \
        }                                                               \
    } while (0)

/**
 * @brief cvector_set_capacity - For internal use, sets the capacity variable of the vector
 * @param vec - the vector
 * @param size - the new capacity to set
 * @return void
 */
#define cvector_set_capacity(vec, size)     \
    do {                                    \
        if ((vec)) {                        \
            ((size_t *)(vec))[-1] = (size); \
        }                                   \
    } while (0)

/**
 * @brief cvector_set_size - For internal use, sets the size variable of the vector
 * @param vec - the vector
 * @param size - the new capacity to set
 * @return void
 */
#define cvector_set_size(vec, size)         \
    do {                                    \
        if ((vec)) {                        \
            ((size_t *)(vec))[-2] = (size); \
        }                                   \
    } while (0)

/**
 * @brief cvector_grow - For internal use, ensures that the vector is at least <count> elements big
 * @param vec - the vector
 * @param count - the new capacity to set
 * @return void
 */
#define cvector_grow(vec, count)                                                                                  \
    do {                                                                                                          \
        const size_t cv_sz__ = (count) * sizeof(*(vec)) + sizeof(size_t) * 2 + sizeof(cvector_elem_destructor_t); \
        if ((vec)) {                                                                                              \
            cvector_elem_destructor_t *cv_p1__ = &((cvector_elem_destructor_t *)&((size_t *)(vec))[-2])[-1];      \
            cvector_elem_destructor_t *cv_p2__ = cvector_clib_realloc(cv_p1__, cv_sz__);                          \
            assert(cv_p2__);                                                                                      \
            (vec) = (void *)&((size_t *)&cv_p2__[1])[2];                                                          \
        } else {                                                                                                  \
            cvector_elem_destructor_t *cv_p__ = cvector_clib_malloc(cv_sz__);                                     \
            assert(cv_p__);                                                                                       \
            (vec) = (void *)&((size_t *)&cv_p__[1])[2];                                                           \
            cvector_set_size((vec), 0);                                                                           \
            ((cvector_elem_destructor_t *)&(((size_t *)(vec))[-2]))[-1] = NULL;                                   \
        }                                                                                                         \
        cvector_set_capacity((vec), (count));                                                                     \
    } while (0)

#endif /* CVECTOR_H_ */
