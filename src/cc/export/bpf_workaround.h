R"********(
#ifndef __HAVE_BUILTIN_BSWAP16__
#define __HAVE_BUILTIN_BSWAP16__
#endif
#ifndef __HAVE_BUILTIN_BSWAP32__
#define __HAVE_BUILTIN_BSWAP32__
#endif
#ifndef __HAVE_BUILTIN_BSWAP64__
#define __HAVE_BUILTIN_BSWAP64__
#endif

/**
 * commit b2f557eae9ed ("kasan, arm64: adjust shadow size for tag-based mode")
 * KASAN_SHADOW_SCALE_SHIFT moved from headers to the arm64 Makefile
 * see:
 *     https://github.com/torvalds/linux/commit/b2f557eae9ed
 */
#ifdef __aarch64__
#if defined(CONFIG_KASAN) && !defined(KASAN_SHADOW_SCALE_SHIFT)
#ifdef CONFIG_KASAN_SW_TAGS
#define KASAN_SHADOW_SCALE_SHIFT 4
#endif
#ifdef CONFIG_KASAN_GENERIC
#define KASAN_SHADOW_SCALE_SHIFT 3
#endif
#endif
#endif
)********"
