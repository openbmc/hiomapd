/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */
#ifndef COMMON_H
#define COMMON_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <syslog.h>

#ifndef PREFIX
#define PREFIX ""
#endif

enum verbose { MBOX_LOG_NONE = 0, MBOX_LOG_INFO = 1, MBOX_LOG_DEBUG = 2 };

extern enum verbose verbosity;

/* The MSG_* macros below rely on the GNU ", ##__VA_ARGS__" extension so
 * they can be called with or without extra arguments.  Clang diagnoses
 * the token-pasting as -Wgnu-zero-variadic-macro-arguments (an error
 * under -Werror at meson warning_level=3), so silence it around the
 * definitions.  The push/pop keeps the suppression scoped to this
 * header; GCC does not know the clang-specific warning name, hence the
 * __clang__ guard.
 */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

/* Error Messages */
#define MSG_ERR(f_, ...)                                                       \
	do {                                                                   \
		mbox_log(LOG_ERR, f_, ##__VA_ARGS__);                          \
	} while (0)

/* Informational Messages */
#define MSG_INFO(f_, ...)                                                      \
	do {                                                                   \
		if (verbosity >= MBOX_LOG_INFO) {                              \
			mbox_log(LOG_INFO, f_, ##__VA_ARGS__);                 \
		}                                                              \
	} while (0)

/* Debug Messages */
#define MSG_DBG(f_, ...)                                                       \
	do {                                                                   \
		if (verbosity >= MBOX_LOG_DEBUG) {                             \
			mbox_log(LOG_DEBUG, f_, ##__VA_ARGS__);                \
		}                                                              \
	} while (0)

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

extern void (*mbox_vlog)(int p, const char *fmt, va_list args);

#ifdef __cplusplus
extern "C" {
#endif

void mbox_log_console(int p, const char *fmt, va_list args);

__attribute__((format(printf, 2, 3))) void mbox_log(int p, const char *fmt,
						    ...);

uint16_t get_u16(uint8_t *ptr);

void put_u16(uint8_t *ptr, uint16_t val);

uint32_t get_u32(uint8_t *ptr);

void put_u32(uint8_t *ptr, uint32_t val);

static inline uint32_t align_up(uint32_t val, uint32_t size)
{
	return (((val) + (size)-1) & ~((size)-1));
}

static inline uint32_t align_down(uint32_t val, uint32_t size)
{
	return ((val) & ~(((size)-1)));
}

static inline uint32_t min_u32(uint32_t a, uint32_t b)
{
	if (a <= b) {
		return a;
	}

	return b;
}

static inline int log_2(int val)
{
	int ret = 0;

	if (val <= 0) {
		return -1;
	}

	while (val >>= 1) {
		ret++;
	}

	return ret;
}

static inline bool is_power_of_2(unsigned val)
{
	return __builtin_popcount(val) == 1;
}

char *get_dev_mtd(void);

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H */
