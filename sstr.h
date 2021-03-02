/*
 * sstr.h
 *
 * copyright (c) 2020-2021 Xiongfei Shi
 *
 * author: Xiongfei Shi <xiongfei.shi(a)icloud.com>
 * license: Apache-2.0
 *
 * https://github.com/shixiongfei/sstr
 */

#ifndef __SSTR_H__
#define __SSTR_H__

#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef char *sstr_t;

void sstr_setalloc(void *(*allocator)(void *, size_t));

sstr_t sstr_empty(void);
sstr_t sstr_fromstring(const char *str);
sstr_t sstr_frombuffer(const void *buf, int len);
sstr_t sstr_vformat(const char *format, va_list ap);
sstr_t sstr_format(const char *format, ...);
sstr_t sstr_join(const char **argv, int argc, const char *sep, int seplen);

sstr_t sstr_dup(const sstr_t s);
sstr_t sstr_slice(const sstr_t s, int start, int end);

sstr_t sstr_cpy(sstr_t s, const char *str);
sstr_t sstr_cpylen(sstr_t s, const void *buf, int len);

sstr_t sstr_cat(sstr_t s, const char *str);
sstr_t sstr_catlen(sstr_t s, const void *buf, int len);
sstr_t sstr_catvfmt(sstr_t s, const char *format, va_list ap);
sstr_t sstr_catfmt(sstr_t s, const char *format, ...);
sstr_t sstr_catrepr(sstr_t s, const char *str, int len);

sstr_t sstr_growup(sstr_t s, int len);
sstr_t sstr_insert(sstr_t s, int offset, const void *buf, int len);
sstr_t sstr_replace(sstr_t s, const char *old_str, int old_len,
                    const char *new_str, int new_len);

void sstr_trim(sstr_t s, const char *chrset);
void sstr_ltrim(sstr_t s, const char *chrset);
void sstr_rtrim(sstr_t s, const char *chrset);

void sstr_tolower(sstr_t s);
void sstr_toupper(sstr_t s);

void sstr_shrink(sstr_t s, int len);
void sstr_clear(sstr_t s);
void sstr_destroy(sstr_t s);

int sstr_range(sstr_t s, int start, int end);
int sstr_length(const sstr_t s);
int sstr_cmp(const sstr_t l, const sstr_t r);
int sstr_casecmp(const sstr_t l, const sstr_t r);

#ifdef __cplusplus
};
#endif

#endif /* __SSTR_H__ */
