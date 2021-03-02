/*
 * sstr.c
 *
 * copyright (c) 2020-2021 Xiongfei Shi
 *
 * author: Xiongfei Shi <xiongfei.shi(a)icloud.com>
 * license: Apache-2.0
 *
 * https://github.com/shixiongfei/sstr
 */

#include "sstr.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#define strncasecmp _strnicmp
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#pragma pack(push, 1)
typedef struct sstrbuf_t {
  int size;
  int free;
  char data[1];
} sstrbuf_t;
#pragma pack(pop)

#define sstrbuf(ptr) ((sstrbuf_t *)((char *)(ptr)-offsetof(sstrbuf_t, data)))

static void *alloc_emul(void *ptr, size_t size) {
  if (size)
    return realloc(ptr, size);
  free(ptr);
  return NULL;
}

static void *(*sstr_realloc)(void *, size_t) = alloc_emul;

#define sstr_malloc(size) sstr_realloc(NULL, size)
#define sstr_free(ptr) sstr_realloc(ptr, 0)

static unsigned long sstr_nextpower(unsigned long size) {
  if (0 == size)
    return 2;

  /* fast check if power of two */
  if (0 == (size & (size - 1)))
    return size;

  size -= 1;
  size |= size >> 1;
  size |= size >> 2;
  size |= size >> 4;
  size |= size >> 8;
  size |= size >> 16;
#if ULONG_MAX == ULLONG_MAX
  size |= size >> 32;
#endif
  size += 1;

  return size;
}

void sstr_setalloc(void *(*allocator)(void *, size_t)) {
  sstr_realloc = allocator ? allocator : alloc_emul;
}

sstr_t sstr_empty(void) {
  int size = (int)sstr_nextpower(sizeof(sstrbuf_t));
  sstrbuf_t *sb = (sstrbuf_t *)sstr_malloc(size);

  sb->free = size - sizeof(sstrbuf_t);
  sb->size = 0;
  sb->data[sb->size] = 0;

  return sb->data;
}

sstr_t sstr_fromstring(const char *str) {
  return sstr_frombuffer(str, (int)strlen(str));
}

sstr_t sstr_frombuffer(const void *buf, int len) {
  sstr_t s = sstr_empty();
  return sstr_catlen(s, buf, len);
}

sstr_t sstr_vformat(const char *format, va_list ap) {
  sstr_t s = sstr_empty();
  return sstr_catvfmt(s, format, ap);
}

sstr_t sstr_format(const char *format, ...) {
  sstr_t s;
  va_list ap;

  va_start(ap, format);
  s = sstr_vformat(format, ap);
  va_end(ap);

  return s;
}

sstr_t sstr_join(const char **argv, int argc, const char *sep, int seplen) {
  sstr_t s = sstr_empty();
  int i;

  for (i = 0; i < argc; ++i) {
    s = sstr_cat(s, argv[i]);

    if (i < (argc - 1))
      s = sstr_catlen(s, sep, seplen);
  }

  return s;
}

sstr_t sstr_dup(const sstr_t s) {
  sstrbuf_t *sb = sstrbuf(s);
  return sstr_frombuffer(sb->data, sb->size);
}

sstr_t sstr_slice(const sstr_t s, int start, int end) {
  sstr_t dst = sstr_dup(s);
  sstr_range(dst, start, end);
  return dst;
}

sstr_t sstr_cpy(sstr_t s, const char *str) {
  return sstr_cpylen(s, str, (int)strlen(str));
}

sstr_t sstr_cpylen(sstr_t s, const void *buf, int len) {
  sstr_clear(s);
  return sstr_catlen(s, buf, len);
}

sstr_t sstr_cat(sstr_t s, const char *str) {
  return sstr_catlen(s, str, (int)strlen(str));
}

sstr_t sstr_catlen(sstr_t s, const void *buf, int len) {
  int size = sstr_length(s);

  s = sstr_growup(s, len);
  memcpy(s + size, buf, len);

  return s;
}

sstr_t sstr_catvfmt(sstr_t s, const char *format, va_list ap) {
  int len, offset = sstr_length(s);
  va_list argv;

  va_copy(argv, ap);

  len = vsnprintf(NULL, 0, format, argv);
  s = sstr_growup(s, len);

  vsprintf(s + offset, format, ap);
  va_end(argv);

  return s;
}

sstr_t sstr_catfmt(sstr_t s, const char *format, ...) {
  va_list ap;

  va_start(ap, format);
  s = sstr_catvfmt(s, format, ap);
  va_end(ap);

  return s;
}

sstr_t sstr_catrepr(sstr_t s, const char *str, int len) {
  static const char hextab[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  };

  while (len--) {
    char chr = *str++;

    switch (chr) {
    case '\\':
      s = sstr_catlen(s, "\\\\", 2);
      break;
    case '\n':
      s = sstr_catlen(s, "\\n", 2);
      break;
    case '\r':
      s = sstr_catlen(s, "\\r", 2);
      break;
    case '\t':
      s = sstr_catlen(s, "\\t", 2);
      break;
    case '\a':
      s = sstr_catlen(s, "\\a", 2);
      break;
    case '\b':
      s = sstr_catlen(s, "\\b", 2);
      break;
    default:
      if (isprint(chr))
        s = sstr_catlen(s, &chr, 1);
      else {
        char tmp[4] = {'\\', 'x', hextab[chr >> 4], hextab[chr & 0x0f]};
        s = sstr_catlen(s, tmp, sizeof(tmp));
      }
      break;
    }
  }

  return s;
}

sstr_t sstr_growup(sstr_t s, int len) {
  sstrbuf_t *sb = sstrbuf(s);

  if (sb->free < len) {
    int need = len - sb->free;
    int newlen = sb->size + sb->free + need;
    int size = (int)sstr_nextpower(sizeof(sstrbuf_t) + newlen);

    sb = (sstrbuf_t *)sstr_realloc(sb, size);
    sb->free += (size - sizeof(sstrbuf_t) - sb->size - sb->free);
  }

  sb->free -= len;
  sb->size += len;
  sb->data[sb->size] = 0;

  return sb->data;
}

sstr_t sstr_insert(sstr_t s, int offset, const void *buf, int len) {
  int size = sstr_length(s);

  if (offset < 0)
    offset = size + offset;

  offset = offset < 0 ? 0 : offset > size ? size : offset;

  if (offset == size)
    return sstr_catlen(s, buf, len);

  s = sstr_growup(s, len);

  memmove(s + offset + len, s + offset, size - offset);
  memcpy(s + offset, buf, len);

  return s;
}

static void *sstr_memmem(const void *haystack, unsigned int haystacklen,
                         const void *needle, unsigned int needlelen) {
  const unsigned char *begin = (const unsigned char *)haystack;
  const unsigned char *last_possible = begin + (haystacklen - needlelen);
  const unsigned char *end = (const unsigned char *)needle;
  unsigned char first_chr = (unsigned char)*end++;

  if (0 == needlelen)
    return (void *)begin;

  if (haystacklen >= needlelen) {
    if (1 == needlelen)
      return (void *)memchr(begin, first_chr, haystacklen);

    for (; begin <= last_possible; begin++) {
      if (((*begin) == first_chr) &&
          (0 == memcmp(begin + 1, end, needlelen - 1))) {
        return (void *)begin;
      }
    }
  }

  return NULL;
}

sstr_t sstr_replace(sstr_t s, const char *old_str, int old_len,
                    const char *new_str, int new_len) {
  unsigned char *begin, *end, *found;
  int diff_size, size = sstr_length(s);

  if (!old_str || old_len <= 0)
    return s;

  diff_size = new_len - old_len;

  begin = (unsigned char *)s;
  end = begin + size;

  while (begin <= end) {
    found = (unsigned char *)sstr_memmem(begin, (unsigned int)(end - begin),
                                         old_str, old_len);

    if (!found)
      break;

    if (diff_size > 0) {
      int offset = (int)(found - begin);

      s = sstr_growup(s, diff_size);
      size = sstr_length(s);

      begin = (unsigned char *)s;
      end = begin + size;

      found = begin + offset;
    }

    memmove(found + new_len, found + old_len,
            (size_t)(end - (found + old_len)));

    if (new_str && new_len > 0)
      memcpy(found, new_str, new_len);

    if (diff_size < 0)
      sstr_shrink(s, diff_size);

    end += diff_size;
    begin = found + new_len;
  }

  return s;
}

void sstr_trim(sstr_t s, const char *chrset) {
  sstr_rtrim(s, chrset);
  sstr_ltrim(s, chrset);
}

void sstr_ltrim(sstr_t s, const char *chrset) {
  sstrbuf_t *sb = sstrbuf(s);
  const char *begin = (const char *)sb->data;
  const char *end = (const char *)sb->data + sb->size;
  int newlen;

  while (begin < end && strchr(chrset, *begin))
    begin++;

  newlen = (int)(end - begin);

  if (newlen > 0 && sb->data != begin)
    memmove(sb->data, begin, newlen);

  sb->free += sb->size - newlen;
  sb->size = newlen;
  sb->data[sb->size] = 0;
}

void sstr_rtrim(sstr_t s, const char *chrset) {
  sstrbuf_t *sb = sstrbuf(s);
  const char *begin = (const char *)sb->data;
  const char *end = (const char *)sb->data + sb->size - 1;
  int newlen;

  while (end > begin && strchr(chrset, *end))
    end--;

  newlen = (int)(end - begin + 1);

  sb->free += sb->size - newlen;
  sb->size = newlen;
  sb->data[sb->size] = 0;
}

void sstr_tolower(sstr_t s) {
  int i, len = sstr_length(s);

  for (i = 0; i < len; ++i)
    s[i] = tolower(s[i]);
}

void sstr_toupper(sstr_t s) {
  int i, len = sstr_length(s);

  for (i = 0; i < len; ++i)
    s[i] = toupper(s[i]);
}

void sstr_shrink(sstr_t s, int len) {
  sstrbuf_t *sb = sstrbuf(s);

  if (len > sb->size)
    len = sb->size;

  sb->free += len;
  sb->size -= len;
  sb->data[sb->size] = 0;
}

void sstr_clear(sstr_t s) { sstr_shrink(s, sstr_length(s)); }

void sstr_destroy(sstr_t s) {
  sstrbuf_t *sb = sstrbuf(s);
  sstr_free(sb);
}

int sstr_range(sstr_t s, int start, int end) {
  sstrbuf_t *sb = sstrbuf(s);
  int newlen;

  if (sb->size == 0)
    return 0;

  if (start < 0)
    start = sb->size + start;

  if (end < 0)
    end = sb->size + end;

  start = start < 0 ? 0 : start > sb->size ? sb->size : start;
  end = end < 0 ? 0 : end > sb->size ? sb->size : end;

  if (start >= end) {
    sstr_clear(s);
    return 0;
  }

  newlen = end - start;

  if (start > 0)
    memmove(sb->data, sb->data + start, newlen);

  sb->free += sb->size - newlen;
  sb->size = newlen;
  sb->data[sb->size] = 0;

  return sb->size;
}

int sstr_length(const sstr_t s) {
  sstrbuf_t *sb = sstrbuf(s);
  return sb->size;
}

int sstr_cmp(const sstr_t l, const sstr_t r) {
  int ll = sstr_length(l);
  int rl = sstr_length(r);
  int cmp = memcmp(l, r, min(ll, rl));
  return 0 == cmp ? ll - rl : cmp;
}

int sstr_casecmp(const sstr_t l, const sstr_t r) {
  int ll = sstr_length(l);
  int rl = sstr_length(r);
  int cmp = strncasecmp(l, r, min(ll, rl));
  return 0 == cmp ? ll - rl : cmp;
}
