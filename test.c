/*
 * test.c
 *
 * copyright (c) 2020-2021 Xiongfei Shi
 *
 * author: Xiongfei Shi <xiongfei.shi(a)icloud.com>
 * license: Apache-2.0
 *
 * https://github.com/shixiongfei/sstr
 */

#include "sstr.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  char *tokens[3] = {"foo", "bar", "zap"};
  sstr_t s1 = sstr_fromstring("Hello World!");
  sstr_t s2 = sstr_dup(s1);
  sstr_t s3 = sstr_format("%d", argc);
  sstr_t s4 = sstr_join((const char **)tokens, 3, "|", 1);

  printf("%s, %d\n", s1, sstr_length(s1));
  printf("%s, %s, %d\n", s1, s2, sstr_cmp(s1, s2));

  s3 = sstr_catfmt(s3, ", %s", argv[0]);
  printf("%s\n", s3);

  printf("%s, %d\n", s4, sstr_length(s4));
  s4 = sstr_replace(s4, "bar", 3, "buzz", 4);
  printf("%s, %d\n", s4, sstr_length(s4));

  sstr_destroy(s4);
  sstr_destroy(s3);
  sstr_destroy(s2);
  sstr_destroy(s1);

  return 0;
}
