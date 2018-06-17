
#include <stdio.h>
#include "func.h"

int sum2(int a, int b) {
  fprintf(stdout, "sum2 \n");
  return a + b;
}

int sum3(int a, int b) {
  fprintf(stdout, "sum3 \n");
  return a + b;
}

int test_char4_1(struct char4_t char4) {
  return char4.a + char4.b + char4.c + char4.d;
}

int test_char4_2(struct char4_t* char4) {
  return char4->a + char4->b + char4->c + char4->d;
}

int test_s4_1(struct s4_t s4) {
  return s4.a + s4.b + s4.c + s4.d;
}

int test_s4_2(struct s4_t* s4) {
  return s4->a + s4->b + s4->c + s4->d;
}

int test_args(int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9, int v10) {
  return v1 + v2 + v3 + v4 + v5 + v6 + v7 + v8 + v9 + v10;
}

