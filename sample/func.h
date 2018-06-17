
#ifndef __func_h__
#define __func_h__

struct char4_t {
  char a;
  char b;
  char c;
  char d;
};

struct s4_t {
  char a;
  long b;
  int  c;
  long d;
};

int sum2(int a, int b);
int sum3(int a, int b);

int test_char4_1(struct char4_t char4);
int test_char4_2(struct char4_t* char4);

int test_s4_1(struct s4_t s4);
int test_s4_2(struct s4_t* s4);

int test_args(int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9, int v10);

#endif  // __func_h__

