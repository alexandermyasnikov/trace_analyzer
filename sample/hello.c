
#include <stdio.h>

int func(int a, int b, int c, int d, int e, int f, int g) {
  return a + b + c + d + e + f + g;
}

int main() {
  for (int i = 0; i < 10; ++i) {
    int a = i;
    int b = 1;
    int c = 2;
    int d = 3;
    int e = 0;
    int f = 0;
    int g = 0;
    int ret = func(a, b, c, d, e, f, g);
    fprintf(stdout, "func(...) return : %d \n", ret);
  }
  fprintf(stdout, "Hello World !!! \n");
  return 0;
}

