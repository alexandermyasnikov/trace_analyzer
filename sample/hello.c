
#include <stdio.h>

int func(int a, int b, int c, int d, int e, int f, int g) {
  return a + b - c + d - e + f - g;
}

int main() {
  for (int i = 0; i < 10; ++i) {
    int a = 0;
    int b = 1;
    int c = i;
    int d = i + 1; 
    int e = c;
    int f = e + 1;
    int g = i * i;
    int ret = func(a, b, c, d, e, f, g);
    fprintf(stderr, "func(...) return : %d \n", ret);
  }
  fprintf(stderr, "Hello World !!! \n");
  return 0;
}

