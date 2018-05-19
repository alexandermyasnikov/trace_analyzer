
#include <stdio.h>

int sum(int a, int b) {
  fprintf(stdout, "sum \n");
  return a + b;
}

int mult(int a, int b) {
  fprintf(stdout, "mult \n");
  return a * b;
}

int sub(int a, int b) {
  fprintf(stdout, "sub \n");
  return a - b;
}

int main() {
  for (int i = 0; i < 10; ++i) {
    int a = i - 5;
    int b = 1;
    int ret;
    ret = sum(a, b);
    ret = sub(a, b);
    fprintf(stdout, "func(...) return : %d \n", ret);
  }
  fprintf(stdout, "Hello World !!! \n");
  return 0;
}

