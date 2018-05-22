
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

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
  fprintf(stdout, "pid: %d \n", getpid());

  for (int i = 0; i < 10000; ++i) {
    int a = i - 5;
    int b = 1;
    int ret;
    ret = sum(a, b);
    ret = sub(a, b);
    fprintf(stdout, "func(...) return : %d \n", ret);
    sleep(10);
  }
  fprintf(stdout, "Hello World !!! \n");
  return 0;
}

