
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int sum(int a, int b) {
  fprintf(stdout, "sum \n");
  return a + b;
}

int main() {
  fprintf(stdout, "pid: %d \n", getpid());

  sleep(10);

  pid_t pid = fork();

  if (pid == 0) {
    sleep(5);
    fprintf(stdout, "pid: %d \n", getpid());
    for (int i = 0; i < 1000; ++i) {
      int ret = sum(i, -10);
      fprintf(stdout, "func(...) return : %d \n", ret);
      sleep(10);
    }
  }
  else if (pid > 0)
  {
    fprintf(stdout, "pid: %d \n", getpid());
    for (int i = 0; i < 100; ++i) {
      int ret = sum(i, 2);
      fprintf(stdout, "func(...) return : %d \n", ret);
      sleep(10);
    }
  }
  else
  {
    // fork failed
    fprintf(stdout, "fork() failed \n");
    return 1;
  }

  return 0;
}

