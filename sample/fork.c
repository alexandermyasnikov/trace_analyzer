
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "func.h"

// extern int sum2(int, int);

int sum(int a, int b) {
  fprintf(stdout, "sum \n");
  return a + b;
}

int main() {
  fprintf(stdout, "pid: %d \n", getpid());

  sleep(10);

  pid_t child_pid = fork();

  if (child_pid == 0) {
    fprintf(stdout, "pid: %d \n", getpid());
    for (int i = 0; i < 10000; ++i) {
      int ret = sum2(i, 1);
      fprintf(stdout, "func(...) return : %d \n", ret);
      sleep(5);
    }
    exit(0);
  } else if (child_pid > 0) {
    fprintf(stdout, "pid: %d \n", getpid());
    for (int i = 0; i < 10000; ++i) {
      int ret = sum2(-i, 2);
      fprintf(stdout, "func(...) return : %d \n", ret);
      sleep(5);
    }
    int status;
    waitpid(child_pid, &status, 0);
  }
  else {
    // fork failed
    fprintf(stdout, "fork() failed \n");
    return 1;
  }

  return 0;
}

