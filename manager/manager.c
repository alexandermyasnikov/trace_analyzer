
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_PID_COUNT           10
#define TIMEOUT_CHECK_PROCESS   1



struct pids_t;
int pids_init(struct pids_t* context, char* program_name);
int pids_desroy(struct pids_t* context);
int pids_add_pid(struct pids_t* context, int pid);
int pids_check_process(struct pids_t* context);



struct input_t;



struct input_t {
  char program_name[100];
};



struct pids_t {
  int pids[MAX_PID_COUNT];
  char cmd[100];
};

int pids_init(struct pids_t* context, char* program_name) {
  memset(&context->pids, 0x00, sizeof(context->pids));
  snprintf(context->cmd, 100, "pgrep -a \"%s\";", program_name);
  return 0;
}

int pids_desroy(struct pids_t* context) {
  memset(&context->pids, 0x00, sizeof(context->pids));
  memset(&context->cmd,  0x00, sizeof(context->cmd));
  return 0;
}

int pids_add_pid(struct pids_t* context, int pid) {
  for (int i = 0; i < MAX_PID_COUNT; ++i) {
    if (!context->pids[i]) {
      context->pids[i] = pid;
      fprintf(stderr, "add pid: %d \n", pid);
      return 0;
    }
  }
  return -1;
}

int pids_check_process(struct pids_t* context) {
  char* line = NULL;
  size_t len = 0;
  int pid;
  int ret = 0;

  FILE* file = popen(context->cmd, "r");

  while (getline(&line, &len, file) != -1) {
    sscanf(line, "%d", &pid);
    pids_add_pid(context, pid);
    ret = 1;
  }

  pclose(file);

  return ret;
}


int main() {

  // struct input_t input;

  struct pids_t pids;
  pids_init(&pids, "fork");

  while (1) {
    if (pids_check_process(&pids))
      break;

    sleep(TIMEOUT_CHECK_PROCESS);
  }

  for (int i = 0; i < MAX_PID_COUNT; ++i) {
    if (pids.pids[i])
      fprintf(stderr, "TODO fork pid: %d \n", pids.pids[i]);
  }

  pids_desroy(&pids);

  return 0;
}

