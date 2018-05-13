#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/user.h>
#include <stdint.h>

struct user_info {
  struct user_regs_struct regs;
  int last_error;
};

void print_info(FILE *stream, struct user_info* info) {
  /*
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
  */
  fprintf(stream, "rbp:  %16llx \n", info->regs.rbp);
  fprintf(stream, "rsp:  %16llx \n", info->regs.rsp);
  fprintf(stream, "rip:  %16llx \n", info->regs.rip);
  fprintf(stream, "rax:  %16llx \n", info->regs.rax);
  fprintf(stream, "rdi_: %16llx \n", info->regs.rdi);
  fprintf(stream, "rsi_: %16llx \n", info->regs.rsi);
  fprintf(stream, "rdx_: %16llx \n", info->regs.rdx);
  fprintf(stream, "rcx_: %16llx \n", info->regs.rcx);
  fprintf(stream, "r8_:  %16llx \n", info->regs.r8);
  fprintf(stream, "r9_:  %16llx \n", info->regs.r9);
  fprintf(stream, " \n\n");
}

void fprint_wait_status(FILE *stream, int status) {
  if (WIFSTOPPED(status)) {
    fprintf(stream, "Child stopped: %d\n", WSTOPSIG(status));
  }
  if (WIFEXITED(status)) {
    fprintf(stream, "Child exited: %d\n", WEXITSTATUS(status));
  }
  if (WIFSIGNALED(status)) {
    fprintf(stream, "Child signaled: %d\n", WTERMSIG(status));
  }
  if (WCOREDUMP(status)) {
    fprintf(stream, "Core dumped.\n");
  }
}

int ptrace_instruction_pointer(int pid, struct user_info *info) {
  if (!info)
    return -1;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &info->regs)) {
    fprintf(stderr, "Error fetching registers from child process: %s\n", strerror(errno));
    return -1;
  }

  info->last_error = 0;

  long ins = ptrace(PTRACE_PEEKTEXT, pid, info->regs.rip, NULL);
  long ins_copy = ins;

  unsigned char opcode = ins & 0xFF;
  ins_copy >>= 8;

  fprintf(stderr, "INS:  %16lx \n", ins);

  if (opcode == 0xE8) {
    int ptr_offset = ins_copy & 0xFFFFFFFF;
    long ptr = info->regs.rip + ptr_offset + sizeof(opcode) + sizeof(ptr_offset);
    fprintf(stderr, "  %hhx CALL   ptr: %x %lx \n", opcode, ptr_offset, ptr);
    fprintf(stderr, "arg1 rdi: %llx \n", info->regs.rdi);
    fprintf(stderr, "arg2 rsi: %llx \n", info->regs.rsi);
    fprintf(stderr, "arg3 rdx: %llx \n", info->regs.rdx);
    fprintf(stderr, "arg4 rcx: %llx \n", info->regs.rcx);
    fprintf(stderr, "arg5  r8: %llx \n", info->regs.r8);
    fprintf(stderr, "arg6  r9: %llx \n", info->regs.r9);

    if ((ptr & 0xFFF) == 0x695) { // HACK
      info->regs.rdi = -info->regs.rdi;
      ptrace(PTRACE_SETREGS, pid, NULL, &info->regs);
    }
  } else if (opcode == 0xC3) {
    fprintf(stderr, "  %hhx RET \n", opcode);
    fprintf(stderr, "ret rax: %llx \n", info->regs.rax);
  } else {
    fprintf(stderr, "opcр: %16hhx \n", opcode);
    info->last_error = -1;
  }

  // print_info(stderr, info);

  return 0;
}

int singlestep(int pid) {
  int retval, status;
  retval = ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
  if (retval) {
    return retval;
  }
  waitpid(pid, &status, 0);
  return status;
}

int main(int argc, char ** argv, char **envp) {
    struct user_info info;
    pid_t pid;
    int status;
    char *program;
    if (argc < 2) {
        fprintf(stderr, "Usage: %s elffile arg0 arg1 ...\n", argv[0]);
        exit(-1);
    }
    program = argv[1];
    char ** child_args = (char**) &argv[1];

    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "Error forking: %s\n", strerror(errno));
        exit(-1);
    }
    if (pid == 0) {
        /* child */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
            fprintf(stderr, "Error setting TRACEME: %s\n", strerror(errno));
            exit(-1);
        }
        execve(program,child_args,envp);
    } else {
        /* parent */
        waitpid(pid, &status, 0);
        fprint_wait_status(stderr, status);
        while (WIFSTOPPED(status)) {
            if (ptrace_instruction_pointer(pid, &info)) {
                break;
            }
            status = singlestep(pid);
        }
        fprint_wait_status(stderr, status);
        fprintf(stderr, "Detaching\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
    }

    return 0;
}

