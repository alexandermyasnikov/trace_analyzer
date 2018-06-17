
#include <sys/user.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

struct process_t;

typedef void (*regs_callback_t) (struct process_t*);



struct process_t {
  pid_t pid;
  struct user_regs_struct regs;
};



void print_hex(void* buf, size_t len) {
  for (size_t i = 0, j = 0; i < len; ++i, j = (j + 1) % 16) {
    fprintf(stderr, "  %02hhx", *(i + (unsigned char*) buf));
    if (j == 7) {
      fprintf(stderr, "  ");
    } else if (j == 15) {
      fprintf(stderr, " \n");
    }
  }
  fprintf(stderr, " \n");
}



int peek_data(pid_t pid, void* src, void* dst, size_t len) {
  unsigned char *s = (unsigned char *) src;
  unsigned char *d = (unsigned char *) dst;

  for (size_t i = 0; i < len; ++i) {
    d[i] = 0xFF & ptrace(PTRACE_PEEKTEXT, pid, s + i, NULL);
    if (errno)
      return -1;
  }

  return 0;
}



void print_regs(struct process_t* process) {
  struct user_regs_struct* regs = &process->regs;

  {
    size_t len = regs->rbp - regs->rsp;
    unsigned char buf[len];
    peek_data(process->pid, (void *) regs->rsp, buf, len);
    print_hex(buf, len);
  }

  fprintf(stderr, "rbp:  %16llx \n", regs->rbp); // указатель на фрейм стека.
  fprintf(stderr, "rsp:  %16llx \n", regs->rsp); // указатель на вершину стека.
  fprintf(stderr, "rip:  %16llx \n", regs->rip); // указатель на каманду.

  fprintf(stderr, "rax:  %16llx \n", regs->rax); // результат вызова.

  fprintf(stderr, "rdi:  %16llx \n", regs->rdi); // аргумент 1.
  fprintf(stderr, "rsi:  %16llx \n", regs->rsi); // аргумент 2.
  fprintf(stderr, "rdx:  %16llx \n", regs->rdx); // аргумент 3.
  fprintf(stderr, "rcx:  %16llx \n", regs->rcx); // аргумент 4.
  fprintf(stderr, "r8:   %16llx \n", regs->r8);  // аргумент 5.
  fprintf(stderr, "r9:   %16llx \n", regs->r9);  // аргумент 6.

  fprintf(stderr, "rbx:  %16llx \n", regs->rbx);
  fprintf(stderr, "r10:  %16llx \n", regs->r10);
  fprintf(stderr, "r11:  %16llx \n", regs->r11);
  fprintf(stderr, "r12:  %16llx \n", regs->r12);
  fprintf(stderr, "r13:  %16llx \n", regs->r13);
  fprintf(stderr, "r14:  %16llx \n", regs->r14);
  fprintf(stderr, "r15:  %16llx \n", regs->r15);

  fprintf(stderr, "cs:   %16llx \n", regs->cs);
  fprintf(stderr, "ss:   %16llx \n", regs->ss);
  fprintf(stderr, "ds:   %16llx \n", regs->ds);
  fprintf(stderr, "es:   %16llx \n", regs->es);
  fprintf(stderr, "fs:   %16llx \n", regs->fs);
  fprintf(stderr, "gs:   %16llx \n", regs->gs);
  fprintf(stderr, "fs_base:  %16llx \n", regs->fs_base);
  fprintf(stderr, "gs_base:  %16llx \n", regs->gs_base);
  fprintf(stderr, "eflags:   %16llx \n", regs->eflags);
  fprintf(stderr, "orig_rax: %16llx \n", regs->orig_rax);

  fprintf(stderr, " \n\n");
}



void sum_call(struct process_t* process) {
  struct user_regs_struct* regs = &process->regs;
  fprintf(stderr, "  CALL: %16llx : int sum((int) %d, (int) %d) \n", regs->rbp, regs->rdi, regs->rsi);
}

void sum_ret(struct process_t* process) {
  struct user_regs_struct* regs = &process->regs;
  fprintf(stderr, "  RET:  %16llx : return (int) %d \n", regs->rbp, regs->rax);
}

void w_test_char4_1(struct process_t* process) {
  struct user_regs_struct* regs = &process->regs;

  struct char4_t {
    char a;
    char b;
    char c;
    char d;
  } char4;

  memcpy(&char4, (void *) &regs->rdi, sizeof(char4));

  fprintf(stderr, "  CALL: %16llx : int test_char4_1((struct char4) { "
      "(char) %hhd, (char) %hhd, (char) %hhd, (char) %hhd }) \n",
      regs->rbp, char4.a, char4.b, char4.c, char4.d);
}

void w_test_char4_2(struct process_t* process) {
  struct user_regs_struct* regs = &process->regs;

  struct char4_t {
    char a;
    char b;
    char c;
    char d;
  } char4;

  peek_data(process->pid, (void *) regs->rdi, &char4, sizeof(char4));

  fprintf(stderr, "  CALL: %16llx : int test_char4_2((struct char4*) { "
      "(char) %hhd, (char) %hhd, (char) %hhd, (char) %hhd }) \n",
      regs->rbp, char4.a, char4.b, char4.c, char4.d);
}

void w_test_s4_1(struct process_t* process) {
  struct user_regs_struct* regs = &process->regs;

  struct s4_t {
    char a;
    long b;
    int  c;
    long d;
  } s4;

  peek_data(process->pid, (void *) regs->rsp + 8, &s4, sizeof(s4));

  fprintf(stderr, "  CALL: %16llx : int test_s4_1((struct s4_t) { (char) %hhd, (long) %ld, (int) %d, (long) %ld }) \n",
      regs->rbp, s4.a, s4.b, s4.c, s4.d);
}

void w_test_s4_2(struct process_t* process) {
  struct user_regs_struct* regs = &process->regs;

  struct s4_t {
    char a;
    long b;
    int  c;
    long d;
  } s4;

  peek_data(process->pid, (void *) regs->rdi, &s4, sizeof(s4));

  fprintf(stderr, "  CALL: %16llx : int test_s4_2((struct s4*) { "
      "(char) %hhd, (long) %ld, (int) %d, (long) %ld }) \n",
      regs->rbp, s4.a, s4.b, s4.c, s4.d);
}

void w_test_args(struct process_t* process) {
  struct user_regs_struct* regs = &process->regs;

  struct args_tail_t {
    long v7;
    long v8;
    long v9;
    long v10;
  } args_tail;

  peek_data(process->pid, (void *) regs->rsp + 8, &args_tail, sizeof(args_tail));

  fprintf(stderr, "  CALL: %16llx : int test_args((int) %d, (int) %d, (int) %d,"
      " (int) %d, (int) %d, (int) %d, (int) %d, (int) %d, (int) %d, (int) %d) \n",
      regs->rbp, regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8, regs->r9,
      args_tail.v7, args_tail.v8, args_tail.v9, args_tail.v10);
}
