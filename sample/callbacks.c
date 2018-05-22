
#include <sys/user.h>
#include <stdio.h>

struct user_info;

typedef void (*callback_t)(struct user_regs_struct*);

void sum_call(struct user_regs_struct* regs) {
  fprintf(stderr, "  CALL: %16llx : int sum((int) %d, (int) %d) \n", regs->rbp, regs->rdi, regs->rsi);
}

void sum_ret(struct user_regs_struct* regs) {
  fprintf(stderr, "  RET:  %16llx : return (int) %d \n", regs->rbp, regs->rax);
}

