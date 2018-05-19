
#include <sys/user.h>
#include <stdio.h>

struct user_info;

typedef void (*callback_t)(struct user_regs_struct*);

void sum(struct user_regs_struct* regs) {
  fprintf(stderr, "  call: int sum((int) %d, (int) %d) \n", regs->rdi, regs->rsi);
}

