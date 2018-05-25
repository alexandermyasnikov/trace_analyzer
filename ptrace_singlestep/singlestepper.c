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
#include <dlfcn.h>
#include "../elf/elf_utils.h"

#define DEBUG_STEPPER(a...) // { fprintf(stderr, "[%s, %d] stepper: ", __FUNCTION__, __LINE__); fprintf(stderr, a); fflush(stderr); }

#define ALARM_TIMEOUT_SEC      60
#define LOCK_FILE_NAME         "LOCK"
#define PROCESS_MAX_COUNT      10
#define INSTRUCTIONS_AT_TIME   10000



volatile int break_flag = 0;



typedef void (*callback_t)(struct user_regs_struct*);

struct func_call_t {
  const char* callbacks_shared;   // Имя динамической библиотеки, содержащее новую функцию.
  const char* func_name;          // Имя перехватыемой функции.
  Elf64_Addr func_addr;           // Адрес перехватываемой функции.
  unsigned long long rbp_call;    // Для определения сответствующей RET инструкции.
  const char* func_call_name;     // Имя новой функции для CALL инструкции.
  const char* func_ret_name;      // Имя новой функции для RET инструкции.
  callback_t callback_call;       // Указатель на новую функцию с именем func_call_name.
  callback_t callback_ret;        // Указатель на новую функцию с именем func_ret_name.
};

struct user_info {
  struct user_regs_struct regs;
  int last_error;
  struct func_call_t func_call;
};

int inject_data(pid_t pid, unsigned char *src, void *dst, int len);

void print_info(FILE *stream, struct user_info* info) {
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

  DEBUG_STEPPER("INS:  %16lx \n", ins);

  if (opcode == 0xE8) {
    int ptr_offset = ins_copy & 0xFFFFFFFF;
    long ptr = info->regs.rip + ptr_offset + sizeof(opcode) + sizeof(ptr_offset);
    DEBUG_STEPPER("  %hhx CALL   ptr: %x %lx \n", opcode, ptr_offset, ptr);
    DEBUG_STEPPER("arg1 rdi: %llx \n", info->regs.rdi);
    DEBUG_STEPPER("arg2 rsi: %llx \n", info->regs.rsi);
    DEBUG_STEPPER("arg3 rdx: %llx \n", info->regs.rdx);
    DEBUG_STEPPER("arg4 rcx: %llx \n", info->regs.rcx);
    DEBUG_STEPPER("arg5  r8: %llx \n", info->regs.r8);
    DEBUG_STEPPER("arg6  r9: %llx \n", info->regs.r9);

    if ((ptr & 0xFFF) == info->func_call.func_addr) { // TODO
      printf("  %hhx CALL   ptr: %x %lx \n", opcode, ptr_offset, ptr);
      if (!info->func_call.rbp_call) {
        info->func_call.rbp_call = info->regs.rbp;
        if (info->func_call.callback_call) {
          ((callback_t) info->func_call.callback_call)(&info->regs);
        }
      } else {
        fprintf(stderr, "  ERROR: nested call \n");
      }
    }

    /*
    if ((ptr & 0xFFF) == info->addr1) { // HACK
      info->regs.rdi = -info->regs.rdi;
      ptrace(PTRACE_SETREGS, pid, NULL, &info->regs);
    }
    */
  } else if (opcode == 0xC3) {
    DEBUG_STEPPER("  %hhx RET \n", opcode);
    DEBUG_STEPPER("ret rax: %llx \n", info->regs.rax);
    if (info->func_call.rbp_call && info->func_call.rbp_call == info->regs.rbp) {
      info->func_call.rbp_call = 0;
      if (info->func_call.callback_ret) {
        ((callback_t) info->func_call.callback_ret)(&info->regs);
      }
    }
  } else {
    // DEBUG_STEPPER("opcр: %16hhx \n", opcode);
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

struct context_symbols_t {
  int fd;
  off_t st_size;
  Elf64_Ehdr* elf;
};

int context_symbols_init(struct context_symbols_t* context, const char* callbacks_shared) {
  return open_elf(callbacks_shared, &context->fd, &context->st_size, &context->elf);
}

int context_symbols_lookup(struct context_symbols_t* context, const char* funcname, Elf64_Addr* addr) {
  *addr = lookup_symbol(context->elf, funcname);
  return addr == 0;
}

int context_symbols_destroy(struct context_symbols_t* context) {
  return close_elf(&context->fd, &context->st_size, &context->elf);
}



struct context_dl_t {
  void* handle;
};

int context_dl_init(struct context_dl_t* context, const char* callbacks_shared) {
  context->handle = dlopen(callbacks_shared, RTLD_NOW);
  return (!context->handle);
}

int context_dl_sym(struct context_dl_t* context, const char* funcname, void** callback) {
  void* fn = dlsym(context->handle, funcname);
  *callback = fn;
  return dlerror() != NULL;
}

int context_dl_destroy(struct context_dl_t* context) {
  return dlclose(context->handle);
}



struct trace_manager_t;
struct trace_info_t {
  struct trace_manager_t* manager;
  struct user_info info;
  pid_t pid;
  int status;
};

int trace_info_init(struct trace_info_t* context, pid_t pid) {
  context->pid = pid;
  ptrace(PTRACE_ATTACH, context->pid, NULL, NULL);
  waitpid(context->pid, &context->status, 0);
  ptrace(PTRACE_SETOPTIONS, context->pid, NULL, PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD);
  fprint_wait_status(stderr, context->status);
  return 0;
}

int trace_info_step(struct trace_info_t* context);

int trace_info_destroy(struct trace_info_t* context) {
  fprint_wait_status(stderr, context->status);
  fprintf(stderr, "Detaching \n");
  ptrace(PTRACE_DETACH, context->pid, NULL, NULL);
  context->pid = 0;
  return 0;
}



struct trace_manager_t {
  struct trace_info_t processes[PROCESS_MAX_COUNT];
};

int trace_manager_init(struct trace_manager_t* context) {
  memset(&context->processes, 0, sizeof(context->processes));
  return 0;
}

int trace_manager_next_processes_id(struct trace_manager_t* context) {
  for (int i = 0; i < PROCESS_MAX_COUNT; ++i) {
    if (!context->processes[i].pid)
      return i;
  }
  return -1;
}

int trace_manager_step(struct trace_manager_t* context) {
  int is_end = 1;
  for (int i = 0; i < PROCESS_MAX_COUNT; ++i) {
    if (!context->processes[i].pid)
      continue;

    if (trace_info_step(&context->processes[i])) {
      trace_info_destroy(&context->processes[i]);
      continue;
    }

    is_end = 0;
  }

  if (break_flag)
    is_end = 1;

  return is_end;
}

int trace_manager_destroy(__attribute__ ((unused)) struct trace_manager_t* context) {
  fprintf(stderr, "END \n");
  return 0;
}



void ALARMhandler(__attribute__ ((unused)) int sig) {
  if (access(LOCK_FILE_NAME, F_OK) != 0) { // file doesn't exist
    break_flag = 1;
  }
  alarm(ALARM_TIMEOUT_SEC);
}



int trace_info_step(struct trace_info_t* context) {
  int k = 0;
  int ret = 1;
  while (WIFSTOPPED(context->status) && ++k < INSTRUCTIONS_AT_TIME) {
    if (WSTOPSIG(context->status) == SIGTRAP) {
      int event = (context->status >> 16) & 0xffff;
      if (event) {
        fprintf(stderr, "event %x \n", event);
        long newpid;
        ptrace(PTRACE_GETEVENTMSG, context->pid, NULL, (long) &newpid);
        fprintf(stderr, "newpid %ld \n", newpid);
        waitpid(newpid, &context->status, 0);

        // ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
        ptrace(PTRACE_DETACH, newpid, NULL, NULL); // XXX

        struct trace_manager_t* manager = context->manager;
        int id = trace_manager_next_processes_id(manager);
        if (id != -1) {
          manager->processes[id].info = context->info;
          manager->processes[id].manager = context->manager;
          trace_info_init(&manager->processes[id], newpid);
        }
      }
    }
    if (ptrace_instruction_pointer(context->pid, &context->info)) {
      return -1;
    }
    context->status = singlestep(context->pid);
    ret = 0;
  }
  return ret;
}



int main(int argc, char ** argv/*, char **envp*/) {
    struct user_info info;

    alarm(1);
    signal(SIGALRM, ALARMhandler);

    if (argc < 3) {
        fprintf(stderr, "Usage: %s elffile pid \n", argv[0]);
        exit(-1);
    }

    info.func_call.callbacks_shared = "./sample/callbacks.so";
    info.func_call.func_name = "sum";
    info.func_call.func_addr = 0;
    info.func_call.rbp_call = 0;
    info.func_call.func_call_name = "sum_call";
    info.func_call.func_ret_name = "sum_ret";
    info.func_call.callback_call = NULL;
    info.func_call.callback_ret = NULL;

    {
      struct context_symbols_t context_symbols;
      context_symbols_init(&context_symbols, argv[1]);

      Elf64_Addr addr;
      context_symbols_lookup(&context_symbols, info.func_call.func_name, &addr);
      fprintf(stderr, "func_name: %s   addr: %lx \n", info.func_call.func_name, addr);
      info.func_call.func_addr = addr;

      context_symbols_destroy(&context_symbols);
    }

    {
      struct context_dl_t context_dl;
      context_dl_init(&context_dl, info.func_call.callbacks_shared);
      context_dl_sym(&context_dl, info.func_call.func_call_name, (void**) &info.func_call.callback_call);
      fprintf(stderr, "func_call: %s   addr: %p \n", info.func_call.func_call_name,
              (void *) info.func_call.callback_call);
      context_dl_sym(&context_dl, info.func_call.func_ret_name, (void**) &info.func_call.callback_ret);
      fprintf(stderr, "func_ret: %s   addr: %p \n", info.func_call.func_ret_name,
              (void *) info.func_call.callback_call);

      // context_dl_destroy(&context_dl);
    }



    {
      struct trace_manager_t manager;
      trace_manager_init(&manager);
      manager.processes[0].info = info;
      manager.processes[0].manager = &manager;
      trace_info_init(&manager.processes[0], atoi(argv[2]));
      while (!trace_manager_step(&manager))
        ;
      trace_manager_destroy(&manager);
    }



    return 0;
}

int inject_data(pid_t pid, unsigned char *src, void *dst, int len) {
  int      i;
  long long *s = (long long *) src;
  long long *d = (long long *) dst;

  for (i = 0; i < len; i += sizeof(long long), s++, d++) {
    if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0) {
      perror ("ptrace(POKETEXT)");
      return -1;
    }
  }
  return 0;
}

