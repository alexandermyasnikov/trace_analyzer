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

#define TRACE(a...) { fprintf(stderr, "TRACE [%d, %s, %d] ", getpid(), __FUNCTION__, __LINE__); fprintf(stderr, a); fflush(stderr); }
#define ERROR(a...) { fprintf(stderr, "ERROR [%d, %s, %d] ", getpid(), __FUNCTION__, __LINE__); fprintf(stderr, a); fflush(stderr); }
#define DEBUG(a...) { fprintf(stderr, "DEBUG [%d, %s, %d] ", getpid(), __FUNCTION__, __LINE__); fprintf(stderr, a); fflush(stderr); }
#define DEBUG_STEPPER(a...) // { fprintf(stderr, "[%s, %d] stepper: ", __FUNCTION__, __LINE__); fprintf(stderr, a); fflush(stderr); }

#define TIMEOUT_CHECK_LOCK_FILE   10
#define LOCK_FILE_NAME            "/tmp/SINGLE_STEPPER_LOCK"
#define PROCESS_MAX_COUNT         10



volatile int break_flag = 0;



void signal_handler(int sig) {
  DEBUG("sig %d \n", sig);
  switch (sig) {
    case SIGINT:
    case SIGUSR1: {
      break_flag = 1;
      break;
    }
  }
}



typedef void (*callback_t)(struct user_regs_struct*);

struct func_call_t { // old
  const char* callbacks_shared;   // Имя динамической библиотеки, содержащее новую функцию.
  const char* func_name;          // Имя перехватыемой функции.
  Elf64_Addr func_addr;           // Адрес перехватываемой функции.
  unsigned long long rbp_call;    // Для определения сответствующей RET инструкции. // TODO rip.
  unsigned long long int ip;      // instruction_pointer
  const char* func_call_name;     // Имя новой функции для CALL инструкции.
  const char* func_ret_name;      // Имя новой функции для RET инструкции.
  callback_t callback_call;       // Указатель на новую функцию с именем func_call_name.
  callback_t callback_ret;        // Указатель на новую функцию с именем func_ret_name.
};



struct ic_t;

int ic_init(struct ic_t* context, const char* shn, const char* fn);
int ic_destroy(struct ic_t* context);
int ic_debug(struct ic_t* context);



struct pm_t { // proc_maps_t
  pid_t pid;
  FILE* maps;
};

int pm_init(struct pm_t* context, pid_t pid);
int pm_get_ip(struct pm_t* context, const char* fn, long long int* ip);
int pm_destroy(struct pm_t* context);



struct user_info_t {
  struct user_regs_struct regs;
  int last_error;
  struct func_call_t func_call;
};

int inject_data(pid_t pid, unsigned char *src, void *dst, int len);

void print_info(FILE *stream, struct user_info_t* info) {
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

int ptrace_instruction_pointer(int pid, struct user_info_t *info) {
  if (!info)
    return -1;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &info->regs)) {
    ERROR("  Error fetching registers from child process: %s\n", strerror(errno));
    return -1;
  }

  info->last_error = 0;

  long ins = ptrace(PTRACE_PEEKTEXT, pid, info->regs.rip, NULL);
  DEBUG_STEPPER("INS:  %16lx   %16llx \n", ins, info->regs.rip);

  if (info->regs.rip == info->func_call.ip) {
    if (info->func_call.callback_call) {
      ((callback_t) info->func_call.callback_call)(&info->regs);
    }
  }

  // ptrace(PTRACE_SETREGS, pid, NULL, &info->regs); // XXX

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
  context->fd = 0;
  context->st_size = 0;
  context->elf = NULL;
  return open_elf(callbacks_shared, &context->fd, &context->st_size, &context->elf);
}

int context_symbols_lookup(struct context_symbols_t* context, const char* funcname, Elf64_Addr* addr) {
  *addr = lookup_symbol(context->elf, funcname);
  return addr == 0;
}

int context_symbols_destroy(struct context_symbols_t* context) {
  context->fd = 0;
  context->st_size = 0;
  context->elf = NULL;
  return close_elf(&context->fd, &context->st_size, &context->elf);
}



struct context_dl_t {
  void* handle;
};

int context_dl_init(struct context_dl_t* context, const char* callbacks_shared) {
  TRACE(" \n");
  context->handle = dlopen(callbacks_shared, RTLD_NOW);
  TRACE("~ \n");
  return (!context->handle);
}

int context_dl_sym(struct context_dl_t* context, const char* funcname, void** callback) {
  TRACE(" \n");
  void* fn = dlsym(context->handle, funcname);
  *callback = fn;
  TRACE("~ \n");
  return dlerror() != NULL;
}

int context_dl_destroy(struct context_dl_t* context) {
  TRACE(" \n");
  TRACE("~ \n");
  return dlclose(context->handle);
}



struct process_t {
  pid_t pid;
  pid_t children[PROCESS_MAX_COUNT];
  struct user_info_t user_info;
  int status;
};

int process_init(struct process_t* context, pid_t pid, struct func_call_t func_call);
int process_run(struct process_t* context);
int process_wait_children(struct process_t* context);
int process_check_status(struct process_t* context);
int process_add_children(struct process_t* context, pid_t pid);
int process_destroy(struct process_t* context);

int process_init(struct process_t* context, pid_t pid, struct func_call_t func_call) {
  TRACE(" \n");
  context->pid = pid;
  memset(&context->children, 0x00, sizeof(context->children));
  context->user_info.func_call = func_call;
  context->status = 0;

  ptrace(PTRACE_ATTACH, context->pid, NULL, NULL);
  waitpid(context->pid, &context->status, 0);
  ptrace(PTRACE_SETOPTIONS, context->pid, NULL, PTRACE_O_TRACEFORK);
  TRACE("~ \n");
  return 0;
}

int process_run(struct process_t* context) {
  TRACE(" \n");
  DEBUG("pid: %d \n", context->pid);
  while (WIFSTOPPED(context->status) && !break_flag) {
    process_check_status(context);
    if (ptrace_instruction_pointer(context->pid, &context->user_info)) {
      return -1;
    }
    context->status = singlestep(context->pid);
  }
  TRACE("~ \n");
  return 0;
}

int process_wait_children(struct process_t* context) {
  TRACE(" \n");
  DEBUG("pid: %d \n", context->pid);
  for (int i = 0; i < PROCESS_MAX_COUNT; ++i) {
    if (context->children[i]) {
      int status;
      DEBUG("wait pid %d \n", context->children[i]);
      kill(context->children[i], SIGUSR1);
      waitpid(context->children[i], &status, 0);
    }
  }
  TRACE("~ \n");
  return 0;
}

int process_check_status(struct process_t* context) {
  if (WSTOPSIG(context->status) != SIGTRAP)
    return 0;

  int event = (context->status >> 16) & 0xFFFF;
  if (event != PTRACE_EVENT_FORK)
    return 0;

  long newpid;
  ptrace(PTRACE_GETEVENTMSG, context->pid, NULL, (long) &newpid);
  int status;
  waitpid(newpid, &status, 0);

  // ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
  ptrace(PTRACE_DETACH, newpid, NULL, NULL); // XXX

  pid_t child_pid = fork();

  if (child_pid == 0) { // child.
    DEBUG("new pid %d for %ld\n", getpid(), newpid);
    struct process_t process;
    process_init(&process, newpid, context->user_info.func_call);
    process_run(&process);
    process_wait_children(&process);
    process_destroy(&process);
    exit(0);
  } else if (child_pid > 0) { // parent.
    if (process_add_children(context, child_pid)) {
      kill(child_pid, SIGUSR1);
    }
  }

  return 0;
}

int process_add_children(struct process_t* context, pid_t pid) {
  for (int i = 0; i < PROCESS_MAX_COUNT; ++i) {
    if (context->children[i] == 0) {
      context->children[i] = pid;
      return 0;
    }
  }
  return -1;
}

int process_destroy(struct process_t* context) {
  TRACE(" \n");
  DEBUG("pid: %d \n", context->pid);
  ptrace(PTRACE_DETACH, context->pid, NULL, NULL);
  context->pid = 0;
  memset(&context->children, 0x00, sizeof(context->children));
  context->status = 0;
  TRACE("~ \n");
  return 0;
}



// IMPLEMENTATION



struct ic_t { // instruction_callback_t
  long long int ip;    // instruction_pointer
  const char*   shn;   // shared_name
  const char*   fn;    // function_name
  void*         cb;    // callback
  struct context_dl_t dl;
};

int ic_init(struct ic_t* context, const char* shn, const char* fn) {
  TRACE(" \n");
  context->ip = 0;
  context->shn = shn;
  context->fn = fn;
  context->cb = NULL;
  context_dl_init(&context->dl, context->shn);
  TRACE("~ \n");
  return 0;
}

int ic_destroy(struct ic_t* context) {
  TRACE(" \n");
  context->ip = 0;
  context->shn = NULL;
  context->fn = NULL;
  context->cb = NULL;
  context_dl_destroy(&context->dl);
  TRACE("~ \n");
  return 0;
}

int ic_debug(struct ic_t* context){
  TRACE(" \n");
  DEBUG("ic: {ip: %16llx, shn: '%s', fn: '%s', cb: %p} \n",
      context->ip, context->shn, context->fn, context->cb);
  TRACE("~ \n");
  return 0;
}

int ic_set_callback(struct ic_t* context) {
  TRACE(" \n");
  context_dl_sym(&context->dl, context->fn, &context->cb);
  TRACE("~ \n");
  return 0;
}



int pm_init(struct pm_t* context, pid_t pid) {
  TRACE(" \n");
  char maps_path[50];
  snprintf(maps_path, 50, "/proc/%d/maps", pid);

  context->maps = fopen(maps_path, "r");
	if(!context->maps){
		ERROR("  Cannot open the memory maps, %s\n", strerror(errno));
		return -1;
  }

  TRACE("~ \n");
  return 0;
}

int pm_get_ip(struct pm_t* context, const char* fn, long long int* ip) {
  TRACE(" \n");

  char* line = NULL;
  size_t len = 0;

  long long int addr1;
  long long int addr2;
  long long int offset;
  char perm[5] = {};
  char pathname[500] = {};

  rewind(context->maps);

  while ((getline(&line, &len, context->maps)) != -1) {
    sscanf(line, "%llx-%llx %4s %llx %*s %*s %499s", &addr1, &addr2, perm, &offset, pathname);
    // DEBUG("addr: %16llx %16llx %16llx '%s' '%s' \n", addr1, addr2, offset, perm, pathname);
    if ('x' == perm[2] && '/' == pathname[0]) {
      DEBUG("addr: %16llx %16llx %16llx '%s' '%s' \n", addr1, addr2, offset, perm, pathname);

      {
        struct context_symbols_t context_symbols;
        context_symbols_init(&context_symbols, pathname);

        Elf64_Addr addr = 0;
        context_symbols_lookup(&context_symbols, fn, &addr);

        context_symbols_destroy(&context_symbols);

        if (addr) {
          *ip = addr + addr1;
          break;
        }
      }
    }
  }

  // perm == "r-xp" => Use for store text code and const varibles.
  // perm == "r--p" => Use for GNU_RELRO relocated info.
  // perm == "rw-p" => Use for bss data segment.

  TRACE("~ \n");
  return 0;
}

int pm_destroy(struct pm_t* context) {
  TRACE(" \n");

  fclose(context->maps);
  context->maps = NULL;

  TRACE("~ \n");
  return 0;
}



int main(int argc, char ** argv/*, char **envp*/) {
    struct user_info_t info;

    if (argc < 3) {
        ERROR("  Usage: %s elffile pid \n", argv[0]);
        exit(-1);
    }

    signal(SIGUSR1, signal_handler);
    signal(SIGINT,  signal_handler);



    {
      struct ic_t ic;
      ic_init(&ic, "./sample/callbacks.so", "sum_call");

      struct pm_t pm;
      pm_init(&pm, atoi(argv[2]));
      pm_get_ip(&pm, "func_10", &ic.ip);
      pm_destroy(&pm);

      ic_set_callback(&ic);

      // TODO
      info.func_call.ip = ic.ip;
      info.func_call.callback_call = (callback_t) ic.cb;

      ic_debug(&ic);
      // ic_destroy(&ic);
    }



    pid_t child_pid = fork();

    if (child_pid == 0) {
      DEBUG("new pid %d for %d\n", getpid(), atoi(argv[2]));
      struct process_t process;
      process_init(&process, atoi(argv[2]), info.func_call);
      process_run(&process);
      process_wait_children(&process);
      process_destroy(&process);
      exit(0);
    } else if (child_pid > 0) {
      int status;
      creat(LOCK_FILE_NAME, 0777);
      while (1) {
        int status;
        int ret = waitpid(-1, &status, WNOHANG);
        DEBUG("check LOCK file \n");

        if (ret == child_pid) {
          break;
        }

        if (access(LOCK_FILE_NAME, F_OK) != 0) { // LOCK file doesn't exist
          kill(child_pid, SIGUSR1);
          break;
        }

        sleep(TIMEOUT_CHECK_LOCK_FILE);
      }
      waitpid(child_pid, &status, 0);
      remove(LOCK_FILE_NAME);
    }

    return 0;
}

int inject_data(pid_t pid, unsigned char *src, void *dst, int len) {
  int       i;
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

