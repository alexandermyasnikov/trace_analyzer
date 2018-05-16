
#include <stdlib.h>
#include <stdio.h>
#include "elf_utils.h"

int main(int argc, char ** argv/*, char** envp*/) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s elffile \n", argv[0]);
    exit(-1);
  }

  int fd;
  off_t st_size;
  Elf64_Ehdr* elf;

  if (open_elf(argv[1], &fd, &st_size, &elf)) {
    perror("open_elf");
  }

  print_elf(elf);
  Elf64_Addr addr = lookup_symbol(elf, "func");
  fprintf(stderr, "addr: %lx \n", addr);

  if (close_elf(&fd, &st_size, &elf)) {
    perror("close_elf");
  }

  return 0;
}

