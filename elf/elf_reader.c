
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

void read_elf(void* addr, int size) {
  if (sizeof(Elf64_Ehdr) > (size_t) size)
    return;

  // typedef struct
  // {
  //   unsigned char        e_ident[EI_NIDENT];        /* Magic number and other info */
  //   Elf64_Half        e_type;                        /* Object file type */
  //   Elf64_Half        e_machine;                /* Architecture */
  //   Elf64_Word        e_version;                /* Object file version */
  //   Elf64_Addr        e_entry;                /* Entry point virtual address */
  //   Elf64_Off        e_phoff;                /* Program header table file offset */
  //   Elf64_Off        e_shoff;                /* Section header table file offset */
  //   Elf64_Word        e_flags;                /* Processor-specific flags */
  //   Elf64_Half        e_ehsize;                /* ELF header size in bytes */
  //   Elf64_Half        e_phentsize;                /* Program header table entry size */
  //   Elf64_Half        e_phnum;                /* Program header table entry count */
  //   Elf64_Half        e_shentsize;                /* Section header table entry size */
  //   Elf64_Half        e_shnum;                /* Section header table entry count */
  //   Elf64_Half        e_shstrndx;                /* Section header string table index */
  // } Elf64_Ehdr;

  Elf64_Ehdr* elf_hdr;
  elf_hdr = (Elf64_Ehdr*) addr;

  fprintf(stderr, "e_ident:     %.*s \n", EI_NIDENT, elf_hdr->e_ident);
  fprintf(stderr, "e_type:      %hx  \n", elf_hdr->e_type);
  fprintf(stderr, "e_machine:   %hx  \n", elf_hdr->e_machine);
  fprintf(stderr, "e_version:   %x   \n", elf_hdr->e_version);
  fprintf(stderr, "e_entry:     %lx  \n", elf_hdr->e_entry);
  fprintf(stderr, "e_phoff:     %lx  \n", elf_hdr->e_phoff);
  fprintf(stderr, "e_shoff:     %lx  \n", elf_hdr->e_shoff);
  fprintf(stderr, "e_flags:     %x   \n", elf_hdr->e_flags);
  fprintf(stderr, "e_ehsize:    %hx  \n", elf_hdr->e_ehsize);
  fprintf(stderr, "e_phentsize: %hx  \n", elf_hdr->e_phentsize);
  fprintf(stderr, "e_phnum:     %hx  \n", elf_hdr->e_phnum);
  fprintf(stderr, "e_shentsize: %hx  \n", elf_hdr->e_shentsize);
  fprintf(stderr, "e_shnum:     %hx  \n", elf_hdr->e_shnum);
  fprintf(stderr, "e_shstrndx:  %hx  \n", elf_hdr->e_shstrndx);

  // Program header (Phdr)

  // typedef struct
  // {
  //   Elf64_Word        p_type;                        /* Segment type */
  //   Elf64_Word        p_flags;                /* Segment flags */
  //   Elf64_Off        p_offset;                /* Segment file offset */
  //   Elf64_Addr        p_vaddr;                /* Segment virtual address */
  //   Elf64_Addr        p_paddr;                /* Segment physical address */
  //   Elf64_Xword        p_filesz;                /* Segment size in file */
  //   Elf64_Xword        p_memsz;                /* Segment size in memory */
  //   Elf64_Xword        p_align;                /* Segment alignment */
  // } Elf64_Phdr;

  for (int i = 0; i < elf_hdr->e_phnum; ++i) {
    Elf64_Phdr* elf_phdr;
    elf_phdr = (Elf64_Phdr*) (addr + elf_hdr->e_phoff + i * sizeof(Elf64_Phdr));

    fprintf(stderr, " \n");
    fprintf(stderr, "p_type:      %x   \n", elf_phdr->p_type);
    fprintf(stderr, "p_flags:     %x   \n", elf_phdr->p_flags);
    fprintf(stderr, "p_offset:    %lx  \n", elf_phdr->p_offset);
    fprintf(stderr, "p_vaddr:     %lx  \n", elf_phdr->p_vaddr);
    fprintf(stderr, "p_paddr:     %lx  \n", elf_phdr->p_paddr);
    fprintf(stderr, "p_filesz:    %lx  \n", elf_phdr->p_filesz);
    fprintf(stderr, "p_memsz:     %lx  \n", elf_phdr->p_memsz);
    fprintf(stderr, "p_align:     %lx  \n", elf_phdr->p_align);
  }

  // Section header (Shdr)

  // typedef struct
  // {
  //   Elf64_Word        sh_name;                /* Section name (string tbl index) */
  //   Elf64_Word        sh_type;                /* Section type */
  //   Elf64_Xword        sh_flags;                /* Section flags */
  //   Elf64_Addr        sh_addr;                /* Section virtual addr at execution */
  //   Elf64_Off        sh_offset;                /* Section file offset */
  //   Elf64_Xword        sh_size;                /* Section size in bytes */
  //   Elf64_Word        sh_link;                /* Link to another section */
  //   Elf64_Word        sh_info;                /* Additional section information */
  //   Elf64_Xword        sh_addralign;                /* Section alignment */
  //   Elf64_Xword        sh_entsize;                /* Entry size if section holds table */
  // } Elf64_Shdr;

  for (int i = 0; i < elf_hdr->e_shnum; ++i) {
    Elf64_Shdr* elf_shdr;
    elf_shdr = (Elf64_Shdr*) (addr + elf_hdr->e_shoff + i * sizeof(Elf64_Shdr));

    fprintf(stderr, " \n");
    fprintf(stderr, "sh_name:     %x   \n", elf_shdr->sh_name);
    fprintf(stderr, "sh_type:     %x   \n", elf_shdr->sh_type);
    fprintf(stderr, "sh_flags:    %lx  \n", elf_shdr->sh_flags);
    fprintf(stderr, "sh_addr:     %lx  \n", elf_shdr->sh_addr);
    fprintf(stderr, "sh_offset:   %lx  \n", elf_shdr->sh_offset);
    fprintf(stderr, "sh_size:     %lx  \n", elf_shdr->sh_size);
    fprintf(stderr, "sh_link:     %x   \n", elf_shdr->sh_link);
    fprintf(stderr, "sh_info:     %x   \n", elf_shdr->sh_info);
    fprintf(stderr, "sh_addralign:%lx  \n", elf_shdr->sh_addralign);
    fprintf(stderr, "sh_entsize:  %lx  \n", elf_shdr->sh_entsize);
  }
}

int main(int argc, char ** argv/*, char** envp*/) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s elffile \n", argv[0]);
    exit(-1);
  }

  struct stat st;
  int fd = open(argv[1], O_RDONLY);

  if (fd < 0) {
    perror("open");
    exit(-1);
  }

  if (fstat(fd, &st) < 0) {
    perror("fstat");
    exit(-1);
  }

  void* addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (addr == MAP_FAILED) {
    perror("mmap");
    exit(-1);
  }

  read_elf(addr, st.st_size);

  munmap(addr, st.st_size);
  close(fd);

  return 0;
}
