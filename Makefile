
all:
	@make -C sample
	@make -C ptrace_singlestep
	@make -C elf
	@make -C manager

clean:
	@make -C sample clean
	@make -C ptrace_singlestep clean
	@make -C elf clean
	@make -C manager clean

