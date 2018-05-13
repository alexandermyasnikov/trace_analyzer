
all:
	@make -C sample
	@make -C ptrace_singlestep

clean:
	@make -C sample clean
	@make -C ptrace_singlestep clean

