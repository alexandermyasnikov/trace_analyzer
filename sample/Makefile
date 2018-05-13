
all:
	gcc -O0 hello.c -o hello
	objdump -S -D hello > hello.dump
	gcc -S hello.c -o hello.s

clean:
	rm -rf hello hello.dump hello.s

