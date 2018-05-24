
all:
	gcc -O0 hello.c -o hello
	objdump -S -D hello > hello.dump
	gcc -S hello.c -o hello.s

	gcc -c callbacks.c -o callbacks.o -fPIC
	gcc -shared -o callbacks.so callbacks.o

	gcc -O0 fork.c -o fork

clean:
	rm -rf hello hello.dump hello.s
	rm -rf callbacks.o callbacks.so
	rm -rf fork

