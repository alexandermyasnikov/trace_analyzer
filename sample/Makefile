
all:
	gcc -O0 hello.c -o hello
	objdump -S -D hello > hello.dump
	gcc -S hello.c -o hello.s

	gcc -c callbacks.c -o callbacks.o -fPIC
	gcc -shared -o callbacks.so callbacks.o

clean:
	rm -rf hello hello.dump hello.s
	rm -rf callbacks.o callbacks.so

