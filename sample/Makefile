
all:
	gcc -O0 hello.c -o hello
	objdump -S -D hello > hello.dump
	gcc -S hello.c -o hello.s

	gcc -c callbacks.c -o callbacks.o -fPIC
	gcc -shared -o callbacks.so callbacks.o

	gcc -c func.c -o func.o -fPIC -fpic
	gcc -shared -o libfunc.so func.o

	gcc -O3 fork.c -o fork -L. -lfunc -Wl,-rpath=.

clean:
	rm -rf hello hello.dump hello.s
	rm -rf callbacks.o callbacks.so
	rm -rf func.o libfunc.so
	rm -rf fork

