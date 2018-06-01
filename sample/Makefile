
all:
	gcc -O0 hello.c -o hello
	objdump -S -D hello > hello.dump
	gcc -S hello.c -o hello.s

	gcc -c callbacks.c -o callbacks.o -fPIC
	gcc -shared -o callbacks.so callbacks.o

	gcc -c func.c -o func.o -fPIC
	gcc -shared -o libfunc.so func.o

	gcc -O3 -c many.c -o many.o -fPIC
	gcc -O3 -shared -o libmany.so many.o

	gcc -O0 fork.c -o fork -L. -lfunc -Wl,-rpath=.

	gcc -O3 many_sample.c -o many_sample -L. -lmany -Wl,-rpath=.

clean:
	rm -rf hello hello.dump hello.s
	rm -rf callbacks.o callbacks.so
	rm -rf func.o libfunc.so
	rm -rf many.o libmany.so
	rm -rf fork
	rm -rf many_sample

