
# export LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH

all: hello fork many_sample func_sample callbacks.so

hello: hello.c
	echo making $@ ...
	gcc -O0 hello.c -o hello
	gcc -S hello.c -o hello.s
	objdump -S -D hello > hello.dump

fork: fork.c libfunc.so
	echo making $@ ...
	gcc -O0 fork.c -o fork -L. -lfunc

many_sample: many_sample.c libmany.so
	echo making $@ ...
	gcc -O3 many_sample.c -o many_sample -L. -lmany

func_sample: func_sample.c libfunc.so
	echo making $@ ...
	gcc -O0 func_sample.c -o func_sample -L. -lfunc



callbacks.so: callbacks.c
	echo making $@ ...
	gcc -c callbacks.c -o callbacks.o -fPIC
	gcc -shared -o callbacks.so callbacks.o

libfunc.so: func.c
	echo making $@ ...
	gcc -c func.c -o func.o -fPIC
	gcc -shared -o libfunc.so func.o

libmany.so: many.c
	echo making $@ ...
	gcc -O3 -c many.c -o many.o -fPIC
	gcc -O3 -shared -o libmany.so many.o



clean:
	rm -rf hello hello.dump hello.s
	rm -rf fork
	rm -rf many_sample
	rm -rf func_sample
	rm -rf callbacks.o callbacks.so
	rm -rf libfunc.so func.o
	rm -rf libmany.so many.o

