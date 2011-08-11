
all:	test

test:	test.c
	gcc -g -pthread -o test test.c -L.. -lplebnet  -I../include

clean:
	rm -f test test.core