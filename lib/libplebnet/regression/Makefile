
all:	test tcpconnect

test:	test.c
	gcc -g -pthread -o test test.c -L.. -lplebnet  -I../include

tcpconnect:	tcpconnect.c
	gcc -g -pthread -o tcpconnect tcpconnect.c -L.. -lplebnet  -I../include

clean:
	rm -f test test.core