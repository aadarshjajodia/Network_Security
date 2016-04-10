all: clean pbproxy

pbproxy: pbproxy.c
	gcc -g pbproxy.c -o pbproxy -Werror -lcrypto -lpthread -I /usr/local/include/node/

clean:
	rm -f *~ *.o *.out
