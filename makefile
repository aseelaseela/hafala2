CC=gcc
CFLAGS=-lcrypto -lm

all: server_b asyncClient

server_b: server_b.c
	$(CC) -o server_b server_b.c $(CFLAGS)

asyncClient: asyncClient.c
	$(CC) -o asyncClient asyncClient.c $(CFLAGS)

clean:
	rm -f server_b asyncClient