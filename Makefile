SOURCES = client.c server.c

CC = gcc

COMFLAGS = -Wall

OBJECTS = client server

default: $(SOURCES)

client: client.c
	$(CC) $(COMFLAGS) client.c -o client -lcrypto -lssl

server: server.c
	$(CC) $(COMFLAGS) server.c -o server -lcrypto -lssl

clean:
	rm -rf *.out *.o *~ $(OBJECTS)
