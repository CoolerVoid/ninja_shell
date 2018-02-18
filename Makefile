CC=gcc
CFLAGS=
DFLAGS=-g
LDFLAGS=-Wl,-z,relro,-z,now -lssl -lcrypto
DIR=src/
DIROUT=bin/


server: $(DIR)server.c 
	$(CC) $(CFLAGS) $(DFLAGS) -o $(DIROUT)server $(DIR)server.c  $(LDFLAGS) 
	$(CC) $(CFLAGS) $(DFLAGS) -o $(DIROUT)client $(DIR)client.c $(LDFLAGS)

clean:
	rm -f *.o server
	rm -f *.o client
