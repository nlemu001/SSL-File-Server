#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>

// Removes '=' and '-' from argumanets to obatin server
// address and port number
int remove_eq(char * new_array, char * arg)
{
	char * pch;
	pch = strtok(arg, "-=");
	strcpy(new_array, pch);
	return 0;
}

// Parses command line arguments
int set_args(char* argv[], char* server, char* port, char * cmd, char * path)
{
	char dummy[64];
	remove_eq(dummy, argv[1]);
	remove_eq(server, NULL);
	remove_eq(dummy, argv[2]);
	remove_eq(port, NULL);
	remove_eq(cmd, argv[3]);
	strcpy(path, argv[4]);
	return atoi(port);
}

int main(int argc, char * argv[])
{
//	SL_CTX *ctx;
//    SSL *ssl;
//    BIO *sbio;
//    int sock;
	if(argc < 5)
	{
		printf("Not enough arguments!\n");
		return 0;
	}

	char server[64];
	char port[64];
	char cmd[64];
	char path[64];
	
	int port_number = set_args(argv, server, port, cmd, path);

	printf("Server: %s\n", server);
	printf("Port #: %d\n", port_number);
	printf("Command: %s\n", cmd);
	printf("File Path: %s\n", path);

	return 0;
}
