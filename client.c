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
#include <openssl/bio.h>
#include <openssl/err.h>

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
	BIO * bio;
	SSL * ssl;
	SSL_CTX * ctx;
	
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	
	if(!SSL_library_init())
	{
		printf("Error initializing OpenSSL\n");
		return 1;
	}
	
	if(argc < 5)
	{
		printf("Not enough arguments!\n");
		return 1;
	}

	char server[64];
	char port[64];
	char cmd[64];
	char path[64];
	char address[1024];	
	set_args(argv, server, port, cmd, path);
	
	strcpy(address, server);
	strcat(address, ":");
	strcat(address, port);
	
	//printf("Server: %s\n", server);
	//printf("Port #: %d\n", port_number);
	//printf("Command: %s\n", cmd);
	//printf("File Path: %s\n", path);
	//printf("Address: %s\n\n", address);

	// Setting up Client context
	ctx = SSL_CTX_new(SSLv23_method());
	if(!ctx)
	{
	  printf("Error setting up client SSL context\n");
	  ERR_print_errors_fp(stderr);
	  return 1;
	}
	printf("Client context created.\n");
	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	
	if(SSL_CTX_set_cipher_list(ctx, "ADH-AES256-SHA") != 1)
	{
	  printf("Error setting client cipher list\n");
	  return 1;
	}
	
	bio = BIO_new_connect(address);
	//bio = BIO_set_conn_int_port(bio, port_number);
	if(bio == NULL)
	{
	  printf("There was a problem creating the BIO object\n");
	  return 1;
	}
	if(BIO_do_connect(bio) <= 0)
	{
	  printf("BIO connection failed\n");
	  return 1;
	}
	ssl = SSL_new(ctx);
	if(!ssl)
	{
	  printf("Error creating client SSL\n");
	  return 1;
	}
	SSL_set_bio(ssl, bio, bio);
	printf("Connecting to server...\n");
	if(SSL_connect(ssl) <= 0)
	{
	  printf("Error connecting to server\n");
	  return 1;
	}
	

	printf("Connection successful!\n");
	
	// Writing to server
	char buf[1024];
	strcpy(buf, "This is client.");
	if(SSL_write(ssl, buf, sizeof buf) < 0)
	{
	  printf("Error writing to server\n");
	  return 1;
	}
	
	char in_buff[1024];
	if(SSL_read(ssl, in_buff, 1024) < 0)
	{
	  printf("Error reading from server\n");
	  return 1;
	}
	printf("Server says: %s\n", in_buff);
	
	SSL_shutdown(ssl);
	SSL_free(ssl);
	printf("SSL connection closed\n");
	SSL_CTX_free(ctx);
	printf("SSL context freed\n");
	//BIO_free_all(bio);
	printf("Client finished\n");
	return 0;
}
