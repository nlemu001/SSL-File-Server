#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main(int argc, char * argv[])
{
	BIO * bio;
	SSL * ssl;
	SSL_CTX * ctx;

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

// Command line parsing
	if(argc != 2)
	{
		printf("Not enough arguments!\n");
		return 1;
	}
	
	char port[64];
	char * pch;
	pch = strtok(argv[1], "=");
	strcpy(port, pch);
	pch = strtok(NULL, "=");
	strcpy(port, pch);
	printf("Port: %s\n", port);

// Begin SSL

	if(!SSL_library_init())
	{
		printf("Error initializing OpenSSL\n");
		return 1;
	}

// Server context
	ctx = SSL_CTX_new(SSLv23_method());
	if(!ctx)
	{
	  printf("Error creating client SSL context\n");
	  return 1;
	}
	printf("Client context created.\n");
	
	DH* dh = DH_new();
	if(!dh)
	{
	  printf("Error at DH_new\n");
	  return 1;
	}

	if(!DH_generate_parameters_ex(dh, 64,2, 0))
	{
	  printf("Error at DH_generate_parameters_ex\n");
	  return 1;
	}

	int dh_codes;
	if(!DH_check(dh, &dh_codes))
	{
	  printf("Error at DH_check()\n");
	  return 1;
	}
	
	if(!DH_generate_key(dh))
	{
	  printf("Error at DH_generate_key()\n");
	  return 1;
	}

	SSL_CTX_set_tmp_dh(ctx, dh);   
    
	if(SSL_CTX_set_cipher_list(ctx, "ADH-AES256-SHA") != 1)
	{
	    printf("Error setting cipher list\n");
	    return 1;
	}
 // End Server context


	char serv_address[64];
	char * s = "*:";
	strcpy(serv_address, s);
	strcat(serv_address, port);
	printf("BIO Port: %s\n", serv_address);
	bio = BIO_new_accept(serv_address);
	if(!bio)
	{
	  printf("Error creating server BIO\n");
	  return 1;
	}
	if(BIO_do_accept(bio) <= 0)
	{
	  printf("Error accepting BIO object\n");
	  return 1;
	}

	char buf[1024];
	BIO * client;
	for(;;)
	{
	  if(BIO_do_accept(bio) <= 0)
	  {
	    printf("Error accepting BIO object\n");
	  }
	  else
	  {
	    printf("Accepted connection!\n");
	    client = BIO_pop(bio);
	    if (!(ssl = SSL_new(ctx)))
	    {
	      printf("Error creating SSL\n");
	      return 1;
	    }
	    SSL_set_bio(ssl, client, client);
	    if (SSL_accept(ssl) <= 0)
	    {
	      printf("Error accepting SSL\n");
	      return 1;
	    }
	    printf("Connection successful!\n");
	    
	    char buff[256] = {0};
 
	    int r = SSL_read(ssl, buff, sizeof buff);  
	    if (r > 0) {
		printf("Server received: <%s>\n", buff);
		char answer[256] = {0};
		r = sprintf(answer, "I (the server) received this: <%s>", buff);
		SSL_write(ssl, answer, r);
	    }
	    //client = BIO_pop(bio);
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	    /*int x = BIO_read(bio, buf, 1024);
	    if(x == 0)
	    {
		printf("Received message: %s\n", buf);
		BIO_reset(bio);
	    }
	    else if(x < 0)
	    {
		printf("Error reading from socket\n");
	    }*/
	  }
		
	}	
	return 0;
}
