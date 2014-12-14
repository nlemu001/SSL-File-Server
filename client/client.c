#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/dh.h>	

// Prints bits into a HEX string
void print_hex(unsigned char * ptr, int sz)
{
  int j;
  for (j = 0; j < sz; j++)
    printf("%02X", ptr[j] & 0xFF);
  printf("\n\n");
}
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

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	
	if(!SSL_library_init())
	{
		printf("Error initializing OpenSSL\n");
		return 1;
	}

	ctx = SSL_CTX_new(SSLv23_client_method());
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
// End Create Client Context
	printf("Connection successful!\n");

// Generating random challenge
	unsigned char challenge[64];
	if(RAND_bytes(challenge, 64) != 1)
	{
	  printf("Error generating random challenge.\n");
	  ERR_print_errors_fp(stderr);
	  return 1;
	}
// End Generating random challenge 

	printf("Unencrypted Challenge: ");
	print_hex(challenge, 64);
    // Hashing the challenge
    
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(challenge, 64, hash);
	printf("Hash value of the challenge: ");
	print_hex(hash, SHA_DIGEST_LENGTH);
    // End hashing challenge

// Encrypting challenge

	BIO * public_key = BIO_new_file("pubrsa.pem", "r");
	if(public_key == NULL)
	{
	  printf("Error reading in public key.\n");
	  return 1;
	}
	RSA * p_key =  PEM_read_bio_RSA_PUBKEY(public_key, NULL, 0, NULL);
	
	int rsa_size = RSA_size(p_key);
	unsigned char encrypted_challenge[rsa_size - 11];
	int enc_size = RSA_public_encrypt(64, challenge, encrypted_challenge, p_key, RSA_PKCS1_PADDING);
	if( enc_size == -1)
	{
	  printf("Error encrypting challenge.\n");
	  return 1;
	}
	printf("RSA ENC size: %d\n", enc_size);
	printf("Encrypted Challenge: \n\n");
	print_hex(encrypted_challenge, enc_size);

// End challenge encryption
	
// Writing challenge to server
	
	//char buf[1024];
	//memset(buf, 0, 1024);
	//strncpy(buf, encrypted_challenge, sizeof encrypted_challenge);
	//for (j = 0; j < enc_size; j++)
	//    printf("%02X", buf[j] & 0xFF);
	//printf("\n\n");
	int r = SSL_write(ssl, encrypted_challenge, enc_size);
	if(r < 0)
	{
	  printf("Error writing to server\n");
	  return 1;
	}

// End Writing to server

// Reading in signed server response
	unsigned char in_buff[enc_size];
	r = SSL_read(ssl, in_buff, enc_size);
	if(r < 0)
	{
	  printf("Error reading from server\n");
	  return 1;
	}
	printf("Server says: \n\n");//, in_buff);
	print_hex(in_buff, sizeof in_buff);
// End reading in signed server response

// Decrypt Server's response
	unsigned char decrypted_response[SHA_DIGEST_LENGTH];
	int dec_res_size = RSA_public_decrypt(r, in_buff, decrypted_response, p_key, RSA_PKCS1_PADDING);
	printf("Decrypted Response: ");//, in_buff);
	print_hex(decrypted_response, dec_res_size);
// End decrypt server's response

// Comparing signed hash and server response
	
	int j;
	for(j = 0; j < dec_res_size; j++)
	{
	  if(decrypted_response[j] != hash[j])
	  {
	    printf("Hashed values do not match!\n");
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	    SSL_CTX_free(ctx);
	    return 1;
	  }
	}
	printf("Server's response and hashed challenge match!\n");
// End comparing signed hash and server response

// Freeing resources
	SSL_shutdown(ssl);
	SSL_free(ssl);
	printf("SSL connection closed\n");
	SSL_CTX_free(ctx);
	printf("SSL context freed\n");
	printf("Client finished\n");
	return 0;
}

