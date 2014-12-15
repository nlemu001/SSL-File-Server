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
void set_args(char* argv[], char* server, char* port, char * cmd, char * path)
{
	char dummy[64];
	remove_eq(dummy, argv[1]);
	remove_eq(server, NULL);
	remove_eq(dummy, argv[2]);
	remove_eq(port, NULL);
	remove_eq(cmd, argv[3]);
	strcpy(path, argv[4]);
}

int main(int argc, char * argv[])
{
	BIO * bio;
	SSL * ssl;
	SSL_CTX * ctx;
	char receive[64] = "receive";
	char send[64] = "send";
	
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
	printf("Connection successful!\n");
	
// End Create Client Context

// Generating random challenge
	
	unsigned char challenge[64];
	if(RAND_bytes(challenge, 64) != 1)
	{
	  printf("Error generating random challenge.\n");
	  ERR_print_errors_fp(stderr);
	  return 1;
	}
	printf("Unencrypted Challenge: ");
	print_hex(challenge, 64);
	
// End Generating random challenge 

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
//	printf("RSA ENC size: %d\n", enc_size);
	printf("Encrypted Challenge: \n\n");
	print_hex(encrypted_challenge, enc_size);

// End challenge encryption
	
// Writing challenge to server

	int r = SSL_write(ssl, encrypted_challenge, enc_size);
	if(r < 0)
	{
	  printf("Error writing to server\n");
	  return 1;
	}

// End Writing challenge to server

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

// Decrypt server's response

	unsigned char decrypted_response[SHA_DIGEST_LENGTH];
	int dec_res_size = RSA_public_decrypt(r, in_buff, decrypted_response, p_key, RSA_PKCS1_PADDING);
	printf("Decrypted Response: ");
	print_hex(decrypted_response, dec_res_size);
	
// End decrypt server's response

// Comparing signed hash and server response
	
	int j;
	for(j = 0; j < dec_res_size; j++)
	{
	  if(decrypted_response[j] != hash[j])
	  {
	    printf("Hashed values do not match!\n");
	    printf("Shutting off connection.\n");
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	    SSL_CTX_free(ctx);
	    return 1;
	  }
	}
	printf("Server's response and hashed challenge match!\n");
	
// End comparing signed hash and server response

// Sending file command

	r = SSL_write(ssl, cmd, 64);
	if(r < 0)
	{
	  printf("Error sending command to server.\n");
	  return 1;
	}
	// Sending file path
	r = SSL_write(ssl, path, 64);
	if(r < 0)
	{
	  printf("Error sending command to server.\n");
	  return 1;
	}
	
// End sending file command to server

// Receiving file from server

	if(strcmp(cmd, receive) == 0)
	{
	  // Sending file path
	  r = SSL_write(ssl, path, 64);
	  if(r < 0)
	  {
	    printf("Error sending path to server.\n");
	    return 1;
	  }
	  
	  // receive file size
	  char file_size[20];
	  r = SSL_read(ssl, file_size, 20);
	  long fileSize = atol(file_size);
	  //printf("File length: %lu\n", fileSize);
	  
	  // Receiving file
	  char new_file[fileSize];
		long cnt;
		char * file_ptr = new_file;
		for(cnt = 0; cnt < (fileSize/16384) + 1; cnt++)
		{
		  r = SSL_read(ssl, new_file, fileSize);
			file_ptr += 16384;
		}
	  
	  // saving file
	  
	  FILE * file_to_be_saved = fopen(path, "a+");
	  fwrite(new_file, 1, fileSize, file_to_be_saved);
	  fclose(file_to_be_saved);
	  printf("File received!\n");
	}
	
// End receiving file from server

// Send file to server
	else if(strcmp(cmd, send) == 0)
	{
	  char file_size[20];
	  FILE * file_to_be_sent = fopen(path, "r");
	  if(!file_to_be_sent)
	  {
	    printf("File does not exist!\n");
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	    SSL_CTX_free(ctx);
	    file_size[0] = 'n';
	    SSL_write(ssl, file_size, 20);
	    return 1;
	  }
	  else
	  {
	   // read in file from disk
	    fseek(file_to_be_sent, 0, SEEK_END);  
	    long len = ftell(file_to_be_sent);
	    char *ret = malloc(len);  
	    fseek(file_to_be_sent, 0, SEEK_SET);  
	    fread(ret, 1, len, file_to_be_sent);  
	    fclose(file_to_be_sent);
	  // send file size to server
	    
	    sprintf(file_size, "%ld", len);
	    //printf("File length: %s\n", file_size);
		long cnt;	
		r = SSL_write(ssl, (unsigned *)file_size, 20);
		
	    
	  // send file
		char * file_ptr = ret;
		for(cnt = 0; cnt < (len/16384) + 1; cnt++)
		{
		    r = SSL_write(ssl, (unsigned *)file_ptr, len);
			file_ptr += 16384;
		}
	    if(r < 0)
	      printf("Error sending file!\n");
	    printf("File sent!\n");
	  }
	}
	else
	  printf("Invalid command!\n");
// Freeing resources
	SSL_shutdown(ssl);
	SSL_free(ssl);
	printf("SSL connection closed\n");
	SSL_CTX_free(ctx);
	printf("SSL context freed\n");
	printf("Client finished\n");
	return 0;
}

