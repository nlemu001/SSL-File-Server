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
#include <openssl/sha.h>

// Prints bits into a HEX string
void print_hex(unsigned char * ptr, int sz)
{
  int j;
  for (j = 0; j < sz; j++)
    printf("%02X", ptr[j] & 0xFF);
  printf("\n\n");
}


int main(int argc, char * argv[])
{
	BIO * bio;
	SSL * ssl;
	SSL_CTX * ctx;

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

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	if(!SSL_library_init())
	{
		printf("Error initializing OpenSSL\n");
		return 1;
	}

// Server context
	ctx = SSL_CTX_new(SSLv23_server_method());
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
	
	// Ensures OpenSSL doesn't send a certificate to the client
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	
	if(SSL_CTX_set_cipher_list(ctx, "ADH-AES256-SHA") != 1)
	{
	    printf("Error at SSL_CTX_set_cipher_list()\n");
	    return 1;
	}
 // End Server context

// Start Server loop
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
	    
	    unsigned char buff[1024];
	    memset(buff, 0, 1024);
	    int r = SSL_read(ssl, buff, sizeof buff);
	    printf("Bytes read: %d\n", r);
	    printf("Received challenge: \n\n");
	    print_hex(buff, r);

    // Decrypting using Private key
	      
	    BIO * private_key = BIO_new_file("rsakey.pem", "r");
	    if(private_key == NULL)
	    {
	      printf("Error reading in private key.\n");
	      return 1;
	    }
	    RSA * p_key =  PEM_read_bio_RSAPrivateKey(private_key, NULL, 0, NULL);
	    
	    int rsa_size = RSA_size(p_key);
	    unsigned char decrypted_challenge[rsa_size];
	    int dec_size = RSA_private_decrypt(r, buff, decrypted_challenge, p_key, RSA_PKCS1_PADDING);
	    if( dec_size == -1)
	    {
	      printf("Error decrypting challenge.\n");
	      return 1;
	    }
	    printf("RSA DEC size: %d\n", dec_size);
	    printf("Decrypted Challenge: ");
	    
	    print_hex(decrypted_challenge, dec_size);
    
    // End Decryption
    
    // Hashing the decrypted challenge
    
	    unsigned char hash[SHA_DIGEST_LENGTH];
	    SHA1(decrypted_challenge, dec_size, hash);
	    
	    printf("Hash value of decrypted_challenge: ");
	    print_hex(hash, SHA_DIGEST_LENGTH);
	    
    // End Hashing the decypted challenge
    
    // Signing the hashed challenge
	    unsigned char signed_challenge[rsa_size - 11];
	    int signed_size = RSA_private_encrypt(SHA_DIGEST_LENGTH, hash, signed_challenge, p_key, RSA_PKCS1_PADDING);
	    if( signed_size == -1)
	    {
	      printf("Error decrypting challenge.\n");
	      return 1;
	    }
	    printf("RSA Signed size: %d\n", signed_size);
	    printf("Signed Challenge: \n");
	    
    // Sending signed hashed challenge to client
	    print_hex(signed_challenge, signed_size);
	    r = SSL_write(ssl, signed_challenge, signed_size);
	    printf("Bytes sent: %d\n", r);
    // End sending signed hashed challenge to client

	    SSL_shutdown(ssl);
	    SSL_free(ssl);

	  }
	
	}
	return 0;
}
