/*
	Author: Kunal Baweja
	Date: 04-Jan-2014
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

int aes_256_gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
			int aad_len, unsigned char *key, unsigned char *iv,
			unsigned char *ciphertext, unsigned char *tag);

int aes_256_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, 
						unsigned char *tag, unsigned char *key, unsigned char *iv,
						unsigned char *plaintext
					);
