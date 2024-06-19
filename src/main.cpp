#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <libscrypt.h>

#include "twrp/hash/HashPassword.h"
#include "ssl/aes_gcm.h"

// https://cs.android.com/android/platform/superproject/+/android-13.0.0_r1:frameworks/base/services/core/java/com/android/server/locksettings/SyntheticPasswordCrypto.java;l=160;drc=7f9d653deb637e00f0f954a76fc5163fda5b7fd7

#define PASSWORD_TOKEN_SIZE 32
#define TAG "SyntheticPasswordCrypto"
#define PROFILE_KEY_IV_SIZE 12
#define DEFAULT_TAG_LENGTH_BITS 128
#define AES_KEY_LENGTH 32 // 256-bit AES key

/* This is the structure of the data in the password data (*.pwd) file which the structure can be found
 * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#187 */
struct password_data_struct {
	int password_type;
	unsigned char scryptN;
	unsigned char scryptR;
	unsigned char scryptP;
	int salt_len;
	void* salt;
	int handle_len;
	void* password_handle;
};

std::string Read_To_String(const std::string& path) {
    std::ifstream file_handle(path);

    if (file_handle) {
		std::ostringstream ss;
		ss << file_handle.rdbuf(); // reading data

		return ss.str();
    }

	throw std::runtime_error("Failed to read file");
}

bool Get_Password_Data(const std::string& spblob_path, const std::string& handle_str, password_data_struct *pwd) {
	std::string pwd_data = Read_To_String(spblob_path);
	if (pwd_data.empty()) {
		printf("Get_Password_Data pwd_data is empty\n");
		return false;
	}

	const int* intptr = (const int*)pwd_data.data();
	pwd->password_type = *intptr;
	endianswap(&pwd->password_type);

	const unsigned char* byteptr = (const unsigned char*)pwd_data.data() + sizeof(int);
	pwd->scryptN = *byteptr;
	byteptr++;
	pwd->scryptR = *byteptr;
	byteptr++;
	pwd->scryptP = *byteptr;
	byteptr++;
	intptr = (const int*)byteptr;
	pwd->salt_len = *intptr;
	endianswap(&pwd->salt_len);
	if (pwd->salt_len != 0) {
		pwd->salt = malloc(pwd->salt_len);
		if (!pwd->salt) {
			printf("Get_Password_Data malloc salt\n");
			return false;
		}
		memcpy(pwd->salt, intptr + 1, pwd->salt_len);
		intptr++;
		byteptr = (const unsigned char*)intptr;
		byteptr += pwd->salt_len;
	} else {
		printf("Get_Password_Data salt_len is 0\n");
		return false;
	}

	intptr = (const int*)byteptr;
	pwd->handle_len = *intptr;
	endianswap(&pwd->handle_len);

	if (pwd->handle_len != 0) {
		pwd->password_handle = malloc(pwd->handle_len);
		if (!pwd->password_handle) {
			printf("Get_Password_Data malloc password_handle\n");
			return false;
		}
		memcpy(pwd->password_handle, intptr + 1, pwd->handle_len);
	} else {
		printf("Get_Password_Data handle_len is 0\n");
		// Not an error if using weaver
	}

 
	return true;
}

bool Get_Password_Token(const password_data_struct *pwd, const std::string& Password, unsigned char* password_token) {
	if (!password_token) {
		printf("password_token is null\n");
		return false;
	}
	unsigned int N = 1 << pwd->scryptN;
	unsigned int r = 1 << pwd->scryptR;
	unsigned int p = 1 << pwd->scryptP;
	int ret = libscrypt_scrypt(
		reinterpret_cast<const uint8_t*>(Password.data()), 
		Password.size(),
        reinterpret_cast<const uint8_t*>(pwd->salt), 
		pwd->salt_len,
        N, r, p,
		password_token, 
		32
	);

	if (ret != 0) {
		printf("scrypt error\n");
		return false;
	}

	return true;
}

void output_hex(const char* buf, const int size) {
	char hex[size * 2 + 1];
	int index;
	for (index = 0; index < size; index++)
		sprintf(&hex[2 * index], "%02X", buf[index]);
	printf("%s", hex);
}

#define TARGET_PWD "target/9fda7bfaf62651f9.pwd" // synthetic password metadata
#define TARGET_SPBLOB "target/unknown/8e62018d6d05b4f0.spblob" // synthetic password encrypted blob
#define TARGET_PEM "target/unknown/1000_USRPKEY_synthetic_password_8e62018d6d05b4f0" // synthetic password aes key

#define SYNTHETIC_PASSWORD_PASSWORD_BASED 0	
#define SYNTHETIC_PASSWORD_TOKEN_BASED 1

struct spblobFile {
	uint8_t version;
	int type; // either SYNTHETIC_PASSWORD_PASSWORD_BASED or SYNTHETIC_PASSWORD_TOKEN_BASED
	unsigned char* iv;
	unsigned char* ciphertext;
	unsigned int ciphertext_len;
};

bool readSpblobFile(const std::string& path, spblobFile* spblob) {
	std::string spblob_data = Read_To_String(path);
	if (spblob_data.empty()) {
		printf("readSpblobFile spblob_data is empty\n");
		return false;
	}

	unsigned char* data_pointer = (unsigned char*)spblob_data.data();

	int version = *data_pointer;
	data_pointer++;

	int type = *data_pointer;
	data_pointer++;

	spblob->version = version;
	spblob->type = type;
	spblob->iv = (unsigned char*)data_pointer;
	data_pointer += PROFILE_KEY_IV_SIZE;
	spblob->ciphertext = (unsigned char*)data_pointer;
	spblob->ciphertext_len = spblob_data.size() - 14;

	return true;
}

int main() {
	
	spblobFile spblob;
	std::string pem_key = Read_To_String(TARGET_PEM);

	if (!readSpblobFile(TARGET_SPBLOB, &spblob)) {
		printf("Failed to read spblob file\n");
		return EXIT_FAILURE;
	}

	unsigned char tag[16];
	unsigned int data[1024];

	output_hex((const char*)spblob.ciphertext, spblob.ciphertext_len);
	printf("\n");
	output_hex((const char*)spblob.iv, PROFILE_KEY_IV_SIZE);
	printf("\n");


	int result = aes_256_gcm_decrypt(
		spblob.ciphertext, // cipher text (spblob we are trying to decrypt)
		spblob.ciphertext_len,  // cipher text length
		tag,
		(unsigned char*)pem_key.data(), 
		spblob.iv, 
		(unsigned char*)data
	);

	printf("Decrypted data: %i\n", result);

    return EXIT_SUCCESS;
}

