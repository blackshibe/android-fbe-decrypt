// // derive the password creation settings from the synthetic password blob
//     password_data_struct pwd;
//     Get_Password_Data(TARGET_PWD, "handle", &pwd);

// 	if (pwd.password_type == 2) {
// 		printf("password type: password/PIN\n");
// 	} else if (pwd.password_type == 4) {
// 		printf("password type: password\n");
// 	} else if (pwd.password_type == 1) {
// 		printf("password type: pattern\n");
// 	} else if (pwd.password_type == 3) {
// 		printf("password type: PIN\n");
// 	}

//     printf("scrypt N: %i\n", pwd.scryptN);
//     printf("scrypt R: %i\n", pwd.scryptR);
//     printf("scrypt P: %i\n", pwd.scryptP);

// 	// generate the password token
// 	std::string test_password = "1234";
// 	unsigned char password_token[PASSWORD_TOKEN_SIZE];

// 	if (!Get_Password_Token(&pwd, test_password, &password_token[0])) {
// 		printf("Failed to Get_Password_Token\n");
// 		return EXIT_FAILURE;
// 	}

// 	void* personalized_application_id = PersonalizedHashBinary(PERSONALISATION_APPLICATION_ID, (const void*)&password_token[0], PASSWORD_TOKEN_SIZE);

// 	// first 12 bits of this key are the IV, the rest is the key data
// 	std::string encryption_key = Read_To_String(TARGET_PEM);

// 	// read the encryption key and the encrypted blob
// 	unsigned char* encrypt_byteptr = (unsigned char*)encrypted_blob.data();
// 	unsigned char* ciphertext = (unsigned char*)encrypt_byteptr;


// 	unsigned char plaintext[2048];
// 	int control = aes_256_gcm_decrypt(
// 		(unsigned char*)ciphertext, // cipher text (spblob we are trying to decrypt)
// 		(encrypted_blob.size() - 14),  // cipher text length
// 		(unsigned char*)TAG,  // tag
// 		(unsigned char*)personalized_application_id, 
// 		iv, 
// 		plaintext
// 	);

// 	if (control <= 0) {
// 		printf("\nDecryption failed\n");
// 		return EXIT_FAILURE;
// 	}

// 	printf("Decrypted data: %s\n", plaintext);
