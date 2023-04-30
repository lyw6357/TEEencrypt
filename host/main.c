/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#include <unistd.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[64] = {0, };
	char ciphertext[64] = {0, };
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];
	int encKey;
	FILE* fp;
	
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);

   	memset(&op, 0, sizeof(op));
   	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 
					 TEEC_VALUE_INOUT, 
					 TEEC_MEMREF_TEMP_INPUT, 
					 TEEC_MEMREF_TEMP_OUTPUT); 

	if (strcmp(argv[1], "-e") == 0){
		fp = fopen(argv[2], "r");
		if(fp == NULL){
			perror("Plaintext file not found");
			return 1;
		}
		fread(plaintext, 1, 64, fp);
		fclose(fp);

		printf("\n==================== Encryption ====================\n");
		printf("-------------------- Plaintext --------------------\n%s\n", plaintext);

		if (strcmp(argv[3], "Caesar") == 0){
   			op.params[0].tmpref.buffer = plaintext;
   			op.params[0].tmpref.size = 64;

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENCRYPT, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, 64);
			
			printf("-------------------- Ciphertext --------------------\n%s\n", ciphertext);
			
                	fp = fopen("ciphertext.txt", "w");
			fputs(ciphertext, fp); 
			fclose(fp);

			fp = fopen("encryptedkey.txt", "w");
			int enc_key = op.params[1].value.a;
			fprintf(fp, "%d", enc_key);
			fclose(fp);
		}
		else if(strcmp(argv[3], "RSA") == 0){
			op.params[2].tmpref.buffer = clear;
			op.params[2].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
			op.params[3].tmpref.buffer = ciph;
			op.params[3].tmpref.size = RSA_CIPHER_LEN_1024;
		
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_GENKEYS, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand failed %#x\n", res);
			memcpy(op.params[2].tmpref.buffer, plaintext, RSA_MAX_PLAIN_LEN_1024);
			
			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_ENCRYPT, &op, &err_origin);
			if(res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand failed 0x%x origin 0x%x\n", res, err_origin);
			memcpy(ciph, op.params[3].tmpref.buffer, 64);
			
			printf("\n-------------------- Ciphertext --------------------\n%s\n", ciph);

			fp = fopen("ciphertext_RSA.txt", "w");
			fputs(ciph, fp);
			fclose(fp);
		}
		else{
			perror("Undefined algorithmn\n");
			return 1;
		}
   	}
   	else if (strcmp(argv[1], "-d") == 0){ 
   		op.params[0].tmpref.buffer = ciphertext;
   		op.params[0].tmpref.size = 64;

		fp = fopen(argv[2], "r");
		if (fp == NULL){
			perror("Ciphertext file not found");
			return 1;
		}
		fread(ciphertext, 1, 64, fp);
		fclose(fp);

		printf("\n==================== Decryption ====================\n");
		printf("-------------------- Ciphertext --------------------\n%s\n", ciphertext);

		fp = fopen(argv[3], "r");
		if (fp == NULL){
			perror("Encryptedkey file not found");
			return 1;
		}
		fscanf(fp, "%d", &encKey);
		fclose(fp);
        
		memcpy(op.params[0].tmpref.buffer, ciphertext, 64);
		op.params[1].value.a = encKey;

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DECRYPT, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		memcpy(plaintext, op.params[0].tmpref.buffer, 64);
		
		printf("-------------------- Plaintext --------------------\n%s\n", plaintext);

		fp = fopen("plaintext.txt", "w");
		fputs(plaintext, fp);
		fclose(fp);
   	}
   	else{
		perror("Undefined command option\n");
		return 1;
   	}

   	TEEC_CloseSession(&sess);
   	TEEC_FinalizeContext(&ctx);
   	return 0;
}
