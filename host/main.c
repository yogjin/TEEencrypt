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

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	uint32_t encrypted_randomKey;
	FILE *fp;
	int len=64;
	char *option = argv[1];
	char *algorithm = argv[3];

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	// TA와 공유하는 buffer: tmpref 할당
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	/*
	 * 실행 커맨드
	 * 암호화: TEEencrypt -e [평문파일(.txt)][알고리즘]
	 * 복호화: TEEencrypt -d [암호문 + 암호화키 파일]
	 * 알고리즘 = Ceaser | RSA(암호화만 구현) 
	 */

	if (strcmp(algorithm, "Ceaser") == 0) {
		if (strcmp(option, "-e") == 0) {
			printf("========================Ceaser Encryption========================\n");

			// (1) CA에서 평문 텍스트 파일 읽기, TA 호출
			fp = fopen(argv[2], "r");
			fgets(plaintext, sizeof(plaintext), fp);
			printf("Plaintext: %s\n", plaintext);
			memcpy(op.params[0].tmpref.buffer, plaintext, len);

			/* invokeCommand 로직 (TA_TEEencrypt_CMD_ENC_VALUE)
			 * (2) TA에서 랜덤키 생성
			 * (3) 랜덤키로 평문 암호화, 랜덤키는 TA의 root키로 암호화 (전부 시저암호 사용)
			 */ 
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

			/*
			 * (4) TA에서 CA로 암호문 + 암호화된 TA키 전달
			 * (5) CA는 받은 암호문, 암호화된 키를 파일로 저장
			 * 암호화된 텍스트는 op.params[0].tmpref.buffer에 있음
			 * 암호화된 비밀키는 op.params[0].value.a에 있음
			 */
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			encrypted_randomKey = op.params[1].value.a;

			printf("Ciphertext : %s\n", ciphertext);
			printf("Encrypted_randomKey : %d\n", encrypted_randomKey);
			
			fp = fopen("Ceaser_ciphertext.txt","w");
			fprintf(fp, "%s", ciphertext);
			printf("Ceaser_ciphertext.txt is created\n");

			fp = fopen("Ceaser_key.txt","w");
			fprintf(fp, "%d", encrypted_randomKey);
			printf("Ceaser_key.txt is created\n");

			fclose(fp);
		}
		else if (strcmp(option, "-d") == 0) {

		}
	}

	else if(strcmp(algorithm, "RSA") == 0) {
		if (strcmp(option, "-e") == 0) {

		}
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
