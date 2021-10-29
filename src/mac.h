#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#ifndef __MAC_H__
#define __MAC_H_


void print_it(const char* label, const byte* buff, size_t len)
{
	if(!buff || !len) {
		return;
	}
	if(label) {
		printf("%s: ", label);
	}
	for(size_t i = 0; i < len; ++i) {
		printf("%02X ", buff[i]);

	}
	printf("\n");
}

int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)
{
	/* Returned to caller */
	int result = -1;
	size_t req = 0;
	EVP_MD_CTX* ctx = NULL;
	*sig = NULL;

	ctx = EVP_MD_CTX_create();
	if(ctx == NULL) {
		printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	const EVP_MD* md = EVP_get_digestbyname("SHA256");
	if (md == NULL) {
		printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	int rc = EVP_DigestInit_ex(ctx, md, NULL);
	if(rc != 1){
		printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	rc= EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
	if(rc!=1){
		printf("Evp_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	rc = EVP_DigestSignUpdate(ctx, msg, mlen);
	if(rc != 1){
		printf("EvP_DigestSignUpdate failed, error Ox%lx\n", ERR_get_error());
		return result;
	}
	rc = EVP_DigestSignFinal(ctx, NULL, &req);
	if(rc!=1){
		printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
		return result;
	}

	*sig = OPENSSL_malloc(req);
	if(*sig == NULL){
		printf("OPENSSL_malloc failed error, 0x%lx", ERR_get_error());
		return result;
	}
	*slen = req;
	rc = EVP_DigestSignFinal(ctx, *sig, slen);
	if(rc!=1){
		printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
		return result;
	}

	result = 0;
	if(ctx){
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}

	return result;
}

int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)
{
	/*Returned to caller */
	int result = -1;

	EVP_MD_CTX* ctx = NULL;

	ctx = EVP_MD_CTX_create();
	if(ctx == NULL){
		printf("EVP_MD_cTX_create failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	const EVP_MD* md = EVP_get_digestbyname("SHA256");
	if(md == NULL) {
		printf("EVP_get_digestbyname failed error 0x%lx\n", ERR_get_error());
		return result;
	}

	int rc = EVP_DigestInit_ex(ctx, md, NULL);
	if(rc != 1) {
		printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
	if(rc!=1){
		printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	rc = EVP_DigestSignUpdate(ctx, msg, mlen);
	if(rc!=1){
		printf("EvP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	byte buffer[EVP_MAX_MD_SIZE];
	size_t size = sizeof(buffer);

	rc = EVP_DigestSignFinal(ctx, buffer, &size);
	if(rc != 1){
		printf("EvP_DigestSignFinal failed, error 0x%lx\n", ERR_get_error());
		return result;
	}

	const size_t m = (slen < size ? slen : size);
	result = CRYPTO_memcmp(sig, buffer, m);

	OPENSSL_cleanse(buffer, sizeof(buffer));

	if(ctx) {
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}

	return result;

}


#endif

// EOF

