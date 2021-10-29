#include "msg.h"

int _pad_unknown(void)
{
	unsigned long l;
	while((l = ERR_get_error()) != 0) {
		if(ERR_GET_REASON(l) == RSA_R_UNKNOWN_PADDING_TYPE) {
			return (1);
		}
	}
	return 0;
}

// for server
int gen_rsa_key_pair(void)
{
	int ret = 0;
	int num;
	RSA* rsa;
	BIO* bp_public = NULL;
	BIO* bp_private = NULL;

	unsigned long e_value = RSA_F4;
	BIGNUM* exponent_e = BN_new();

	rsa = RSA_new();

	BN_set_word(exponent_e, e_value);

	// RSA key gen
	if(RSA_generate_key_ex(rsa, 2048, exponent_e, NULL) == NULL) {
		fprintf(stderr, "RSA_generate_key_ex() error");
		ret = -1;
		goto err;
	}

	// write "public.pem"
	bp_public = BIO_new_file("./dirServerSecret/public.pem", "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
	if(ret != 1) {
		goto err;
	}

	// write "private.pem"
	bp_private = BIO_new_file("./dirServerSecret/private.pem", "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
	if(ret != 1) {
		goto err;
	}

err:
	RSA_free(rsa);
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);

	return ret;
}

// for client
int read_pubkey_pem(RSA** rsa_pubkey)
{
    int ret = 0;

    BIO* bp_public = NULL;
    RSA* read_pubkey = NULL;

    bp_public = BIO_new_file("./dirClient/public.pem", "r");
    if(!PEM_read_bio_RSAPublicKey(bp_public, &read_pubkey, NULL, NULL)) {
        ret = -1;
        goto err;
    }

    memcpy(rsa_pubkey, &read_pubkey, sizeof(RSA*));
    ret = 1;

err:
    if(bp_public) {
        BIO_free(bp_public);    
    }
    
    return ret;
}


// EOF
