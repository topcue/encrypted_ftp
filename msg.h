#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>


#ifndef __MSG_H__
#define __MSG_H__

#define BUFSIZE     	1024
#define MAX_CLNT		256
#define HASH_SIZE		32
#define AES_KEY_128 	16
#define AES_BLOCK_LEN	16
#define HEADER_SIZE		8
#define TYPE_SIZE		4
#define LEN_SIZE		4
#define DEBUG 			0

typedef unsigned char byte;

enum MSG_TYPE {
	PUBLIC_KEY_REQUEST,
	PUBLIC_KEY_EXIST,
	PUBLIC_KEY,
	SESSION_KEY,
	SESSION_IV,
	SIGNUP_ID,
	SIGNUP_PW,
	LOGIN_ID,
	LOGIN_PW,
	LOGIN,
	ACK,
	NACK,
	CMD,
	ENCRYPTED_MSG
};

enum CMD_TYPE {
	HELP,
	LIST,
	DOWN,
	UP
};

typedef struct _APP_MSG_ {
	int type;
	int msg_len;
	byte hash[HASH_SIZE];
	byte payload[BUFSIZE+AES_BLOCK_LEN];
} APP_MSG;


typedef struct _FOO_ {
	int sock;
	int type;
	APP_MSG* app_msg;
	byte* buffer;
	int len;
	byte* key;
	byte* iv;
	EVP_PKEY* hmacKey;
} FOO;

#endif

// EOF
