#include "msg.h"

#ifndef __UTIL_H__
#define __UTIL_H__

extern void err(char* msg);
extern int get_user_input(byte* buffer);

extern int check_rsa_key_exist(void);
extern int check_pubkey_exist(void);

extern int signup(int type, byte* buffer);
extern int login(int type, byte* buffer);

extern int extract_fname1(byte* buffer, byte* dir, byte* fname);
extern int extract_fname2(byte* buffer, byte* dir, byte* fname);

extern int get_CMD_TYPE(byte* buffer);
extern int get_list(byte* buffer);
extern int show_list(int sock, APP_MSG* msg_in, byte* buffer, int len, byte* key, byte* iv, EVP_PKEY* hmacKey);
extern int file_check(byte* fname, int len);

extern int send_msg(int sock, int type, APP_MSG* msg_out, byte* buffer, int len);
extern int send_encmsg(int sock, int type, APP_MSG* msg_out, byte* buffer, int len, byte* key, byte* iv, EVP_PKEY* hmacKey);

extern int recv_msg(int sock, APP_MSG* msg_in);
extern int recv_encmsg(int sock, APP_MSG* msg_in, byte* buffer, byte* key, byte* iv, EVP_PKEY* hmacKey);

extern int send_file_foo(FOO* foo);
extern int recv_file_foo(FOO* foo);

#endif

// EOF
