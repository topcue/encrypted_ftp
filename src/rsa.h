#include "msg.h"

#ifndef __MYRSA_H__
#define __MYRSA_H__

extern int _pad_unknown(void);
extern int gen_rsa_key_pair(void);
extern int read_pubkey_pem(RSA** rsa_pubkey);

#endif

// EOF
