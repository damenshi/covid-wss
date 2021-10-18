#ifndef __CBC128_H
#define __CBC127_H

#include "modes_local.h"
void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key, unsigned char ivec[16],
                           block128_f block);

void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key, unsigned char ivec[16],
                           block128_f block);
#endif
