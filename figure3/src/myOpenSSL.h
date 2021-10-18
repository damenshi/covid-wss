#ifndef MYOPENSSL_H 
#define MYOPENSSL_H


#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

 

/*
int My_AES_gcm_encrypt( 
		unsigned char *out,
		unsigned char *in, 
		int inlen, 
		const unsigned char *key);
int My_AES_gcm_decrypt(
		unsigned char * out,
		unsigned char * in, int inlen,
		const unsigned char * key);

*/

void random_scalar_generation(secp256k1_scalar *num);
void random_scalar_generation_halfq(secp256k1_scalar *num);

  int stringCompare(const unsigned char *ch1,  const unsigned char *ch2,  const int size);


void shake128_absorb(uint64_t *s,
                     const unsigned char *input,
                     unsigned long long inlen);

void shake128_squeezeblocks(unsigned char *output,
                            unsigned long nblocks,
                            uint64_t *s);

void shake256_absorb(uint64_t *s,
                     const unsigned char *input,
                     unsigned long long inlen);

void shake256_squeezeblocks(unsigned char *output,
                            unsigned long nblocks,
                            uint64_t *s);

void shake128(unsigned char *output,
              unsigned long long outlen,
              const unsigned char *input,
              unsigned long long inlen);

void shake256(unsigned char *output,
              unsigned long long outlen,
              const unsigned char *input,
              unsigned long long inlen);

 

		
#endif
 
