
#include "cbc128.h"
#include "sm4.h"
#include "util.h"
#include "str.h"

static const unsigned char gvec[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};


/**
 * \breif  使用CBC模式加密数据
 *
 * \param in  待加密的明文数据
 * \param inlen 待加密的数据长度
 * \param out 加密后的数据
 * \param ks  加密所用的密钥
 *
 * \return 返回加密后的密文数据长度, 其长度为16的整数倍
 */
static int SM4_encrypt_cbc(const uint8_t *in, size_t inlen, uint8_t *out,
                    const SM4_KEY *ks) {
  unsigned char ivec[16] = {0};
  size_t outlen;
  size_t mod = 0;
  memcpy(ivec, gvec, sizeof(ivec));
  if (inlen % 16 == 0) {
    mod = (inlen >> 4);
  } else {
    mod = (1 + (inlen >> 4));
  }
  outlen = mod * 16;
  CRYPTO_cbc128_encrypt(in, out, inlen, ks, ivec, SM4_encrypt);
  return outlen;
}

/**
 * \breif  使用CBC模式解密数据
 *
 * \param in  待解密的密文数据
 * \param inlen 待解密的数据长度
 * \param out 解密后的数据
 * \param ks  解密所用的密钥
 *
 * \return 返回解密后的密文数据长度, 其长度为16的整数倍
 */
static int SM4_decrypt_cbc(const uint8_t *in, size_t inlen, uint8_t *out,
                    const SM4_KEY *ks) {
  unsigned char ivec[16] = {0};
  unsigned char ivec2[16] = {0};
  int i = inlen;
  memcpy(ivec2, in + inlen - 16, 16);
  memcpy(ivec, gvec, sizeof(ivec));
  CRYPTO_cbc128_decrypt(in, out, inlen, ks, ivec, SM4_decrypt);
  
  for (i = inlen; i > 1; i--) {
    if (out[i - 1] != 0x00) {
      break;
    }
  }
  return i;
}


/**
 * \breif 加密任意长度的数据
 *
 * \param out 加密后的数据，其长度为16字节整数倍
 * \param in  待加密的明文数据
 * \param inlen 待加密的数据长度
 * \param key  加密所用的密钥
 *
 * \return 返回加密后的密文数据长度
 *
 */
int encrypt(unsigned char *out, unsigned char *in, int inlen,
               const unsigned char *key) {

  SM4_KEY sm4key;
  SM4_set_key(key, &sm4key);
  return SM4_encrypt_cbc(in, inlen, out, &sm4key);
}


/**
 * \breif 解密任意长度的数据
 *
 * \param out 解密后的数据，
 * \param in  待解密的密文数据
 * \param inlen 待解密的数据长度
 * \param key  解密所用的密钥
 *
 * \return 返回解密后的明文数据长度
 *
 */
int decrypt(unsigned char *out, unsigned char *in, int inlen,
               const unsigned char *key) {
  SM4_KEY sm4key;
  SM4_set_key(key, &sm4key);
  return SM4_decrypt_cbc(in, inlen, out, &sm4key);
}


