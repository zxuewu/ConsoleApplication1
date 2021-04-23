/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SM2_H
# define HEADER_SM2_H
# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_SM2

#  ifdef __cplusplus
extern "C" {
#  endif

#  include <openssl/ec.h>
#  include <openssl/evp.h>

typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

/* The default user id as specified in GM/T 0009-2012 */
#  define SM2_DEFAULT_USERID "1234567812345678"

int SM2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key);

BIGNUM *SM2_compute_msg_hash(const EVP_MD *digest,
                        const EC_KEY *key,
                        const uint8_t *id,
                        const size_t id_len,
                        const uint8_t *msg, size_t msg_len);
/*
 * SM2 signature operation. Computes Z and then signs H(Z || msg) using SM2
 */
ECDSA_SIG *SM2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const uint8_t *id,
                       const size_t id_len,
                       const uint8_t *msg, size_t msg_len);

int SM2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *signature,
                  const uint8_t *id,
                  const size_t id_len,
                  const uint8_t *msg, size_t msg_len);

/*
 * SM2 signature generation.
 */
int SM2_sign(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/*
 * SM2 signature verification.
 */
int SM2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int siglen, EC_KEY *eckey);

/*
 * SM2 encryption
 */
BIGNUM *SM2_Ciphertext_get0_x(SM2_Ciphertext *cipher);
BIGNUM *SM2_Ciphertext_get0_y(SM2_Ciphertext *cipher);
ASN1_OCTET_STRING *SM2_Ciphertext_get0_c(SM2_Ciphertext *cipher);
ASN1_OCTET_STRING *SM2_Ciphertext_get0_m(SM2_Ciphertext *cipher);

int SM2_Ciphertext_set0(SM2_Ciphertext *cipher,
    BIGNUM *x, BIGNUM *y, ASN1_OCTET_STRING *m, ASN1_OCTET_STRING *c);

int SM2_Ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size);

int SM2_Plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                       size_t *pt_size);

int SM2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len,
                uint8_t *ciphertext_buf, size_t *ciphertext_len);

int SM2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len);

/*
 * SM2 DH
 */
int SM2_compute_share_key(int is_initiator, EC_KEY *pri_key, EC_KEY *tmp_pri_key, EC_KEY *peer_pub, EC_KEY *peer_tmp_pub,
    const char *id, const char *peer_id, EVP_MD *md, unsigned char *out, size_t outlen);

#  ifdef __cplusplus
}
#  endif

# endif /* OPENSSL_NO_SM2 */
#endif
