/*
 Copyright (c) 2019 MariaDB Corporation

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include <my_global.h>
#include <string.h>

#include <my_crypt.h>
#define PROTYPES_H
#include <nss.h>
#include "prerror.h"
#include "pk11pub.h"

typedef struct {
  PK11SlotInfo *slot;
  PK11Context *ctx;
  CK_MECHANISM_TYPE Cipher;
  PK11SymKey *EncryptionKey;
  SECItem *EncryptionIV;
  int flags;
  const uchar *src;
  unsigned int slen;
  unsigned int buf_len;
  uchar key[32];
  unsigned int keylen;
  char oiv[MY_AES_BLOCK_SIZE];
  unsigned int oivlen;
  my_bool fixed;
} NSS_CIPHER_CTX;

/* ma_pkcs7_pad 
   Simple PKCS7 padding implementation, as described in RFC 5652
   The value of each byte added is the number of bytes added:
   03 04 05 01 02 04 01 F1 08 08 08 08 08 08 08 08
   If the length is a multiple of blocksize, and entire block of size
   block size will be added or removed
   if mode is set (=add) size of source must be at least len + blocksize.
 */
static int ma_pkcs7_pad(unsigned char *src,
    unsigned int *len,
    unsigned int block_size,
    unsigned char add)
{
  if (add)
  {
    unsigned int new_len;
    unsigned char pad;

    new_len= (*len / block_size + 1) * block_size;
    pad= new_len - *len;

    memset((char *)src + *len, pad, (size_t)pad);
    *len= new_len;
  } else {
    unsigned char pad[MY_AES_BLOCK_SIZE];
    unsigned char pad_len= *(src - 1);
    /* Either we are in wrong mode or decrypted string
       doesn't has padding - so we will return an error */
    if (pad_len > MY_AES_BLOCK_SIZE)
      return 1;
    memset(pad, pad_len, pad_len);
    if (memcmp(src - pad_len, pad, pad_len) == 0)
      *len= pad_len;
  }
  return 0;
}

/* ma_internal_pad: 
   internal padding: 
   We don't fill up to the next blocksize but en/decrypt the remaining bytes
   with XOR operation
*/
static unsigned int ma_internal_pad(NSS_CIPHER_CTX *ctx,
    unsigned char *src,
    unsigned char *dst,
    unsigned int *slen)
{
  unsigned char mask[MY_AES_BLOCK_SIZE];
  unsigned int i, masklen, pad_len;
  pad_len= *slen % MY_AES_BLOCK_SIZE;

  if (!pad_len)
    return 0;

  *slen-= pad_len;

  my_aes_crypt(MY_AES_ECB, ENCRYPTION_FLAG_ENCRYPT | ENCRYPTION_FLAG_NOPAD,
      (uchar *)ctx->oiv, ctx->oivlen, mask, &masklen, ctx->key, ctx->keylen, 0, 0);
  for (i=0; i < pad_len; i++)
    dst[*slen + i]= src[*slen + i] ^ mask[i];
  return pad_len;
}

/* clear ctx:
   clear contest, frees all internal variables, but not
   the context structure itself */
static void clear_ctx(NSS_CIPHER_CTX *ctx)
{
  if (ctx->slot)
   PK11_FreeSlot(ctx->slot);
  if (ctx->EncryptionKey)
    PK11_FreeSymKey(ctx->EncryptionKey);
  if (ctx->EncryptionIV)
    SECITEM_FreeItem(ctx->EncryptionIV, PR_TRUE);

  if (ctx->ctx)
    PK11_DestroyContext(ctx->ctx, PR_TRUE);

  memset(ctx, 0, sizeof(NSS_CIPHER_CTX));
}

int my_aes_crypt_init(void *cctx, enum my_aes_mode mode, int flags,
                      const unsigned char* key, unsigned int klen,
                      const unsigned char* iv, unsigned int ivlen)
{
  int rc= MY_AES_OPENSSL_ERROR;
  NSS_CIPHER_CTX *ctx= (NSS_CIPHER_CTX *)cctx;
  SECItem ivItem= {0, (unsigned char *)iv, ivlen}, 
          keyItem= {0, (unsigned char *)key, klen};
  CK_AES_CTR_PARAMS ctr_params;

  /* do some checks first */
  if (!key || !klen || klen > MY_AES_MAX_KEY_LENGTH)
    return MY_AES_BAD_KEYSIZE;

  if (ivlen > MY_AES_BLOCK_SIZE)
    return MY_AES_BAD_KEYSIZE;

  /* make sure context is properly initialized */
  memset(ctx, 0, sizeof(NSS_CIPHER_CTX));

  ctx->flags= flags;

  memcpy(ctx->key, key, klen);
  ctx->keylen= klen;
  if (iv && ivlen)
  {
    memcpy(ctx->oiv, iv, ivlen);
    ctx->oivlen= ivlen;
  }

  /* Map cipher names */
  switch (mode) {
  case MY_AES_ECB:
    ctx->Cipher= CKM_AES_ECB;
    ctx->fixed= 1;
    break;
  case MY_AES_CBC:
    ctx->Cipher= CKM_AES_CBC;
    ctx->fixed= 1;
    break;
  case MY_AES_CTR:
    ctx->Cipher= CKM_AES_CTR;
    memcpy(ctr_params.cb, iv, ivlen);
    ctr_params.ulCounterBits= ivlen * 8;
    ivItem.data= (uchar *)&ctr_params;
    ivItem.len= sizeof(ctr_params);
    break;
  default:
    return MY_AES_BAD_DATA;
  }

  ctx->slot= PK11_GetInternalSlot();
  if (!(ctx->EncryptionKey= PK11_ImportSymKey(ctx->slot, ctx->Cipher, PK11_OriginUnwrap, CKA_ENCRYPT,
                                              &keyItem, NULL)))
    goto error;

  if (!(ctx->EncryptionIV= PK11_ParamFromIV(ctx->Cipher, &ivItem)))
    goto error;

  /* create context */
  if (!(ctx->ctx= PK11_CreateContextBySymKey(ctx->Cipher, (flags & ENCRYPTION_FLAG_ENCRYPT) ?
                                             CKA_ENCRYPT : CKA_DECRYPT, ctx->EncryptionKey, ctx->EncryptionIV)))
    goto error;

  return 0;

error:
  clear_ctx(ctx);
  return rc;
}


int my_aes_crypt_update(void *cctx, const uchar *src, uint slen,
                        uchar *dst, uint *dlen)
{
  NSS_CIPHER_CTX *ctx= (NSS_CIPHER_CTX *)cctx;
  unsigned int len= slen;
  int rc= 0;

  if (ctx->fixed)
    len= (slen / MY_AES_BLOCK_SIZE) * MY_AES_BLOCK_SIZE;

  /* We need to pad before encryption */

  if ((ctx->flags & (ENCRYPTION_FLAG_ENCRYPT | ENCRYPTION_FLAG_NOPAD)) && ctx->fixed)
  {
    if (!(ctx->flags & ENCRYPTION_FLAG_NOPAD))
    {
      unsigned int left = slen - len;
      ma_pkcs7_pad((uchar *)dst + len, &left, MY_AES_BLOCK_SIZE, 1);
      len += left;
    }
  }

  if (len)
  {
    rc = PK11_CipherOp(ctx->ctx, dst, (int *)dlen, len, dst, len);
    if (rc != SECSuccess || !*dlen)
    {
      return 1;
    }
  }
  else
    return 1;
  /* After decryption we need to remove padding */
  if (ctx->fixed && 
      !(ctx->flags & ENCRYPTION_FLAG_ENCRYPT) && 
      !(ctx->flags & ENCRYPTION_FLAG_NOPAD))
  {
    unsigned int remove_len;
    if (ma_pkcs7_pad((uchar *)dst + len, &remove_len, MY_AES_BLOCK_SIZE, 0))
    {
      return 1;
    }
    *dlen-= remove_len;
  }

  if (ctx->flags & ENCRYPTION_FLAG_NOPAD)
  {
    unsigned int left= slen - len;
    *dlen+= ma_internal_pad(ctx, (uchar *)src + len, dst + len, &left);
  }

  return MY_AES_OK;
}

int my_aes_crypt_finish(void *cctx, uchar *dst __attribute__((unused)), uint *dlen)
{
  NSS_CIPHER_CTX *ctx= (NSS_CIPHER_CTX *)cctx;

  if (PK11_Finalize(ctx->ctx) != SECSuccess)
    return 1;

  /* clear cipher context */
  clear_ctx((NSS_CIPHER_CTX *)cctx);
  return MY_AES_OK;
}

int my_aes_crypt(enum my_aes_mode mode, int flags,
                 const uchar *src, uint slen, uchar *dst, uint *dlen,
                 const uchar *key, uint klen, const uchar *iv, uint ivlen)
{

  void *ctx= alloca(MY_AES_CTX_SIZE);
  int res1, res2;
  uint d1= 0, d2= 0;

  if ((res1= my_aes_crypt_init(ctx, mode, flags, key, klen, iv, ivlen)))
    return res1;

  memcpy(dst, src, slen);
  res1= my_aes_crypt_update(ctx, (flags & ENCRYPTION_FLAG_ENCRYPT) ? dst : src, slen, dst, &d1);
  res2= my_aes_crypt_finish(ctx, dst + d1, &d2);
  if (!res1 && !res2)
    *dlen= d1 + d2;
  return res1 ? res1 : res2;
}


/*
  calculate the length of the cyphertext from the length of the plaintext
  for different AES encryption modes with padding enabled.
  Without padding (ENCRYPTION_FLAG_NOPAD) cyphertext has the same length
  as the plaintext
*/
unsigned int my_aes_get_size(enum my_aes_mode mode __attribute__((unused)), unsigned int source_length)
{
  if (mode == MY_AES_CTR)
    return source_length;
  return (source_length / MY_AES_BLOCK_SIZE + 1) * MY_AES_BLOCK_SIZE;
}

unsigned int my_aes_ctx_size(enum my_aes_mode mode __attribute__((unused)))
{
  return sizeof(NSS_CIPHER_CTX);
}

int my_random_bytes(uchar *buf, int num)
{
  if (PK11_RandomUpdate((void *)buf, num) != SECSuccess)
    return MY_AES_OPENSSL_ERROR;
  return MY_AES_OK;
}

