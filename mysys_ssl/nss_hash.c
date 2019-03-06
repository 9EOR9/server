/* Copyright (c) 2018 MariaDB

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA */

#if defined(HAVE_NSS)

#define PROTYPES_H
#include <my_global.h>
#include <stdarg.h>

#include <nss.h>
#include <prprf.h>
#include <prtypes.h>
#include <plgetopt.h>
#include <prio.h>

/* NSS headers */
#include <secoid.h>
#include <secmodt.h>
#include <sechash.h>

typedef struct {
  HASHContext *ctx;
  unsigned int resultlen;
} CONTEXT;

size_t nss_hash_context_size()
{
  return sizeof(CONTEXT);
}

static void nss_hash_init(CONTEXT *context, SECOidTag hashOIDTag)
{
  HASH_HashType type= HASH_GetHashTypeByOidTag(hashOIDTag);
  if (!NSS_IsInitialized())
    NSS_NoDB_Init(NULL);
  context->ctx= HASH_Create(type);
  context->resultlen= HASH_ResultLen(type);
  HASH_Begin(context->ctx);
}

static void nss_hash_input(CONTEXT *context, const uchar *buf, unsigned len)
{
  HASH_Update(context->ctx, (uchar *)buf, len);
}

static void nss_hash_result(CONTEXT *context, uchar *digest)
{
  unsigned int result;
  HASH_End(context->ctx, digest, &result, context->resultlen);
  HASH_Destroy(context->ctx);
}

static void nss_hash(uchar *digest, SECOidTag oidtag, const char *buf, size_t len)
{
  CONTEXT ctx;
  memset(&ctx, 0, sizeof(CONTEXT));
  nss_hash_init(&ctx, oidtag);
  nss_hash_input(&ctx, (uchar *)buf, (unsigned)len);
  nss_hash_result(&ctx, digest);
}

#define NSS_HASH_FUNC(f,alg)\
size_t my_ ## f ## _context_size()\
{\
  return sizeof(CONTEXT);\
}\
void my_ ## f ##_init(void *context)\
{\
  nss_hash_init((CONTEXT *)context, (alg));\
}\
void my_ ## f ## _input(void *context, const uchar *buf, size_t len)\
{\
  nss_hash_input((CONTEXT *)context, buf, (uint) len);\
}\
void my_ ## f ## _result(void *context, uchar *digest)\
{\
  nss_hash_result((CONTEXT *)context, digest);\
}\
void my_ ## f (uchar *digest, const char *buf, size_t len)\
{\
  nss_hash(digest, (alg), buf, len);\
}\
void my_ ## f ## _multi(uchar *digest, ...)\
{\
  va_list args;\
  CONTEXT ctx;\
  const uchar *str;\
  nss_hash_init(&ctx, (alg));\
  va_start(args, digest);\
  for (str= va_arg(args, const uchar*); str; str= va_arg(args, const uchar*))\
    nss_hash_input(&ctx, str, (uint) va_arg(args, size_t));\
  nss_hash_result(&ctx, digest);\
  va_end(args);\
}

NSS_HASH_FUNC(md5,SEC_OID_MD5)
NSS_HASH_FUNC(sha1,SEC_OID_SHA1)
NSS_HASH_FUNC(sha224,SEC_OID_SHA224)
NSS_HASH_FUNC(sha256,SEC_OID_SHA256)
NSS_HASH_FUNC(sha384,SEC_OID_SHA384)
NSS_HASH_FUNC(sha512,SEC_OID_SHA512)

#endif /* HAVE_NSS */
