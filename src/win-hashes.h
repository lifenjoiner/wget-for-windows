/* Windows hashes wrapper.
   Copyright (C) 2020-2020 Free Software Foundation,
   Inc.
   Originally contributed by YX Hao.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

GNU Wget is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wget.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this program, or any covered work, by linking or
combining it with the OpenSSL project's OpenSSL library (or a
modified version of that library), containing parts covered by the
terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
grants you additional permission to convey the resulting work.
Corresponding Source for a non-source form of such a combination
shall include the source code for the parts of OpenSSL used as well
as that of the covered work.  */


#ifndef __WIN_HASHES_H__
#define __WIN_HASHES_H__

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

#define hash_block  hash_update

#define MD2_DIGEST_SIZE 16
#define md2_ctx         _CRYPT_CTX
#define md2_init_ctx(ctx)                   hash_init(CALG_MD2, ctx)
#define md2_process_bytes(buff, len, ctx)   hash_update(ctx, buff, len)
#define md2_process_block(buff, len, ctx)   hash_update(ctx, buff, len)
#define md2_finish_ctx(ctx, hash)           hash_final(ctx, hash)
#define md2_buffer(buff, len, hash)         hash_buffer(CALG_MD2, buff, len, hash)

#define MD4_DIGEST_SIZE 16
#define md4_ctx         _CRYPT_CTX
#define md4_init_ctx(ctx)                   hash_init(CALG_MD4, ctx)
#define md4_process_bytes(buff, len, ctx)   hash_update(ctx, buff, len)
#define md4_process_block(buff, len, ctx)   hash_update(ctx, buff, len)
#define md4_finish_ctx(ctx, hash)           hash_final(ctx, hash)
#define md4_buffer(buff, len, hash)         hash_buffer(CALG_MD4, buff, len, hash)
// OpenSSL style
#define MD4_CTX         CRYPT_CTX
#define MD4_Init(ctx)                       hash_init(CALG_MD4, ctx)
#define MD4_Update(ctx, buff, len)          hash_update(ctx, buff, len)
#define MD4_Final(hash, ctx)                hash_final(ctx, hash)

#define MD5_DIGEST_SIZE 16
#define md5_ctx         _CRYPT_CTX
#define md5_init_ctx(ctx)                   hash_init(CALG_MD5, ctx)
#define md5_process_bytes(buff, len, ctx)   hash_update(ctx, buff, len)
#define md5_process_block(buff, len, ctx)   hash_update(ctx, buff, len)
#define md5_finish_ctx(ctx, hash)           hash_final(ctx, hash)
#define md5_buffer(buff, len, hash)         hash_buffer(CALG_MD5, buff, len, hash)

#define SHA1_DIGEST_SIZE    20
#define sha1_ctx            _CRYPT_CTX
#define sha1_init_ctx(ctx)                      hash_init(CALG_SHA1, ctx)
#define sha1_process_bytes(buff, len, ctx)      hash_update(ctx, buff, len)
#define sha1_process_block(buff, len, ctx)      hash_update(ctx, buff, len)
#define sha1_finish_ctx(ctx, hash)              hash_final(ctx, hash)
#define sha1_buffer(buff, len, hash)            hash_buffer(CALG_SHA1, buff, len, hash)

#define SHA256_DIGEST_SIZE  32
#define sha256_ctx          _CRYPT_CTX
#define sha256_init_ctx(ctx)                    hash_init(CALG_SHA_256, ctx)
#define sha256_process_bytes(buff, len, ctx)    hash_update(ctx, buff, len)
#define sha256_process_block(buff, len, ctx)    hash_update(ctx, buff, len)
#define sha256_finish_ctx(ctx, hash)            hash_final(ctx, hash)
#define sha256_buffer(buff, len, hash)          hash_buffer(CALG_SHA_256, buff, len, hash)

#define SHA384_DIGEST_SIZE  46
#define sha384_ctx          _CRYPT_CTX
#define sha384_init_ctx(ctx)                    hash_init(CALG_SHA_384, ctx)
#define sha384_process_bytes(buff, len, ctx)    hash_update(ctx, buff, len)
#define sha384_process_block(buff, len, ctx)    hash_update(ctx, buff, len)
#define sha384_finish_ctx(ctx, hash)            hash_final(ctx, hash)
#define sha384_buffer(buff, len, hash)          hash_buffer(CALG_SHA_384, buff, len, hash)

#define SHA512_DIGEST_SIZE  64
#define sha512_ctx          _CRYPT_CTX
#define sha512_init_ctx(ctx)                    hash_init(CALG_SHA_512, ctx)
#define sha512_process_bytes(buff, len, ctx)    hash_update(ctx, buff, len)
#define sha512_process_block(buff, len, ctx)    hash_update(ctx, buff, len)
#define sha512_finish_ctx(ctx, hash)            hash_final(ctx, hash)
#define sha512_buffer(buff, len, hash)          hash_buffer(CALG_SHA_512, buff, len, hash)


typedef struct _CRYPT_CTX {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
} CRYPT_CTX, *P_CRYPT_CTX;

void hash_init(ALG_ID id, CRYPT_CTX *ctx);
void hash_update(CRYPT_CTX *ctx, const unsigned char *data, unsigned int len);
void * hash_final(CRYPT_CTX *ctx, unsigned char *digest);
void * hash_buffer(ALG_ID id, const char *buffer, size_t len, unsigned char *digest);


// the following needs gnulib

#define BLOCKSIZE 32768
#if BLOCKSIZE % 64 != 0
# error "invalid BLOCKSIZE"
#endif

#define md2_stream(stream, digest)      hash_stream(CALG_MD2, "md2", stream, digest, MD2_DIGEST_SIZE)
#define md4_stream(stream, digest)      hash_stream(CALG_MD4, "md4", stream, digest, MD4_DIGEST_SIZE)
#define md5_stream(stream, digest)      hash_stream(CALG_MD5, "md5", stream, digest, MD5_DIGEST_SIZE)
#define sha1_stream(stream, digest)     hash_stream(CALG_SHA1, "sha1", stream, digest, SHA1_DIGEST_SIZE)
#define sha256_stream(stream, digest)   hash_stream(CALG_SHA_256, "sha256", stream, digest, SHA256_DIGEST_SIZE)
#define sha384_stream(stream, digest)   hash_stream(CALG_SHA_384, "sha384", stream, digest, SHA384_DIGEST_SIZE)
#define sha512_stream(stream, digest)   hash_stream(CALG_SHA_512, "sha512", stream, digest, SHA512_DIGEST_SIZE)

int hash_stream(ALG_ID id, char *alg, FILE *stream, unsigned char *digest, size_t hashlen);

#endif
