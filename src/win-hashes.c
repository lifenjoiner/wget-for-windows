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


/* Used definitions
metalink.c:
md2_stream
md4_stream
md5_stream
sha1_stream

sha224_stream <== no: https://docs.microsoft.com/en-us/windows/win32/seccrypto/hash-and-signature-algorithms

sha256_stream
sha384_stream
sha512_stream

--
md4
http-ntlm.c:
MD4_CTX
MD4_Init
MD4_Update
MD4_Final

Need DES. We use native SSPI.

--
md5
http.c/ftp-opie.c:
md5_ctx

md5_init_ctx
md5_process_bytes
md5_finish_ctx

--
sha1
warc.c:
sha1_ctx
sha1_init_ctx
sha1_process_block
sha1_process_bytes
sha1_finish_ctx
sha1_stream

--
sha256
utils.c:
sha256_buffer

--
des
http-ntlm.c:
Not hash. We use native SSPI.
*/


#include "wget.h"

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

#include "win-hashes.h"

/* Ref:
    https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta
    https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptographic-provider-types

PROV_RSA_AES Hashing:
MD2
MD4
MD5
SHA-1
SHA-2 (SHA-256, SHA-384, and SHA-512)
*/
void hash_init(ALG_ID id, CRYPT_CTX *ctx) {
    if (CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptCreateHash(ctx->hCryptProv, id, 0, 0, &ctx->hHash);
    }
}

void hash_update(CRYPT_CTX *ctx, const void *data, unsigned int len) {
    CryptHashData(ctx->hHash, (const BYTE *)data, (DWORD)len, 0);
}

void * hash_final(CRYPT_CTX *ctx, void *digest) {
    DWORD length;

    // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgethashparam
    if (CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0)) { // <-- finish and get result length
        CryptGetHashParam(ctx->hHash, HP_HASHVAL, (BYTE *)digest, &length, 0);
    }
    if (ctx->hHash) CryptDestroyHash(ctx->hHash);
    if (ctx->hCryptProv) CryptReleaseContext(ctx->hCryptProv, 0);

    return digest;
}


void * hash_buffer(ALG_ID id, const void *buffer, unsigned int len, void *digest) {
    CRYPT_CTX ctx;

    hash_init(id, &ctx);
    hash_update(&ctx, buffer, len);
    return hash_final(&ctx, digest);
}

// the following needs gnulib

#include "af_alg.h"

int hash_stream(ALG_ID id, char *alg, FILE *stream, void *digest, size_t hashlen) {
    CRYPT_CTX ctx;
    char *buffer;
    size_t sum, n;

    switch (afalg_stream(stream, alg, digest, hashlen)) {
    case 0: return 0;
    case -EIO: return 1;
    }

    buffer = malloc(BLOCKSIZE + 72);
    if (!buffer) return 1;

    hash_init(id, &ctx);

    while (1) {
        sum = 0;
        while (1) {
            if (feof(stream)) goto process_partial_block;
            n = fread(buffer + sum, 1, BLOCKSIZE - sum, stream);
            sum += n;
            if (sum == BLOCKSIZE) break;
            if (n == 0) {
                if (ferror(stream)) {
                    free(buffer);
                    return 1;
                }
                goto process_partial_block;
            }
        }
        hash_update(&ctx, (const unsigned char *)buffer, BLOCKSIZE);
    }

process_partial_block:
    if (sum > 0) hash_update(&ctx, (const unsigned char *)buffer, sum);

    hash_final(&ctx, digest);
    free(buffer);
    return 0;
}
