/* Windows SSPI public part.
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


/* SSPI declarations for using Windows encryption/decryption
    For: https, ftps; NTLM
    Todo: Digest, Kerberos
    4 types on Win:
    https://docs.microsoft.com/en-us/windows/win32/secauthn/ssp-packages-provided-by-microsoft
    HTTP/1.1 Authentication:
    https://tools.ietf.org/html/rfc7235
    https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
*/

#ifndef __WIN_SSPI_H__
#define __WIN_SSPI_H__

#include <stdbool.h>

#define SECURITY_WIN32
#include <sspi.h>

extern HMODULE g_hSec_dll;
extern PSecurityFunctionTable g_pSSPI;

bool LoadSecurityLibrary(void);
void UnloadSecurityLibrary(void);

void InitSecBuffer(SecBuffer *buffer, unsigned long cbBuf, void *pBuf, unsigned long BufType);
void InitSecBufferDesc(SecBufferDesc *desc, unsigned long cBuf, SecBuffer *pBufArr);
char *sspi_strerror(SECURITY_STATUS err);

#endif
