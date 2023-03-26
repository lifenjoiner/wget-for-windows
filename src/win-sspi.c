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

#include "wget.h"

#include <winsock2.h>
#include <windows.h>

#include "win-sspi.h"

HMODULE g_hSec_dll = NULL;
PSecurityFunctionTable g_pSSPI;

bool LoadSecurityLibrary(void) {
    OSVERSIONINFO VerInfo;
    INIT_SECURITY_INTERFACE pInitSecurityInterface;

    // secur32.dll is introduced in Windows 2000
    VerInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (!GetVersionEx(&VerInfo)) {
        return false;
    }

    if (g_hSec_dll != NULL) {
        return true;
    }

    if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT && VerInfo.dwMajorVersion == 4) {
        g_hSec_dll = LoadLibrary("security");
    }
    else if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT || VerInfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
        g_hSec_dll = LoadLibrary("secur32");
    }
    else {
        return false;
    }

    if (g_hSec_dll == NULL) {
        logprintf(LOG_NOTQUIET, "Loading security dll failed!\n");
        goto FAIL;
    }

    // Init SSPI
    pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(g_hSec_dll, "InitSecurityInterfaceA");
    if (pInitSecurityInterface == NULL) {
        goto FAIL;
    }
    g_pSSPI = pInitSecurityInterface();
    if (g_pSSPI == NULL) {
        goto FAIL;
    }

    atexit(UnloadSecurityLibrary);
    return true;

FAIL:
	UnloadSecurityLibrary();
	return false;
}

void UnloadSecurityLibrary(void) {
    FreeLibrary(g_hSec_dll);
    g_hSec_dll = NULL;
}


void InitSecBuffer(SecBuffer *buffer, unsigned long cbBuf, void *pBuf, unsigned long BufType) {
  buffer->cbBuffer = cbBuf;
  buffer->BufferType = BufType;
  buffer->pvBuffer = pBuf;
}

void InitSecBufferDesc(SecBufferDesc *desc, unsigned long cBuf, SecBuffer *pBufArr) {
  desc->ulVersion = SECBUFFER_VERSION;
  desc->cBuffers = cBuf;
  desc->pBuffers = pBufArr;
}

/* more details:
    https://docs.microsoft.com/en-us/windows/win32/secauthn/schannel-error-codes-for-tls-and-ssl-alerts
    https://chromium.googlesource.com/chromium/src/net/+/master/cert/cert_verify_proc_win.cc
    https://github.com/microsoft/referencesource/blob/master/System/net/System/Net/_SecureChannel.cs
    https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_status
*/
char *sspi_strerror(SECURITY_STATUS err) {
#define ERR2TXT(err) case err: txt = #err; break
    char *txt;
    static char hex[11] = {0};
    switch (err) {
    ERR2TXT(CERT_E_INVALID_NAME);
    ERR2TXT(CERT_E_REVOKED);
    ERR2TXT(CRYPT_E_REVOKED);
    ERR2TXT(CRYPT_E_NO_REVOCATION_CHECK);
    ERR2TXT(CRYPT_E_REVOCATION_OFFLINE);
    ERR2TXT(SEC_E_ALGORITHM_MISMATCH);
    ERR2TXT(SEC_E_CERT_EXPIRED);
    ERR2TXT(SEC_E_UNTRUSTED_ROOT);
    ERR2TXT(SEC_E_WRONG_PRINCIPAL);
    default: sprintf(hex, "0x%08lX", err); txt = hex; break;
    }
    return txt;
}

