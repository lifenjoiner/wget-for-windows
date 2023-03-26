/* http-ntlm support via SSPI.
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


/* NTLM over http References
    MS intro:
    https://docs.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview

    [MS-NTHT]: NTLM Over HTTP Protocol:
    https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NTHT/[MS-NTHT].pdf
    ==> [MS-NLMP]

    Hash versions:
    https://en.wikipedia.org/wiki/NT_LAN_Manager

    Security:
    https://docs.microsoft.com/en-us/windows/win32/seccertenroll/cryptoapi-cryptographic-service-providers

    x [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol:
    x https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/[MS-NLMP].pdf

    *Win API*:
    https://docs.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--ntlm

    NTLM is a challenge-response authentication protocol:
    First, the client establishes a network path to the server and sends a NEGOTIATE_MESSAGE advertising its capabilities.
    Next, the server responds with CHALLENGE_MESSAGE which is used to establish the identity of the client.
    Finally, the client responds to the challenge with an AUTHENTICATE_MESSAGE.
    AcquireCredentialsHandle -> InitializeSecurityContext -> CompleteAuthToken -> QueryContextAttributes -> InitializeSecurityContext

    MS example:
    https://docs.microsoft.com/en-us/windows/win32/secauthn/using-sspi-with-a-windows-sockets-client
*/

/* NTLM Handshake
=====   ======================================== ============= =========================================== |
win:  0   /--- QuerySecurityPackageInfo()                                                                  |
          \--> cbMaxToken            -------\ !ISC_REQ_ALLOCATE_MEMORY                                     |
                                            |      ^                                                       |
      1    /-- AcquireCredentialsHandle() <-/      |                                                       |
           |                                       |                                                       |
      3 /--+-- InitializeSecurityContext() <-\ <---/                                                       |
      c |  |                                 |                                                             |
        |  \-> PCredHandle >------2------+-+-/                                                             |
     +- +----> PCtxtHandle >~~~~~~~4~~~~~| |                                                               |
     +- \----> PSecBufferDesc_out >-5-7--+ |                       AcquireCredentialsHandle() --\          |
     |    /7d-/                       |  a b                                                    |          |
     |  /-+-a> PSecBufferDesc_in >--a-+--/ |                     /-> AcceptSecurityContextt() --+--\       |
     |  | |                           7    |                     |                              |  |       |
     \6-+-+--> CompleteAuthToken() >--/    |                     \--=+----------< PCtxtHandle <-+--|       |
        \-+-------------a-\                |                         +----------< PCredHandle <-/  |       |
      7 d \-+> base64()  -+----------8---e-+->   =-8-e\ /-9-f=   <-------- PSecBufferDesc_out <----|       |
            |                              |           x                                           |       |
            \--9---------------------------+--   <----/ \---->              PSecBufferDesc_in >----/       |
                                           b                                                               |
        https: QueryContextAttributes() -+ |                                                               |
               SecPkgContext_Bindings   -+-/                                                               |
                                                                                                           |
=====   ======================================== ============= =========================================== |
               Client                                                 Server                               |
=====   ======================================== ============= =========================================== |
        httpRequest                                -------->                                               |
        Get ...                                                httpResponse                                |
                                                               401 Unauthorized                            |
                                                   <--------   WWW-Authenticate: NTLM                      |
        Get ...                                                                                            |
      8 Authorization: NTLM base64-type1-message   -------->                                               |
                                                               401 Unauthorized                            |
      9                                            <--------   WWW-Authenticate: NTLM base64-type2-message |
        GET ...                                                                                            |
      e Authorization: NTLM base64-type3-message   -------->                                               |
      f                                            <--------   200 OK                                      |
.....   ........................................ ............. ........................................... +
               Client                                                 Proxy                                |
.....   ........................................ ............. ........................................... |
                                                               407 Proxy Authentication Required           |
        Proxy-Authorization: NTLM base64-message    <~~~~~>    Proxy-Authenticate: NTLM                    |
=====   ======================================== ============= =========================================== |

type1: [MS-NLMP]:2.2.1.1 NEGOTIATE_MESSAGE
type2: [MS-NLMP]:2.2.1.2 CHALLENGE_MESSAGE
type3: [MS-NLMP]:2.2.1.3 AUTHENTICATE_MESSAGE

CHALLENGE_MESSAGE:
    Index   Description         Content
    0       Signature           Null-terminated ASCII "NTLMSSP\x00"
    8       MessageType         4 bytes (0x00000002)
    12      TargetNameFields    8 bytes (len 2 + MaxLen 2 + offset 4)
    20      NegotiateFlags      4 bytes struct `NEGOTIATE`
    24      ServerChallenge     8 bytes `nonce`
    32      Reserved            8 bytes (MUST be zero)
    40      TargetInfoFields    8 bytes (len 2 + MaxLen 2 + offset 4)
    48      Version             8 bytes struct `VERSION`
    56      Payload             variable (TargetName + TargetInfo + padding)

SSPI take in charge the whole MESSAGE.
*/

/* Another way
    https://www.innovation.ch/personal/ronald/ntlm.html
    https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-signing-a-hash-and-verifying-the-hash-signature
    CryptImportKey, CryptCreateHash, CALG_DES, CryptHashData, CryptSignHash, CryptDestroyHash
    There is likely a way to implemente the `DES_ecb_encrypt` ...
     https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_crypto.c
*/

#include "wget.h"

#include "http-ntlm.h" // store whole MESSAGE instead of `nonce`

#include "win-sspi.h"

#include "log.h"
#include "utils.h" // base64


// https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_a
static void ntlm_gen_identity(char *domain, char *user, char *passwd, SEC_WINNT_AUTH_IDENTITY *pId) {
    pId->User = (unsigned char *)user;
    pId->UserLength = strlen(user);
    pId->Domain = (unsigned char *)domain;
    pId->DomainLength = strlen(domain);
    pId->Password = (unsigned char *)passwd;
    pId->PasswordLength = strlen(passwd);
    pId->Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
}

static bool ntlm_create_type1_message(struct ntlmdata *ntlm, char *user, char *passwd) {
    SEC_WINNT_AUTH_IDENTITY identity, *pId;
    char *p;

    SECURITY_STATUS Status;
    SecBuffer       type1_buf;
    SecBufferDesc   type1_desc;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;

    DEBUGP(("NTLM-Auth: Create NEGOTIATE message ...\n"));

    // prepare identity
    pId = NULL; // indicates use default
    p = strchr(user, '\\'); // not `/`
    if (user && *user && p != NULL) {
        *p = 0;
        ntlm_gen_identity(user, p + 1, passwd, &identity);
        *p = '\\';
        pId = &identity;
    }

    // Init Credentials
    // https://docs.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--ntlm
    Status = g_pSSPI->AcquireCredentialsHandle(NULL, "NTLM",
                                               SECPKG_CRED_OUTBOUND, NULL,
                                               pId, NULL, NULL,
                                               &ntlm->hCreds, &tsExpiry);

    if (Status != SEC_E_OK) {
        logprintf(LOG_NOTQUIET, "NTLM-Auth: AcquireCredentialsHandle error %s\n", sspi_strerror(Status));
        return false;
    }

    // service principal name (SPN)
    // https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names
    // <service class>/<host>[:port[/service name]]
    if (ntlm->host == NULL) ntlm->host = ""; // in case of uninitialized using/fuzzing
    ntlm->spn = malloc(5 + strlen(ntlm->host) + 6); // max port, no service name
    if (ntlm->spn == NULL) {
        logprintf(LOG_NOTQUIET, "malloc failed.\n");
        return false;
    }
    sprintf(ntlm->spn, "%s/%s/%d", "HTTP", ntlm->host, ntlm->port);

    InitSecBuffer(&type1_buf, 0, NULL, SECBUFFER_TOKEN);
    InitSecBufferDesc(&type1_desc, 1, &type1_buf);

    // Init context & token, use `ISC_REQ_ALLOCATE_MEMORY`
    Status = g_pSSPI->InitializeSecurityContext(
                    &ntlm->hCreds, NULL, ntlm->spn, ISC_REQ_ALLOCATE_MEMORY,
                    0, SECURITY_NETWORK_DREP,
                    NULL,
                    0,
                    &ntlm->hContext, &type1_desc, &dwSSPIOutFlags, &tsExpiry);

    if (Status == SEC_I_COMPLETE_NEEDED || Status == SEC_I_COMPLETE_AND_CONTINUE) {
        Status = g_pSSPI->CompleteAuthToken(&ntlm->hContext, &type1_desc);
        if (Status != SEC_E_OK) {
            logprintf(LOG_NOTQUIET, "NTLM-Auth: CompleteAuthToken error %s\n", sspi_strerror(Status));
            return false;
        }
    }
    else if (Status != SEC_E_OK && Status != SEC_I_CONTINUE_NEEDED) {
        logprintf(LOG_NOTQUIET, "NTLM-Auth: InitializeSecurityContext error %s\n", sspi_strerror(Status));
        return false;
    }

    ntlm->out = type1_buf.pvBuffer;
    ntlm->out_len = type1_buf.cbBuffer;

    return true;
}

static bool ntlm_create_type3_message(struct ntlmdata *ntlm) {
    SECURITY_STATUS Status;
    SecBuffer       type2_bufs[2];
    SecBufferDesc   type2_desc;
    SecBuffer       type3_buf;
    SecBufferDesc   type3_desc;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;

    DEBUGP(("NTLM-Auth: Create AUTHENTICATE message ...\n"));

    InitSecBuffer(&type2_bufs[0], ntlm->in_len, ntlm->in, SECBUFFER_TOKEN);
    InitSecBufferDesc(&type2_desc, 1, type2_bufs);

    // https? Haven't pass over here! need the SSL\TLS `PCtxtHandle`

    InitSecBuffer(&type3_buf, 0, NULL, SECBUFFER_TOKEN);
    InitSecBufferDesc(&type3_desc, 1, &type3_buf);

    // https://docs.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--ntlm
    Status = g_pSSPI->InitializeSecurityContext(
                    &ntlm->hCreds, &ntlm->hContext, ntlm->spn, ISC_REQ_ALLOCATE_MEMORY,
                    0, SECURITY_NETWORK_DREP,
                    &type2_desc,
                    0,
                    NULL, &type3_desc, &dwSSPIOutFlags, &tsExpiry);

    if (Status != SEC_E_OK) {
        logprintf(LOG_NOTQUIET, "NTLM-Auth: InitializeSecurityContext error %s\n", sspi_strerror(Status));
        return false;
    }

    ntlm->out = type3_buf.pvBuffer;
    ntlm->out_len = type3_buf.cbBuffer;

    return true;
}

static void ntlm_cleanup(struct ntlmdata *ntlm) {
    g_pSSPI->FreeCredentialsHandle(&ntlm->hCreds);
    g_pSSPI->DeleteSecurityContext(&ntlm->hContext);
    free(ntlm->in);
    free(ntlm->spn);
}

/* Process remote (server/proxy) response
    1. got auth request, return and go to create type-1 message as output
    2. decode type-2 message, and then go to create type-3 message as output
*/
bool ntlm_input(struct ntlmdata *ntlm, const char *header) {
    size_t len_enc;

    if (strncmp(header, "NTLM", 4)) return false;
    header += 4;

    if (g_pSSPI == NULL) {
        if (!LoadSecurityLibrary()) {
            logprintf(LOG_NOTQUIET, "NTLM-Auth: Initializing SSPI failed!\n");
            return false;
        }
    }

    while (*header && isspace(*header)) header++;

    if (*header) {
        DEBUGP(("NTLM-Auth: CHALLENGE message received.\n"));
        len_enc = strlen(header);
        if (len_enc % 4) {
            logprintf(LOG_NOTQUIET, "NTLM-Auth: illegal data.\n");
            return false;
        }
        ntlm->in_len = len_enc / 4 * 3;
        ntlm->in = malloc(ntlm->in_len);
        if (ntlm->in == NULL) {
            logprintf(LOG_NOTQUIET, "malloc failed.\n");
            return false;
        }
        //
        if (wget_base64_decode(header, ntlm->in, ntlm->in_len) < 0) {
            logprintf(LOG_NOTQUIET, "NTLM-Auth: invalid data.\n");
            return false;
        }
        //
        ntlm->state = NTLMSTATE_TYPE2; // <--- got
    }
    else if (ntlm->state == NTLMSTATE_LAST) {
        logprintf(LOG_NOTQUIET, "NTLM-Auth: restarted.\n"); // continue
    }
    else if (ntlm->state == NTLMSTATE_TYPE3) {
        logprintf(LOG_NOTQUIET, "NTLM-Auth: rejected.\n");
        ntlm->state = NTLMSTATE_NONE;
        return false;
    }
    else if (ntlm->state > NTLMSTATE_NONE) {
        // type1, type2: got 'empty' response? Wrong turn ...
        logprintf(LOG_NOTQUIET, "NTLM-Auth: fatal error!\n");
        return false;
    }
    else { // <--- 0, start from here
        DEBUGP(("NTLM-Auth: Starting ...\n"));
        ntlm->state = NTLMSTATE_TYPE1;
    }

    return true;
}

static char* ntlm_encode_message(struct ntlmdata *ntlm) {
    char *out;
    size_t len;

    len = (ntlm->out_len + 2) / 3 * 4;
    out = malloc(len + 6);
    if (out == NULL) {
        logprintf(LOG_NOTQUIET, "malloc failed.\n");
        return NULL;
    }

    memcpy(out, "NTLM ", 5);
    wget_base64_encode(ntlm->out, ntlm->out_len, out + 5);
    g_pSSPI->FreeContextBuffer(ntlm->out); // free every round
    DEBUGP(("NTLM-Auth: Message has been encoded.\n"));

    return out;
}

/* return the base64 ecoded type-1/type-3 MESSAGE */
char *ntlm_output(struct ntlmdata *ntlm, const char *user, const char *passwd, bool *ready) {
    ntlm->out = NULL;
    ntlm->out_len = 0;

    switch (ntlm->state) {
    case NTLMSTATE_TYPE1:   // server request start
    default:                // (re)start
        if (ntlm_create_type1_message(ntlm, (char*)user, (char*)passwd)) {
            return ntlm_encode_message(ntlm);
        }
        break;
    case NTLMSTATE_TYPE2:   // got type2 response
        if (ntlm_create_type3_message(ntlm)) {
            ntlm_cleanup(ntlm);
            *ready = true; // should finish successful or failed
            return ntlm_encode_message(ntlm);
        }
        break;
    case NTLMSTATE_TYPE3:   // type3 msg has been sent
        *ready = true; // in case it comes here again
        ntlm->state = NTLMSTATE_LAST;
        break;
    }

    return NULL;
}
