/* SSL support via Schannel on Windows.
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


/* Win SSL/TLS backgroud
https://en.wikipedia.org/wiki/Transport_Layer_Security
https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
https://en.wikipedia.org/wiki/Security_Support_Provider_Interface
https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations

Certificate Trust Verification
https://msdn.microsoft.com/en-us/library/windows/desktop/aa376546.aspx
Tracking all of the certificates that back a new end certificate can become
cumbersome. Therefore, CryptoAPI 2.0 technology provides functions that automate
creating the chain of certificates that back any given end certificate. These
functions also check and report on the validity of each certificate in a chain.

* Procedures Used with Most Security Packages and Protocols
https://msdn.microsoft.com/en-us/library/windows/desktop/aa378824.aspx
InitSecurityInterface() <--- Doesn't need call GetProcAddress many times.

Creating a Secure Connection Using Schannel
https://msdn.microsoft.com/en-us/library/windows/desktop/aa374782.aspx

1. Obtain Schannel credentials (Obtaining Schannel Credentials).
https://msdn.microsoft.com/en-us/library/windows/desktop/aa378812.aspx
Getting Schannel Credentials
https://docs.microsoft.com/en-us/windows/win32/secauthn/getting-schannel-credentials
SCHANNEL_CRED structure
https://docs.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-schannel_cred
*AcquireCredentialsHandle*
https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlea

2. Create an Schannel security context (Creating an Schannel Security Context).
https://docs.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--schannel

*InitializeSecurityContext* (Client) <===> AcceptSecurityContext (Server), loops

3. Getting Information About Schannel Connections
https://docs.microsoft.com/en-us/windows/win32/secauthn/getting-information-about-schannel-connections
*QueryContextAttributes*
https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querycontextattributesa
https://docs.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--schannel

4. exchange data
EncryptMessage
https://docs.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--schannel
DecryptMessage
https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
CertGetNameString
https://msdn.microsoft.com/en-us/library/windows/desktop/aa376086.aspx
SChannel in Windows XP (OS version 5.1) uses legacy handshakes and algorithms
that may not be supported by all servers.

***
Schannel SSP Technical Overview
https://technet.microsoft.com/en-us/library/dn786429.aspx

steps in using TLS for client/server communication:
https://msdn.microsoft.com/en-us/library/windows/desktop/aa380516.aspx

The steps that make up TLS are divided into two protocols that, together,
provide connection security:
* TLS Handshake Protocol - (steps 1 - 3)
  https://msdn.microsoft.com/en-us/library/windows/desktop/aa380513.aspx
* TLS Record Protocol - (step 4)

    RFCs      ~   APIs   ~     DLLs
communication ~ protocol ~ implementation

InitializeSecurityContext (Client) <===> AcceptSecurityContext (Server)

Supported Cipher Suites and Protocols in the Schannel SSP
https://docs.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-
https://docs.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf

Using SSPI
https://msdn.microsoft.com/en-us/library/windows/desktop/aa380535.aspx

Creating a Secure Connection Using Schannel
https://msdn.microsoft.com/en-us/library/windows/desktop/aa374782.aspx
*/

/* Tls handshake
=====   ================================== ============= =================================
win:  0    /-- AcquireCredentialsHandle()                AcquireCredentialsHandle() --\
           |                                                                          |
      2 /--+-- InitializeSecurityContext() <-\         /-> AcceptSecurityContextt() --+--\
      6 |  |                                 |         |                              |  |
        |  \-> PCredHandle >------1-----+----/         \--=+----------< PCtxtHandle <-+--|
        +----> PCtxtHandle >~~~~~~~~3~~~|                  +----------< PCredHandle <-/  |
        \----> PSecBufferDesc_out >-4-7-+> =-4-7\ /-5-8=         PSecBufferDesc_out <----|
          /-9-/                         |        x                                       |
          |    PSecBufferDesc_in >--5-8-/  <----/ \---->          PSecBufferDesc_in >----/
          |
          \--> QueryContextAttributes()

=====   ================================== ============= =================================
               Client                                                        Server
=====   ================================== ============= =================================
      4        ClientHello                   -------->
      5                                                                 ServerHello
      5                                                                Certificate*
      5                                                          ServerKeyExchange*
                                                                CertificateRequest*
                                             <--------              ServerHelloDone
               Certificate*
      7        ClientKeyExchange
      6        CertificateVerify*
      7        [ChangeCipherSpec]
               Finished                      -------->
      8                                                          [ChangeCipherSpec]
                                             <--------                     Finished
      9        Application Data              <------->             Application Data
=====   ================================== ============= =================================

SSL/TLS in Detail:
https://technet.microsoft.com/en-us/library/cc785811(v=ws.10).aspx
https://docs.microsoft.com/en-us/windows/win32/secauthn/transport-layer-security-protocol
https://docs.microsoft.com/en-us/windows/win32/secauthn/secure-channel
*/

/* PSDK server 2003
https://www.microsoft.com/en-us/download/confirmation.aspx?id=15656
Samples\Security\SSPI\SSL\WebClient\

// Initialize the WinSock subsystem ---> WSAStartup()

// Open the certificate store       ---> CertOpenSystemStore()

// Create credentials               ---> AcquireCredentialsHandle(),
    UNISP_NAME as initiate, get handle for Initialization
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374716.aspx

// Connect to server                ---> socket(), connect()

// Perform handshake                ---> InitializeSecurityContext() <<<--- ***
-----> handshake n, loop until a sufficient security context is established
    To build a security context between the client and server.
    Typically, the InitializeSecurityContext (Schannel) function is called in a
    loop until a sufficient security context is established.
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa375924.aspx
    * The certificate is specified when calling the AcquireCredentialsHandle
    (Schannel) function. When using the Schannel SSP, set pszPackage to
    UNISP_NAME.
    send()
    ---> CertFindChainInStore()
    If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS, means
    the server just requested client authentication. So 'the opened CertStore'
    is used to find a suitable client certificate from the list of trusted
    certificate authorities.
    recv()
<----- handshake n, loop

<-----Authenticated, so check it!----->

// Authenticate server's credentials
//   Get server's certificate               ---> QueryContextAttributes,
        get and check the respose.
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa379340.aspx
SECPKG_ATTR_NEGOTIATION_INFO
SECPKG_ATTR_STREAM_SIZES,
SECPKG_ATTR_APPLICATION_PROTOCOL,
SECPKG_ATTR_REMOTE_CERT_CONTEXT,  get the certificate supplied by the server.
//   Attempt to validate server certificate ---> CertGetCertificateChain,
                                                CertVerifyCertificateChainPolicy
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa376078.aspx
        hAdditionalStore, be NULL if no *additional* store is to be searched
//   Free the server certificate context

// Read file from server

// close down the connection    ---> ApplyControlRecvBuffer(),
                                     InitializeSecurityContex(),
                                     DeleteSecurityContext(),
                                     closesocket()
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa380138.aspx

// Free the server certificate context  ---> CertFreeCertificateContext()
// Free SSPI context handle     ---> DeleteSecurityContext()
// Free SSPI credentials handle ---> FreeCredentialsHandle()
// Close socket                 ---> closesocket()
// Shutdown WinSock subsystem   ---> WSACleanup()
// Close the certificate store  ---> CertCloseStore()
==========

Is InitSecurityInterface necessary?
This function enables clients to use SSPI without binding directly to an
implementation of the interface. It is convenient for dynamic loading :)
So, it depends on linking directly or the late binding.
InitSecurityInterfaceA db 'SSPICLI.InitSecurityInterfaceA' :P
InitSecurityInterface()
https://msdn.microsoft.com/en-us/library/windows/desktop/aa376103.aspx
Using SSPI with a Windows Sockets Client (example)
https://msdn.microsoft.com/en-us/library/windows/desktop/aa380536.aspx
SECURITY_FUNCTION_TABLE definition
https://lifeinhex.com/msdn-is-sometimes-wrong/


http://www.coastrd.com/tls-with-schannel


Shutting Down an Schannel Connection
https://docs.microsoft.com/en-us/windows/win32/secauthn/shutting-down-an-schannel-connection


Cryptography Functions
https://msdn.microsoft.com/en-us/library/windows/desktop/aa380252.aspx
CertGetCertificateChain
CertFreeCertificateChain

CertFindCertificateInStore
CertFreeCertificateContext

QueryContextAttributes

*/

/* Wget SSL/TLS working model

* Handshake and certificate

gethttp --> ssl_init
gethttp --> establish_connection --> ssl_connect_wget --> ssl_check_certificate

getftp --> ssl_init
getftp --> init_control_ssl_connection --> ssl_connect_wget --> ssl_check_certificate
getftp --> ssl_connect_wget --> ssl_check_certificate

ssl_init:
Prepare SSL context and other needed factors.

ssl_connect_wget:
When SSL handshake succeed (SSL_connect, SSL_is_init_finished, API of openssl):
fd_register_transport (int fd, struct transport_implementation *imp, void *ctx)
stores fd and imp to 'static struct hash_table *transport_map;'.
SSL_connect (initiates the SSL/TLS handshake with a server):
https://wiki.openssl.org/index.php/Manual:SSL_connect(3)
SSL_is_init_finished (fully protected data can be transferred):
https://www.openssl.org/docs/manmaster/man3/SSL_is_init_finished.html

ssl_check_certificate:
calls openssl APIs SSL_get_peer_certificate and SSL_get_verify_result, then
checks the subjectAltNames for SNI.
SSL_get_peer_certificate (X509 certificate the peer presented):
https://wiki.openssl.org/index.php/Manual:SSL_get_peer_certificate(3)
SSL_get_verify_result (verification of the X509 certificate presented):
https://wiki.openssl.org/index.php/Manual:SSL_get_verify_result(3)
subjectAltNames (Subject Alternative Names, SANs):
https://en.wikipedia.org/wiki/Subject_Alternative_Name
SNI (Server Name Indication):
https://en.wikipedia.org/wiki/Server_Name_Indication

When downloading, fd_read/fd_write/fd_peek (connect.c) are called:
poll_internal (int fd, struct transport_info *info, int wf, double timeout)
polls info out from transport_map.
And then, using the registered SSL_read/SSL_write/SSL_peek of openssl for
SSL/TLS data exchange.


* Data Exchange Wrapper: `connect.h`
```c
struct transport_implementation {
  int (*reader) (int, char *, int, void *, double);
  int (*writer) (int, char *, int, void *);
  int (*poller) (int, double, int, void *);
  int (*peeker) (int, char *, int, void *, double);
  const char *(*errstr) (int, void *);
  void (*closer) (int, void *);
};
```

They are called by `connect.c`:
fd_read, fd_write, poll_internal,
fd_peek, fd_errstr, fd_close

```c
int fd_read (int, char *, int, double);
int fd_write (int, char *, int, double);
int fd_peek (int, char *, int, double);
const char *fd_errstr (int);
void fd_close (int);
```
`int fd, char *buf, int bufsize, double timeout`

`poll_internal` ==> poller/sock_poll;
`fd_read`   ==> reader; poll_internal, sock_read;
`fd_write`  ==> writer; poll_internal, sock_write;
`fd_peek`   ==> peeker; poll_internal, sock_peek;
`fd_errstr` ==> errstr;
`fd_close`  ==> closer;

*/


#include "wget.h"

#include <errno.h>
#include <stdbool.h>

#include <windows.h>
#include <winsock2.h>
#include <wincrypt.h>
#include <schannel.h>

#include "win-sspi.h"

#include "connect.h"
#include "log.h"
#include "utils.h"


#define SCHANNEL_BUFFER_INIT_SIZE   4096
#define SCHANNEL_BUFFER_FREE_SIZE   2048  // max len of TCP PDU is 1460 < 1500

#ifndef SP_PROT_SSL2_CLIENT
#define SP_PROT_SSL2_CLIENT     0x00000008
#endif

#ifndef SP_PROT_SSL3_CLIENT
#define SP_PROT_SSL3_CLIENT     0x00000008
#endif

#ifndef SP_PROT_TLS1_CLIENT
#define SP_PROT_TLS1_CLIENT     0x00000080
#endif

#ifndef SP_PROT_TLS1_0_CLIENT
#define SP_PROT_TLS1_0_CLIENT   SP_PROT_TLS1_CLIENT
#endif

#ifndef SP_PROT_TLS1_1_CLIENT
#define SP_PROT_TLS1_1_CLIENT   0x00000200
#endif

#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT   0x00000800
#endif

#ifndef SECBUFFER_ALERT
#define SECBUFFER_ALERT         17
#endif


/* Part 0: Public interface declaration */

// ssl.h


/* Part 1: common staff */

// recv in turn
typedef enum _CONN_STATE {
    CONN_SEND = 0,
    CONN_RECV,
    CONN_CLOSE
} CONN_STATE;

typedef enum _HSK_NEGO_STAGE {
    CONNECTED = 0,
    HSK_CLIENT_HELLO,
    HSK_ONGOING,
    HSK_VERIFIED
} HSK_NEGO_STAGE;

typedef struct _EZ_BUFF {
    char *data;
    int used;
    int size;
} EZ_BUFF, *P_EZ_BUFF;

static void ez_buff_free(EZ_BUFF *buff) {
    free(buff->data);
    buff->used = 0;
    buff->size = 0;
}

static bool ez_buff_space(EZ_BUFF *buff, int len) {
    char *p;
    if (buff->size - buff->used < len) {
        len += buff->size;
        p = realloc(buff->data, len);
        if (p == NULL) {
            logprintf(LOG_NOTQUIET, "realloc failed!\n");
            return false;
        }
        buff->data = p;
        buff->size = len;
    }
    return true;
}

/* auto allocate enough space, AND free it manually */
static int ez_socket_recv(SOCKET socket, EZ_BUFF *buff, int flags) {
    int n;
    int socket_err = 0;

    if (!ez_buff_space(buff, SCHANNEL_BUFFER_FREE_SIZE)) {
        return 0;
    }

    DEBUGP(("socket: recv buff: total/used/left %d/%d/%d\n", buff->size, buff->used, buff->size - buff->used));

    /* connect_to_ip: socket(sa->sa_family, SOCK_STREAM, 0); protocol = 0:
        If a value of 0 is specified, the caller does not wish to specify a protocol and
        the service provider will choose the protocol to use. -~-> use default protocol of type
       https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
    */
    errno = 0;
    n = recv(socket, buff->data + buff->used, buff->size - buff->used, flags);
    socket_err = errno;

    if (n == SOCKET_ERROR || n < 0) {
        logprintf(LOG_NOTQUIET, "socket: recv failed!\n");
    }
    else {
        buff->used += n;
    }
    DEBUGP(("socket: recv buff: total/used/received %d/%d/%d\n", buff->size, buff->used, n));

    errno = socket_err;
    return n;
}


/* Schannel model
*/
typedef struct _WINTLS_TRANSPORT_CONTEXT {
    SOCKET      socket;
    SEC_CHAR    *hostname;
    CredHandle  hCreds;
    CtxtHandle  hContext;
    DWORD       dwSSPIFlags;
    EZ_BUFF     rcv_buff;
    EZ_BUFF     dec_buff;
    HSK_NEGO_STAGE  stage;
    bool            can_recv;
    SecPkgContext_StreamSizes stream_sizes;
    int         err_no;
} WINTLS_TRANSPORT_CONTEXT, *P_WINTLS_TRANSPORT_CONTEXT;


// https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id
// https://github.com/curl/curl/blob/master/docs/CIPHERS.md#schannel
static bool set_ciphers(SCHANNEL_CRED *schannel_cred, char *ciphers) {
#define ID2MAP_ITEM(ID) #ID, ID
    typedef struct ALG_ID_MAP {
        char *c;
        ALG_ID id;
    } ALG_ID_MAP;
    ALG_ID_MAP alg_id_map[] = { // wincrypt.h
        {ID2MAP_ITEM(CALG_MD2)},
        {ID2MAP_ITEM(CALG_MD4)},
        {ID2MAP_ITEM(CALG_MD5)},
        {ID2MAP_ITEM(CALG_SHA)},
        {ID2MAP_ITEM(CALG_SHA1)},
        {ID2MAP_ITEM(CALG_MAC)},
        {ID2MAP_ITEM(CALG_RSA_SIGN)},
        {ID2MAP_ITEM(CALG_DSS_SIGN)},
        {ID2MAP_ITEM(CALG_NO_SIGN)},
        {ID2MAP_ITEM(CALG_RSA_KEYX)},
        {ID2MAP_ITEM(CALG_DES)},
        {ID2MAP_ITEM(CALG_3DES_112)},   // Key length: 112 bits, 2-key
        {ID2MAP_ITEM(CALG_3DES)},       // Key length: 168 bits, 3-key
        {ID2MAP_ITEM(CALG_DESX)},       // https://en.wikipedia.org/wiki/DES-X
        {ID2MAP_ITEM(CALG_RC2)},
        {ID2MAP_ITEM(CALG_RC4)},
        {ID2MAP_ITEM(CALG_SEAL)},
        {ID2MAP_ITEM(CALG_DH_SF)},
        {ID2MAP_ITEM(CALG_DH_EPHEM)},
        {ID2MAP_ITEM(CALG_AGREEDKEY_ANY)},
        {ID2MAP_ITEM(CALG_KEA_KEYX)},
        {ID2MAP_ITEM(CALG_HUGHES_MD5)},
        {ID2MAP_ITEM(CALG_SKIPJACK)},
        {ID2MAP_ITEM(CALG_TEK)},
        {ID2MAP_ITEM(CALG_CYLINK_MEK)},
        {ID2MAP_ITEM(CALG_SSL3_SHAMD5)},
        {ID2MAP_ITEM(CALG_SSL3_MASTER)},
        {ID2MAP_ITEM(CALG_SCHANNEL_MASTER_HASH)},
        {ID2MAP_ITEM(CALG_SCHANNEL_MAC_KEY)},
        {ID2MAP_ITEM(CALG_SCHANNEL_ENC_KEY)},
        {ID2MAP_ITEM(CALG_PCT1_MASTER)},
        {ID2MAP_ITEM(CALG_SSL2_MASTER)},
        {ID2MAP_ITEM(CALG_TLS1_MASTER)},
        {ID2MAP_ITEM(CALG_RC5)},
        {ID2MAP_ITEM(CALG_HMAC)},
        {ID2MAP_ITEM(CALG_TLS1PRF)},
        {ID2MAP_ITEM(CALG_HASH_REPLACE_OWF)},
        {ID2MAP_ITEM(CALG_AES_128)},
        {ID2MAP_ITEM(CALG_AES_192)},
        {ID2MAP_ITEM(CALG_AES_256)},
        {ID2MAP_ITEM(CALG_AES)},
        {ID2MAP_ITEM(CALG_SHA_256)},
        {ID2MAP_ITEM(CALG_SHA_384)},
        {ID2MAP_ITEM(CALG_SHA_512)},
#if NTDDI_VERSION >= 0x06000000
        {ID2MAP_ITEM(CALG_ECDH)},
#ifndef CALG_ECDH_EPHEM // for mingw
#define CALG_ECDH_EPHEM 0x0000ae06
#endif
        {ID2MAP_ITEM(CALG_ECDH_EPHEM)},
        {ID2MAP_ITEM(CALG_ECMQV)},
        {ID2MAP_ITEM(CALG_ECDSA)},
#endif
        {ID2MAP_ITEM(CALG_OID_INFO_CNG_ONLY)},
        {ID2MAP_ITEM(CALG_OID_INFO_PARAMETERS)}
    };

    int num_ids = sizeof(alg_id_map)/sizeof(ALG_ID_MAP);
    ALG_ID *alg_ids;
    int count = 0, i = 0;
    bool unset;
    char *p, *p_end;

    alg_ids = (ALG_ID*)calloc(num_ids, sizeof(ALG_ID_MAP));
    if (alg_ids == NULL) {
        logprintf(LOG_NOTQUIET, "WinTLS: calloc failed!\n");
        return false;
    }
    p_end = ciphers + strlen(ciphers);
    while (ciphers && *ciphers && count < num_ids) {
        p = strchr(ciphers, ':');
        if (p == NULL) p = p_end;
        unset = true;
        for (i = 0; i < num_ids; i++) {
            if (strncmp(alg_id_map[i].c, ciphers, (size_t)(p - ciphers)) == 0) {
                alg_ids[count] = alg_id_map[i].id;
                count++;
                unset = false;
                break;
            }
        }
        if (unset) {
            logprintf(LOG_NOTQUIET, "WinTLS: unsupported cipher at %s\n", ciphers);
            return false;
        }
        if (p < p_end) p++;
        ciphers = p;
    }
    schannel_cred->palgSupportedAlgs = alg_ids;
    schannel_cred->cSupportedAlgs = count;

    return true;
}

/* setup SCHANNEL_CRED
   https://docs.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-schannel_cred
   use the system defaults
*/
static SECURITY_STATUS CreateCredentials(PCredHandle phCreds) {
    SECURITY_STATUS Status;
    SCHANNEL_CRED   schannel_cred = {0};
    TimeStamp       tsExpiry;

    char *pfs_ciphers =
        // KeyExchange    _ Signatue            BulkEncryption      MessageAuthentication/hashes
#if NTDDI_VERSION >= 0x06000000
        "CALG_ECDH_EPHEM"
                            ":CALG_ECDSA"
                            // RSA but no DSS
                                                // AES_256_CBC or AES_128_CBC
                                                                    // SHA384, SHA256 or SHA
        ":"
#endif
        "CALG_DH_EPHEM"
                            ":CALG_RSA_SIGN"
                            ":CALG_DSS_SIGN"
                                                ":CALG_AES_256"
                                                ":CALG_AES_128"
                                                ":CALG_DES" // weak
                                                // ":CALG_3DES" <-- NO
                                                                    ":CALG_SHA_384"
                                                                    ":CALG_SHA_256"
                                                                    ":CALG_SHA"
    ;

#define UNIMP_OPT(p, s) if (opt.p) {logprintf(LOG_NOTQUIET, "WinTLS: unimplemented: %s\n", s); return SEC_E_INTERNAL_ERROR;}
    UNIMP_OPT(ca_cert,      "--ca-certificate")
    UNIMP_OPT(ca_directory, "--ca-directory")
    UNIMP_OPT(cert_file,    "--certificate")
    UNIMP_OPT(cert_type,    "--certificate-type")
    UNIMP_OPT(crl_file,     "--crl-file")
    UNIMP_OPT(private_key,  "--private-key")
    UNIMP_OPT(private_key_type, "--private-key-type")
    UNIMP_OPT(pinnedpubkey, "-pinnedpubkey")
    UNIMP_OPT(random_file,  "--random-file")

    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    switch (opt.secure_protocol) {
    case secure_protocol_sslv2: // superseded
        schannel_cred.grbitEnabledProtocols = SP_PROT_SSL2_CLIENT;
        break;
    case secure_protocol_sslv3: // being superseded
        schannel_cred.grbitEnabledProtocols = SP_PROT_SSL3_CLIENT;
        break;
    case secure_protocol_tlsv1:
        schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT;
        break;
    case secure_protocol_tlsv1_1:
        schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT;
        break;
    case secure_protocol_tlsv1_2:
        schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
        break;
    case secure_protocol_tlsv1_3: // no yet supported
        logprintf(LOG_NOTQUIET, "WinTLS: tlsv1.3 is not yet supported!\n");
        break;
    case secure_protocol_pfs:
        if (opt.tls_ciphers_string) break;
        // https://vincent.bernat.ch/en/blog/2011-ssl-perfect-forward-secrecy
        // SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
        // Select cipher suites that imply EDH or ECDHE as a key agreement method
        //  https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
        // --ciphers overrides everything
        // https://en.wikipedia.org/wiki/Cipher_suite#Supported_algorithms
        opt.tls_ciphers_string = pfs_ciphers;
    case secure_protocol_auto:
        // min: tlsv1
        schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;
        break;
    default:
        logprintf(LOG_NOTQUIET, "WinTLS: unsupported 'secure-protocol' value!\n");
        break;
    }
    // WinCE is out of date
    if (opt.check_cert == CHECK_CERT_ON) {
        schannel_cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_REVOCATION_CHECK_CHAIN | SCH_CRED_IGNORE_REVOCATION_OFFLINE;
    }
    else { // --no-check-certificate
        schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION;
    }

    // --ciphers overrides everything
    if (opt.tls_ciphers_string) {
        DEBUGP(("WinTLS: set ciphers: %s\n", pfs_ciphers));
        if (!set_ciphers(&schannel_cred, opt.tls_ciphers_string)) {
            Status = SEC_E_INTERNAL_ERROR;
            goto CLEANUP;
        }
    }

    Status = g_pSSPI->AcquireCredentialsHandle(NULL, UNISP_NAME,
                                               SECPKG_CRED_OUTBOUND, NULL,
                                               &schannel_cred, NULL, NULL,
                                               phCreds, &tsExpiry);

    if (FAILED(Status)) logprintf(LOG_NOTQUIET, "WinTLS: AcquireCredentialsHandle error: %s\n", sspi_strerror(Status));

CLEANUP:
    free(schannel_cred.palgSupportedAlgs);  // --ciphers
    return Status;
}

/* InitializeSecurityContext
    Schannel uses *ServerName* to verify the server certificate,
    AND locate the session in the session cache when reestablishing a connection.

    WinCE? Out of date!

ALPN (Application Layer Protocol Negotiation):
HTTP/2;
since Windows 8.1 and Windows Server 2012 R2.
*/
static SECURITY_STATUS PerformHandshake(WINTLS_TRANSPORT_CONTEXT *ctx) {
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;
    //
    EZ_BUFF         *rcv_buff;
    //
    SecBuffer       OutBuffers[3];
    SecBufferDesc   OutBufferDesc;
    DWORD           cbData;
    //
    SecBuffer       InBuffers[2];
    SecBufferDesc   InBufferDesc;
    //
    INT             i;

    errno = 0;

    // Initiate a client Hello message and generate a token
    ctx->dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT
                     | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM
                     | ISC_REQ_CONFIDENTIALITY;

    InitSecBuffer(&OutBuffers[0], 0, NULL, SECBUFFER_TOKEN);
    InitSecBuffer(&OutBuffers[1], 0, NULL, SECBUFFER_ALERT);
    InitSecBuffer(&OutBuffers[2], 0, NULL, SECBUFFER_EMPTY);
    InitSecBufferDesc(&OutBufferDesc, 3, OutBuffers);

    if (ctx->stage > HSK_CLIENT_HELLO) goto HANDSHAKE_LOOP;

    // initiate client hello
    Status = g_pSSPI->InitializeSecurityContext(
                    &ctx->hCreds, NULL, ctx->hostname, ctx->dwSSPIFlags,
                    0, 0,
                    NULL,
                    0,
                    &ctx->hContext, &OutBufferDesc, &dwSSPIOutFlags, &tsExpiry);
    //
    if (Status != SEC_I_CONTINUE_NEEDED) {
        logprintf(LOG_NOTQUIET, "WinTLS: InitializeSecurityContext failed: %#08lX\n", Status);
        return Status;
    }

    // Say Hello to the server
    if (OutBuffers[0].cbBuffer > 0 && OutBuffers[0].pvBuffer != NULL) {
        //
        cbData = send(ctx->socket, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
        ctx->err_no = errno;
        //
        DEBUGP(("WinTLS: client hello sent %lu\n", cbData));
        //
        g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
        //
        if (cbData == SOCKET_ERROR || cbData == 0) {
            g_pSSPI->DeleteSecurityContext(&ctx->hContext);
            return SEC_E_INTERNAL_ERROR;
        }
        //
        ctx->stage = HSK_ONGOING;
    }

    //
    // perform handshake loop
HANDSHAKE_LOOP:
    rcv_buff = &ctx->rcv_buff;
    ctx->can_recv = true;
    Status  = SEC_E_INCOMPLETE_MESSAGE;

    if (!ez_buff_space(rcv_buff, SCHANNEL_BUFFER_INIT_SIZE)) {
        return SEC_E_INTERNAL_ERROR;
    }

    while (Status == SEC_I_CONTINUE_NEEDED      // client must send the token to the server and wait for a return token
        || Status == SEC_E_INCOMPLETE_MESSAGE   // not whole message recieved
        || Status == SEC_I_INCOMPLETE_CREDENTIALS)  // server requested client authentication
    {
        // need read server response
        if (ctx->can_recv) {
            i = ez_socket_recv(ctx->socket, rcv_buff, 0);
            ctx->err_no = errno;
            if (i <= 0) {
                Status = SEC_E_INTERNAL_ERROR;
                break;
            }
        }

        InitSecBuffer(&InBuffers[0], rcv_buff->used, rcv_buff->data, SECBUFFER_TOKEN);
        InitSecBuffer(&InBuffers[1], 0, NULL, SECBUFFER_EMPTY);
        InitSecBufferDesc(&InBufferDesc, 2, InBuffers);

        Status = g_pSSPI->InitializeSecurityContext(
                        &ctx->hCreds, &ctx->hContext, ctx->hostname, ctx->dwSSPIFlags,
                        0, 0,
                        &InBufferDesc,
                        0,
                        NULL, &OutBufferDesc, &dwSSPIOutFlags, &tsExpiry);

        DEBUGP(("WinTLS: Status %#08lX: rcv_buff.used %d\n", Status, rcv_buff->used));

        if (Status == SEC_I_CONTINUE_NEEDED || Status == SEC_E_OK || (FAILED(Status) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))) {
            for (i = 0; i < 3; i++) {
                // handshake tokens
                if (OutBuffers[i].BufferType == SECBUFFER_TOKEN && OutBuffers[i].cbBuffer > 0) {
                    //
                    cbData = send(ctx->socket, OutBuffers[i].pvBuffer, OutBuffers[i].cbBuffer, 0);
                    ctx->err_no = errno;
                    //
                    DEBUGP(("WinTLS: next handshake data sent %lu\n", cbData));
                    //
                    if (cbData == SOCKET_ERROR || cbData == 0) {
                        g_pSSPI->FreeContextBuffer(OutBuffers[i].pvBuffer);
                        g_pSSPI->DeleteSecurityContext(&ctx->hContext);
                        return SEC_E_INTERNAL_ERROR;
                    }
                }
                //
                g_pSSPI->FreeContextBuffer(OutBuffers[i].pvBuffer);
                OutBuffers[i].pvBuffer = NULL;
            }
        }

        // not whole message recieved, not enough buffer,
        // increase memory and get a Whole message that can be parsed
        if (Status == SEC_E_INCOMPLETE_MESSAGE) {
            ctx->can_recv = true;
            continue;
        }

        // data parsed
        // "extra" encrypted application protocol layer stuff, save it to be decrypted with DecryptMessage
        if (InBuffers[1].BufferType == SECBUFFER_EXTRA && InBuffers[1].cbBuffer > 0) {
            DEBUGP(("WinTLS: extra data received\n"));
            // InBuffers[1].pvBuffer does NOT work!
            memmove(rcv_buff->data, rcv_buff->data + rcv_buff->used - InBuffers[1].cbBuffer, InBuffers[1].cbBuffer);
            rcv_buff->used = InBuffers[1].cbBuffer;
        }
        else {
            rcv_buff->used = 0;
        }

        // handshake succeeds ==>
        if (Status == SEC_E_OK) {
            DEBUGP(("WinTLS: handshake succeeded. phContext: 0x%p\n", &ctx->hContext));
            break;
        }

        // !SEC_E_OK <===

        // handshaking, client's turn to send the token
        if (Status == SEC_I_CONTINUE_NEEDED) {
            ctx->can_recv = false;
            continue;
        }

        // server has requested client authentication? attempt to continue without it
        if (Status == SEC_I_INCOMPLETE_CREDENTIALS) {
            logprintf(LOG_NOTQUIET, "WinTLS: a client certificate has been requested\n");
            ctx->can_recv = false;
            continue;
        }

        // function failures:
        // https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlea
        switch (Status) {
        case SEC_E_INSUFFICIENT_MEMORY:
        case SEC_E_INTERNAL_ERROR:
        case SEC_E_NO_CREDENTIALS:
        case SEC_E_NOT_OWNER:
        case SEC_E_SECPKG_NOT_FOUND:
        case SEC_E_UNKNOWN_CREDENTIALS:
            // fatal
            logprintf(LOG_NOTQUIET, "WinTLS: InitializeSecurityContext failed: %#08lX\n", Status);
            break;
        default:
            // other nonfatal issues
            logprintf(LOG_NOTQUIET, "WinTLS: Certificate error: %s\n", sspi_strerror(Status));
            logprintf(LOG_NOTQUIET, "WinTLS: To connect insecurely, use `--no-check-certificate'.\n");
        }

        break;
    }

    // out of recv and send
    if (FAILED(Status)) {
        g_pSSPI->DeleteSecurityContext(&ctx->hContext);
    }

    return Status;
}

/* MS says: MUST shut it down
   https://docs.microsoft.com/en-us/windows/win32/secauthn/shutting-down-an-schannel-connection
*/
static SECURITY_STATUS DisconnectFromServer(WINTLS_TRANSPORT_CONTEXT *ctx) {
    DWORD           dwType;
    DWORD           cbData;

    SecBufferDesc   OutBufferDesc;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    DWORD           Status;

    dwType = SCHANNEL_SHUTDOWN; // <--
    InitSecBuffer(&OutBuffers[0], sizeof(dwType), &dwType, SECBUFFER_TOKEN);
    InitSecBufferDesc(&OutBufferDesc, 1, OutBuffers);

    Status = g_pSSPI->ApplyControlToken(&ctx->hContext, &OutBufferDesc);

    if (FAILED(Status)) {
        logprintf(LOG_NOTQUIET, "WinTLS: ApplyControlToken failed: %#08lX\n", Status);
        return Status;
    }

    InitSecBuffer(&OutBuffers[0], 0, NULL, SECBUFFER_TOKEN);
    InitSecBufferDesc(&OutBufferDesc, 1, OutBuffers);

    Status = g_pSSPI->InitializeSecurityContext(
                    &ctx->hCreds, &ctx->hContext, NULL, ctx->dwSSPIFlags,
                    0, SECURITY_NATIVE_DREP,
                    NULL,
                    0,
                    &ctx->hContext, &OutBufferDesc, &dwSSPIOutFlags, &tsExpiry);

    if (FAILED(Status)) {
        logprintf(LOG_NOTQUIET, "WinTLS: InitializeSecurityContext failed: %#08lX\n", Status);
        return Status;
    }

    // Send the close notify message to the server
    if (OutBuffers[0].pvBuffer != NULL && OutBuffers[0].cbBuffer != 0) {
        //
        cbData = send(ctx->socket, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
        //
        if (cbData == SOCKET_ERROR || cbData == 0) {
            return SEC_E_INTERNAL_ERROR;
        }
        DEBUGP(("WinTLS: shutdown data sent %lu\n", cbData));
        //
        g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
    }

    return Status;
}


/* operate with timeout */

typedef int (*ssl_fn_t)(WINTLS_TRANSPORT_CONTEXT *, char *, int);

// Handshake callback args
typedef struct _WINTLS_HSK_CB_ARGS {
    WINTLS_TRANSPORT_CONTEXT    *ctx;
    SECURITY_STATUS             retval;
} WINTLS_HSK_CB_ARGS, *P_WINTLS_HSK_CB_ARGS;

static void perform_handshake_with_timeout_callback(void *arg) {
    WINTLS_HSK_CB_ARGS *args = (WINTLS_HSK_CB_ARGS*)arg;
    args->retval = PerformHandshake(args->ctx);
}

static bool perform_handshake_with_timeout(WINTLS_TRANSPORT_CONTEXT *ctx, double timeout) {
    WINTLS_HSK_CB_ARGS args;

    ctx->err_no = 0;
    args.ctx = ctx;
    if (run_with_timeout(timeout, perform_handshake_with_timeout_callback, &args)) {
        DEBUGP(("WinTLS: timeout!\n"));
        ctx->err_no = ETIMEDOUT;
        return false;
    }

    return args.retval == SEC_E_OK;
}

// Read/Peek callback args
typedef struct _WINTLS_RP_CB_ARGS {
    WINTLS_TRANSPORT_CONTEXT *ctx;
    ssl_fn_t func;
    char    *buf;
    int     bufsize;
    int     retval;
} WINTLS_RP_CB_ARGS, *P_WINTLS_RP_CB_ARGS;

static void wintls_read_peek_callback(void *arg) {
    WINTLS_RP_CB_ARGS *args = (WINTLS_RP_CB_ARGS *) arg;
    args->retval = args->func(args->ctx, args->buf, args->bufsize);
}

static int wintls_read_peek(int fd, char *buf, int bufsize, void *arg, double timeout, ssl_fn_t func) {
    WINTLS_RP_CB_ARGS args;

    if (timeout == -1) timeout = opt.read_timeout; // fd_read/fd_peek defines `-1`

    args.ctx = (WINTLS_TRANSPORT_CONTEXT*) arg;
    args.func = func;
    args.buf = buf;
    args.bufsize = bufsize;

    args.ctx->err_no = 0;

    if (run_with_timeout(timeout, wintls_read_peek_callback, &args)) {
        DEBUGP(("WinTLS: timeout!\n"));
        args.ctx->err_no = ETIMEDOUT;
        return -1;
    }

    return args.retval;
}

// #endif /* OPENSSL_RUN_WITHTIMEOUT */

/* Part 2: data exchange using the secure connection */

// socket layer
static int schannel_send(WINTLS_TRANSPORT_CONTEXT *ctx, char *buf, int len) {
    int n;
    EZ_BUFF SendBuff = {0};
    SECURITY_STATUS Status;
    SecBufferDesc   Message;
    SecBuffer       Buffers[4];
    //
    SecPkgContext_StreamSizes *pStreamSizes;

    ctx->err_no = 0;

    pStreamSizes = &ctx->stream_sizes;
    // get max decryption buffer size
    if (pStreamSizes->cbMaximumMessage == 0) {
        Status = g_pSSPI->QueryContextAttributes(&ctx->hContext, SECPKG_ATTR_STREAM_SIZES, pStreamSizes);
        if (Status != SEC_E_OK) {
            logprintf(LOG_NOTQUIET, "error reading SECPKG_ATTR_STREAM_SIZES\n");
            return Status;
        }
    }

    n = pStreamSizes->cbHeader + pStreamSizes->cbMaximumMessage + pStreamSizes->cbTrailer;

    if (!ez_buff_space(&SendBuff, n)) return 0;

    InitSecBuffer(&Buffers[0], pStreamSizes->cbHeader, SendBuff.data, SECBUFFER_STREAM_HEADER);
    InitSecBuffer(&Buffers[1], len, SendBuff.data + pStreamSizes->cbHeader, SECBUFFER_DATA);
    InitSecBuffer(&Buffers[2], pStreamSizes->cbTrailer, SendBuff.data + pStreamSizes->cbHeader + len, SECBUFFER_STREAM_TRAILER);
    InitSecBuffer(&Buffers[3], 0, NULL, SECBUFFER_EMPTY);
    InitSecBufferDesc(&Message, 4, Buffers);

    memcpy(Buffers[1].pvBuffer, buf, len);

    Status = g_pSSPI->EncryptMessage(&ctx->hContext, 0, &Message, 0);
    if (FAILED(Status)) {
        logprintf(LOG_NOTQUIET, "error: EncryptMessage: %#08lX\n", Status);
        n = 0;
        goto CLEANUP;
    }

    n = Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer;
    DEBUGP(("WinTLS: encrypted data len: %d\n", n));

    n = send(ctx->socket, SendBuff.data, n, 0);
    ctx->err_no = errno;
    DEBUGP(("WinTLS: sent encrypted data len: %d\n", n));
    if (n == SOCKET_ERROR || n == 0) {
        logprintf(LOG_NOTQUIET, "error send encrypted data: %d\n", WSAGetLastError());
    }
    else {
        ctx->can_recv = true;
    }

CLEANUP:
    ez_buff_free(&SendBuff);
    return n;
}

static int schannel_write(WINTLS_TRANSPORT_CONTEXT *ctx, char *buf, int len) {
    return schannel_send(ctx, buf, len);
}

static SECURITY_STATUS decrypt_data(WINTLS_TRANSPORT_CONTEXT *ctx) {
    SECURITY_STATUS Status;
    EZ_BUFF *rcv_buff;
    EZ_BUFF *dec_buff;
    int i, dec_n;
    SecBufferDesc   Message;
    SecBuffer       Buffers[4];
    SecBuffer       *pDataBuffer;
    SecBuffer       *pExtraBuffer;
    //
    rcv_buff = &ctx->rcv_buff;
    dec_buff = &ctx->dec_buff;

    do {
        InitSecBuffer(&Buffers[0], rcv_buff->used, rcv_buff->data, SECBUFFER_DATA);
        InitSecBuffer(&Buffers[1], 0, NULL, SECBUFFER_EMPTY);
        InitSecBuffer(&Buffers[2], 0, NULL, SECBUFFER_EMPTY);
        InitSecBuffer(&Buffers[3], 0, NULL, SECBUFFER_EMPTY);
        InitSecBufferDesc(&Message, 4, Buffers);
        //
        DEBUGP(("WinTLS: rcv_buff total/used/left %d/%d/%d\n", rcv_buff->size, rcv_buff->used, rcv_buff->size - rcv_buff->used));
        DEBUGP(("WinTLS: dec_buff total/used/left %d/%d/%d\n", dec_buff->size, dec_buff->used, dec_buff->size - dec_buff->used));
        //
        Status = g_pSSPI->DecryptMessage(&ctx->hContext, &Message, 0, NULL);
        //
        DEBUGP(("WinTLS: Status %#08lX\n", Status));
        //
        if (Status != SEC_E_OK && Status != SEC_I_RENEGOTIATE && Status != SEC_I_CONTEXT_EXPIRED) {
            break;
        }
        //
        // SEC_E_OK or SEC_I_RENEGOTIATE or SEC_I_CONTEXT_EXPIRED
        pDataBuffer  = NULL;
        pExtraBuffer = NULL;
        for (i = 1; i < 4; i++) {
            if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA) {
                pDataBuffer = &Buffers[i];
            }
            else if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA) {
                pExtraBuffer = &Buffers[i];
            }
        }
        if (pDataBuffer && pDataBuffer->cbBuffer > 0) {
            if (!ez_buff_space(dec_buff, pDataBuffer->cbBuffer + SCHANNEL_BUFFER_FREE_SIZE)) {
                break;
            }
            memcpy(dec_buff->data + dec_buff->used, pDataBuffer->pvBuffer, pDataBuffer->cbBuffer);
            dec_buff->used += pDataBuffer->cbBuffer;
            dec_n = pDataBuffer->cbBuffer;
        }
        else {
            dec_n = 0;
            ctx->can_recv = false; // <--end-- ???
        }
        if (pExtraBuffer) {
            memmove(rcv_buff->data, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
            rcv_buff->used = pExtraBuffer->cbBuffer;
            //
            // no need to FreeContextBuffer? SDK example does not.
            // The encrypted message is decrypted in place, overwriting the original contents of its buffer.
            // https://github.com/microsoft/referencesource/blob/master/System/net/System/Net/_SecureChannel.cs
        }
        else {
            /* End with no extra-data or exactly a block recieved? Hard to say.
                `5 bytes Tls header` + `message`
                https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record
            */
            rcv_buff->used = 0;
        }
        //
        DEBUGP(("WinTLS: Decrypted %d\n", dec_n));
        DEBUGP(("WinTLS: rcv_buff total/used/left %d/%d/%d\n", rcv_buff->size, rcv_buff->used, rcv_buff->size - rcv_buff->used));
        DEBUGP(("WinTLS: dec_buff total/used/left %d/%d/%d\n", dec_buff->size, dec_buff->used, dec_buff->size - dec_buff->used));
    } while (Status == SEC_E_OK && rcv_buff->used > 0);

    return Status;
}

/* decrypt enough data to be read/peeked
    Block/Stream cipher, will be decrypted in place.
*/
static int schannel_recv(WINTLS_TRANSPORT_CONTEXT *ctx, int len) {
    int n;
    EZ_BUFF *rcv_buff;
    EZ_BUFF *dec_buff;
    SECURITY_STATUS Status;
    //
    rcv_buff = &ctx->rcv_buff;
    dec_buff = &ctx->dec_buff;

    ctx->err_no = 0;

    do {
        //
        if (ctx->can_recv == false) {
            DEBUGP(("WinTLS: socket should not be read at the moment!\n"));
            break;
        }
        //
        // read enough data to decrypt
        DEBUGP(("WinTLS: Start recv() ...\n"));
        n = ez_socket_recv(ctx->socket, rcv_buff, 0);
        ctx->err_no = errno;
        if (n <= 0 || rcv_buff->used <= 0) {
            ctx->can_recv = false;
            return n;
        }
        //
        Status = decrypt_data(ctx);
        //
        if (Status == SEC_E_INCOMPLETE_MESSAGE) continue;
        //
        if (Status == SEC_E_DECRYPT_FAILURE && dec_buff->used > 0) break;
        //
        if (Status == SEC_I_CONTEXT_EXPIRED) {
            ctx->can_recv = false;
            break;
        }
        //
        if (Status == SEC_E_OK) break;  // <-- got enough decoded data that can be used
        //
        // The server requested renegotiation
        if (Status == SEC_I_RENEGOTIATE) {
            ctx->stage = HSK_ONGOING;
            Status = PerformHandshake(ctx);
            if (Status != SEC_E_OK) {
                logprintf(LOG_NOTQUIET, "WinTLS: renegotiation failed %#08lX\n", Status);
                ctx->can_recv = false;
                return -2;
            }
        }
    } while (dec_buff->used < len && rcv_buff->used > 0);

    return dec_buff->used;
}

static int schannel_read_peek(WINTLS_TRANSPORT_CONTEXT *ctx, char *buf, int len, int flags) {
    EZ_BUFF *dec_buff;
    int n;

    DEBUGP(("WinTLS: try to %s len: %d, dec_buff->used: %d\n", flags & MSG_PEEK ? "peek" : "read", len, ctx->dec_buff.used));

    dec_buff = &ctx->dec_buff;
    if (dec_buff->used <= 0) {
        n = schannel_recv(ctx, len);
        if (n <= 0) return n;
    }

    // read/peek some min len accessable decrypted data
    len = len < dec_buff->used ? len : dec_buff->used;
    if (len > 0) {
        memcpy(buf, dec_buff->data, len);
        if (!(flags & MSG_PEEK)) {
            dec_buff->used -= len;
            memmove(dec_buff->data, dec_buff->data + len, dec_buff->used);
        }
        //
        DEBUGP(("WinTLS: has %s len: %d, dec_buff->used: %d\n", flags & MSG_PEEK ? "peek" : "read", len, dec_buff->used));
    }

    return len;
}

static int schannel_read(WINTLS_TRANSPORT_CONTEXT *ctx, char *buf, int len) {
    return schannel_read_peek(ctx, buf, len, 0);
}

static int schannel_peek(WINTLS_TRANSPORT_CONTEXT *ctx, char *buf, int len) {
    return schannel_read_peek(ctx, buf, len, MSG_PEEK);
}


// Tls layer
static int wintls_read(int fd, char *buf, int bufsize, void *arg, double timeout) {
    return wintls_read_peek(fd, buf, bufsize, arg, timeout, schannel_read);
}

static int wintls_write (int fd _GL_UNUSED, char *buf, int bufsize, void *arg) {
    return schannel_write((WINTLS_TRANSPORT_CONTEXT*)arg, buf, bufsize);
}

static int wintls_poll(int fd, double timeout, int wait_for, void *arg) {
    int ret;
    WINTLS_TRANSPORT_CONTEXT *ctx = arg;

    ctx->err_no = 0;

    // readable bytes buffered
    if (ctx->dec_buff.used > 0) return 1;
    // otherwise
    if (timeout == -1) timeout = opt.read_timeout;
    ret = select_fd(fd, timeout, wait_for);
    ctx->err_no = errno;

    if (ret == 0) ctx->err_no = ETIMEDOUT; // select_fd says

    return ret;
}

static int wintls_peek(int fd, char *buf, int bufsize, void *arg, double timeout) {
    return wintls_read_peek(fd, buf, bufsize, arg, timeout, schannel_peek);
}

static const char* wintls_errstr(int fd _GL_UNUSED, void *arg) {
    WINTLS_TRANSPORT_CONTEXT *ctx = arg;
    return strerror(ctx->err_no);
}

static void wintls_close(int fd, void *arg) {
    WINTLS_TRANSPORT_CONTEXT *ctx = arg;

    DisconnectFromServer(ctx);
    g_pSSPI->FreeCredentialsHandle(&ctx->hCreds);
    g_pSSPI->DeleteSecurityContext(&ctx->hContext);
    ez_buff_free(&ctx->rcv_buff);
    ctx->rcv_buff.used = 0;
    ez_buff_free(&ctx->dec_buff);
    ctx->dec_buff.used = 0;
    free(ctx);
    closesocket(fd);
}

/* wintls_transport is the singleton that describes the SSL transport
   methods provided by this file. */
static struct transport_implementation wintls_transport = {
    wintls_read, wintls_write, wintls_poll,
    wintls_peek, wintls_errstr, wintls_close
};


/* Part 3: Public interfaces */

bool ssl_init(void) {
    // Init Winsock
    // Done by ws_startup() in mswindows.c since main initializes socket
    //
    // Dynamically load platform dll and initiate SSPI interface
    if (!LoadSecurityLibrary()) {
        logprintf(LOG_NOTQUIET, "WinTLS: Initializing SSPI failed!\n");
        return false;
    }
    return true;
}

/* Perform the SSL/TLS handshake and wrap the connection handle reader and writer
    connection-oriented sockets (type SOCK_STREAM)
*/
bool ssl_connect_wget(int fd /*socket*/, const char *hostname, int *continue_session) {
    WINTLS_TRANSPORT_CONTEXT *wintls_ctx;

    wintls_ctx = calloc(1, sizeof(WINTLS_TRANSPORT_CONTEXT));
    if (wintls_ctx == NULL) {
        logprintf(LOG_NOTQUIET, "WinTLS: calloc failed!\n");
        return false;
    }
    DEBUGP(("WinTLS: socket %d, wintls_ctx @ 0x%p\n", fd, wintls_ctx));

    // Obtain Schannel credentials
    if (CreateCredentials(&wintls_ctx->hCreds) != SEC_E_OK) return false;
    DEBUGP(("WinTLS: Credentials created.\n"));

    // Create an Schannel security context by handshake
    wintls_ctx->stage = HSK_CLIENT_HELLO;

    wintls_ctx->socket = fd;
    // store for renegotiation
    wintls_ctx->hostname = (char *)hostname;
    if (!perform_handshake_with_timeout(wintls_ctx, opt.read_timeout)) {
        g_pSSPI->FreeCredentialsHandle(&wintls_ctx->hCreds);
        return false;
    }
    DEBUGP(("WinTLS: Handshake succeeded.\n"));

    // verified or `--no-check-certificate`
    wintls_ctx->stage = HSK_VERIFIED;

    /* connect.h: transport_implementation */
    fd_register_transport (fd, &wintls_transport, wintls_ctx);
    DEBUGP(("WinTLS: IO layer initialized.\n"));

    return true;
}

// done by: SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_REVOCATION_CHECK_CHAIN
bool ssl_check_certificate(int fd, const char *host) {
    return true;
}
