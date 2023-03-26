/* Windows native IDN support.
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


#include <winnls.h>

/* Windows idn APIs are Unicode based
    https://docs.microsoft.com/en-us/windows/win32/intl/nls--internationalized-domain-name--idn--conversion-sample
*/
#define IDN_MAX_LENGTH 254 // https://en.wikipedia.org/wiki/Hostname

char *idn_encode(const char *encoding, const char *host) {
    wchar_t *host_w = NULL;
    wchar_t *punycode_w = NULL;
    char *punycode = NULL;


    if (!transcode("UTF-16LE", encoding, host, strlen(host), (char**) &host_w)) {
        goto cleanup;
    }

    punycode_w = calloc(IDN_MAX_LENGTH, sizeof(wchar_t));
    if (punycode_w == NULL) {
        logprintf (LOG_VERBOSE, "calloc failed: 0x%08X\n", errno);
        goto cleanup;
    }

    if (IdnToAscii(IDN_ALLOW_UNASSIGNED, host_w, -1, punycode_w, IDN_MAX_LENGTH) == 0) {
        logprintf (LOG_VERBOSE, "IdnToAscii failed: 0x%08lX\n", GetLastError());
        goto cleanup;
    }

    transcode(encoding, "UTF-16LE", (char*) punycode_w, wcslen(punycode_w) * 2, &punycode);

    DEBUGP (("WinIDN: host -> punycode: '%s'\n", punycode));

cleanup:
    free(punycode_w);
    free(host_w);

    return punycode;
}
