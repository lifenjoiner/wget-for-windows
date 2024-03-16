/* Internationalization related declarations.
   Copyright (C) 2008-2011, 2015, 2018-2024 Free Software Foundation,
   Inc.

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

#ifndef IRI_H
#define IRI_H

/* Transcoding is still needed to convert remote file names to local encoded */
#ifdef HAVE_ICONV

char *parse_charset (const char *str);
const char *find_locale (void);
bool check_encoding_name (const char *encoding);
char *locale_to_utf8 (const char *str);
bool remote_to_utf8 (const char *encoding, const char *str, char **new);
bool transcode (const char *tocode, const char *fromcode,
                char const *in, size_t inlen, char **out);

#else

#define parse_charset(str)          NULL
#define find_locale()               NULL
#define check_encoding_name(str)    false
#define locale_to_utf8(str)         (str)
#define remote_to_utf8(a,b,c)       false

#endif


#ifdef ENABLE_IRI

#ifndef WINDOWS
# include <idn2.h>
#endif

char *idn_encode (const char *encoding, const char *host);
char *idn_decode (const char *host);

#else /* ENABLE_IRI */

#define idn_encode(a,b)             NULL
#define idn_decode(str)             NULL
#define idn2_free(str)              ((void)0)

#endif /* ENABLE_IRI */
#endif /* IRI_H */
