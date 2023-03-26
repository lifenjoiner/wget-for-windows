/* IRI related functions.
   Copyright (C) 2008-2011, 2015, 2018-2023 Free Software Foundation,
   Inc.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or (at
your option) any later version.

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

#include "wget.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <langinfo.h>
#include <errno.h>
#ifdef HAVE_ICONV
# include <iconv.h>
#endif

#ifdef ENABLE_IRI
#ifndef WINDOWS
#include <idn2.h>
#if IDN2_VERSION_NUMBER < 0x00140000
# include <unicase.h>
# include <unistr.h>
#endif
#endif
#endif

#include "utils.h"
#include "url.h"
#include "c-strcase.h"
#include "c-strcasestr.h"
#include "xstrndup.h"

/* Note: locale encoding is kept in options struct (opt.locale) */

/* Transcoding is still needed to convert remote file names to local encoded */
#ifdef HAVE_ICONV

/* Given a string containing "charset=XXX", return the encoding if found,
   or NULL otherwise */
char *
parse_charset (const char *str)
{
  const char *end;
  char *charset;

  if (!str || !*str)
    return NULL;

  str = c_strcasestr (str, "charset=");
  if (!str)
    return NULL;

  str += 8;
  end = str;

  /* sXXXav: which chars should be banned ??? */
  while (*end && !c_isspace (*end))
    end++;

  /* sXXXav: could strdupdelim return NULL ? */
  charset = strdupdelim (str, end);

  /* Do a minimum check on the charset value */
  if (!check_encoding_name (charset))
    {
      xfree (charset);
      return NULL;
    }

  /*logprintf (LOG_VERBOSE, "parse_charset: %s\n", quote (charset));*/

  return charset;
}

/* Find the locale used, or fall back on a default value */
const char *
find_locale (void)
{
	const char *encoding = nl_langinfo(CODESET);

	if (!encoding || !*encoding)
		return xstrdup("ASCII");

   return xstrdup(encoding);
}

/* Basic check of an encoding name. */
bool
check_encoding_name (const char *encoding)
{
  const char *s = encoding;

  while (*s)
    {
      if (!c_isascii (*s) || c_isspace (*s))
        {
          logprintf (LOG_VERBOSE, _("Encoding %s isn't valid\n"), quote (encoding));
          return false;
        }

      s++;
    }

  return true;
}

/* Do the conversion according to the passed conversion descriptor cd. *out
   will contain the transcoded string on success. *out content is
   unspecified otherwise. */
bool
transcode (const char *tocode, const char *fromcode, char const *in, size_t inlen, char **out)
{
  iconv_t cd;
  size_t len, done, outlen;
  int tooshort = 0;
  char *s;
  bool ret = false;

  if (!strcasecmp (fromcode, tocode))
    {
      *out = strdup (in);
      DEBUGP (("Encoding is already %s\n", tocode));
      return true;
    }

  cd = iconv_open (tocode, fromcode);
  if (cd == (iconv_t)(-1))
    {
      logprintf (LOG_VERBOSE, _("Conversion from %s to %s isn't supported\n"),
                 quote_n (0, fromcode), quote_n (1, tocode));
      *out = NULL;
      return ret;
    }

  len = outlen = inlen * 2;
  *out = s = xmalloc (outlen + 2); /* Unicode too */
  done = 0;

  for (;;)
    {
      if (iconv (cd, (ICONV_CONST char **) &in, &inlen, out, &outlen) != (size_t)(-1) &&
          iconv (cd, NULL, NULL, out, &outlen) != (size_t)(-1))
        {
          *out = s;
          *(short*)(s + len - outlen - done) = '\0';
          ret = true;
          break;
        }

      if (errno == E2BIG) /* Output buffer full */
        {
          tooshort++;
          done = len;
          len = done + inlen * 2;
          s = xrealloc (s, len + 1);
          *out = s + done - outlen;
          outlen += inlen * 2;
        }
      else if (errno == EINVAL || errno == EILSEQ)
        {
          logprintf (LOG_VERBOSE,
                    _("Incomplete or invalid multibyte sequence encountered\n"));
          break;
        }
      else /* Weird, we got an unspecified error */
        {
          logprintf (LOG_VERBOSE, _("Unhandled errno %d\n"), errno);
          break;
        }
    }

  iconv_close(cd);

  if (!ret)
    {
      xfree (s);
      *out = NULL;
    }

  return ret;
}

/* Transcode only.
   unescape/escape (reencode_escapes) in url_parse.
*/
static bool
iri_transcode (const char *tocode, const char *fromcode, char const *in, size_t inlen, char **out)
{
  bool ret = false;

  bool have_cred = strchr(in, '@');

  IF_DEBUG
  {
    /* Do not print out embedded passwords, in might be an URL */
    if (have_cred)
      {
        debug_logprintf ("Logging suppressed, strings may contain password\n");
        debug_logprintf ("Converting: %s -> %s\n", fromcode, tocode);
      }
    else
      debug_logprintf ("Converting: '%s', %s -> %s\n", in, fromcode, tocode);
  }

  ret = transcode (tocode, fromcode, in, inlen, out);

  if (ret) IF_DEBUG
  {
    /* Do not print out embedded passwords, in might be an URL */
    if (have_cred)
      debug_logprintf ("Converted.\n");
    else
      debug_logprintf ("Converted:  '%s'\n", *out);
  }

  return ret;
}

static bool
iri_to_utf8 (const char *encoding, const char *str, char **new)
{
  if (!encoding)
    return false;

  return iri_transcode ("UTF-8", encoding, str, strlen (str), new);
}

/* Try converting string str from locale to UTF-8. Return a new string
   on success, or str on error or if conversion isn't needed. */
char *
locale_to_utf8 (const char *str)
{
  char *new;

  /* That shouldn't happen, just in case */
  if (!opt.locale)
    {
      logprintf (LOG_VERBOSE, _("locale_to_utf8: locale is unset\n"));
      opt.locale = find_locale ();
    }

  iri_to_utf8 (opt.locale, (char *) str, &new);

  return new;
}

/* Try to transcode string str from remote encoding to UTF-8. On success, *new
   contains the transcoded string. *new content is unspecified otherwise. */
bool
remote_to_utf8 (const char *encoding, const char *str, char **new)
{
  return iri_to_utf8 (encoding, str, new);
}

#endif

#ifdef ENABLE_IRI

#ifdef WINDOWS

#include "win-idn.c"

#else

/* Try to "ASCII encode" UTF-8 host. Return the new domain on success or NULL
   on error. */
char *
idn_encode (const char *encoding, const char *host)
{
  int ret;
  char *ascii_encoded;
  char *utf8_encoded = NULL;
  const char *src;
#if IDN2_VERSION_NUMBER < 0x00140000
  uint8_t *lower;
  size_t len = 0;
#endif

  /* Encode to UTF-8 if not done */
  if (c_strcasecmp (encoding, "UTF-8"))
    {
      if (!remote_to_utf8 (encoding, host, &utf8_encoded))
          return NULL;  /* Nothing to encode or an error occurred */
      src = utf8_encoded;
    }
  else
    src = host;

#if IDN2_VERSION_NUMBER >= 0x00140000
  /* IDN2_TRANSITIONAL implies input NFC encoding */
  ret = idn2_lookup_u8 ((uint8_t *) src, (uint8_t **) &ascii_encoded, IDN2_NONTRANSITIONAL);
  if (ret != IDN2_OK)
    /* fall back to TR46 Transitional mode, max IDNA2003 compatibility */
    ret = idn2_lookup_u8 ((uint8_t *) src, (uint8_t **) &ascii_encoded, IDN2_TRANSITIONAL);

  if (ret != IDN2_OK)
    logprintf (LOG_VERBOSE, _("idn_encode failed (%d): %s\n"), ret,
               quote (idn2_strerror (ret)));
#else
  /* we need a conversion to lowercase */
  lower = u8_tolower ((uint8_t *) src, u8_strlen ((uint8_t *) src) + 1, 0, UNINORM_NFKC, NULL, &len);
  if (!lower)
    {
      logprintf (LOG_VERBOSE, _("Failed to convert to lower: %d: %s\n"),
                 errno, quote (src));
      xfree (utf8_encoded);
      return NULL;
    }

  if ((ret = idn2_lookup_u8 (lower, (uint8_t **) &ascii_encoded, IDN2_NFC_INPUT)) != IDN2_OK)
    {
      logprintf (LOG_VERBOSE, _("idn_encode failed (%d): %s\n"), ret,
                 quote (idn2_strerror (ret)));
    }

  xfree (lower);
#endif

  xfree (utf8_encoded);

  if (ret == IDN2_OK && ascii_encoded)
    {
      char *tmp = xstrdup (ascii_encoded);
      idn2_free (ascii_encoded);
      ascii_encoded = tmp;
    }

  return ret == IDN2_OK ? ascii_encoded : NULL;
}

#endif

/* Try to decode an "ASCII encoded" host. Return the new domain in the locale
   on success or NULL on error. */
char *
idn_decode (const char *host)
{
/*
  char *new;
  int ret;

  ret = idn2_register_u8 (NULL, host, (uint8_t **) &new, 0);
  if (ret != IDN2_OK)
    {
      logprintf (LOG_VERBOSE, _("idn2_register_u8 failed (%d): %s: %s\n"), ret,
                 quote (idn2_strerror (ret)), host);
      return NULL;
    }

  return new;
*/
  /* idn2_register_u8() just works label by label.
   * That is pretty much overhead for just displaying the original ulabels.
   * To keep at least the debug output format, return a cloned host. */
  return xstrdup(host);
}

#endif
