# Makefile for `wget' utility
# Copyright (C) 1995-2011, 2015, 2018-2024 Free Software Foundation,
# Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Wget.  If not, see <http://www.gnu.org/licenses/>.

# Additional permission under GNU GPL version 3 section 7

# If you modify this program, or any covered work, by linking or
# combining it with the OpenSSL project's OpenSSL library (or a
# modified version of that library), containing parts covered by the
# terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
# grants you additional permission to convey the resulting work.
# Corresponding Source for a non-source form of such a combination
# shall include the source code for the parts of OpenSSL used as well
# as that of the covered work.

# see http://www.gnu.org/software/automake/manual/html_node/Parallel-Test-Harness.html#Parallel-Test-Harness

#
# Version: @VERSION@
#

../src/wget$(EXEEXT):
	cd ../src && $(MAKE) $(AM_MAKEFLAGS)

# Make libunittest "PHONY" so we're always sure we're up-to-date.
.PHONY: ../src/libunittest.a
../src/libunittest.a:
	cd ../src && $(MAKE) $(AM_MAKEFLAGS) libunittest.a

../lib/libgnu.a:
	cd ../lib && $(MAKE) $(AM_MAKEFLAGS)

if WITH_WINTLS
  HTTPS_TESTS =
else
  HTTPS_TESTS = \
             Test-proxied-https-auth.px \
             Test-proxied-https-auth-keepalive.px \
             Test-https-pfs.px \
             Test-https-tlsv1.px \
             Test-https-tlsv1x.px \
             Test-https-selfsigned.px \
             Test-https-weboftrust.px \
             Test-https-clientcert.px \
             Test-https-crl.px \
             Test-https-badcerts.px
endif

PX_TESTS = \
             Test-c-full.px \
             Test-c-partial.px \
             Test-c.px \
             Test-c-shorter.px \
             Test-cookies.px \
             Test-cookies-401.px \
             Test-E-k-K.px \
             Test-E-k.px \
             Test-ftp.px \
             Test-ftp-dir.px \
             Test-ftp-pasv-fail.px \
             Test-ftp-bad-list.px \
             Test-ftp-recursive.px \
             Test-ftp-iri.px \
             Test-ftp-iri-fallback.px \
             Test-ftp-iri-recursive.px \
             Test-ftp-iri-disabled.px \
             Test-ftp-list-Multinet.px \
             Test-ftp-list-Unknown.px \
             Test-ftp-list-Unknown-a.px \
             Test-ftp-list-Unknown-hidden.px \
             Test-ftp-list-Unknown-list-a-fails.px \
             Test-ftp-list-UNIX-hidden.px \
             Test-ftp--start-pos.px \
             Test-HTTP-Content-Disposition-1.px \
             Test-HTTP-Content-Disposition-2.px \
             Test-HTTP-Content-Disposition.px \
             Test-i-ftp.px \
             Test-i-http.px \
             Test-idn-headers.px \
             Test-idn-meta.px \
             Test-idn-cmd.px \
             Test-idn-cmd-utf8.px \
             Test-idn-robots.px \
             Test-idn-robots-utf8.px \
             Test-iri.px \
             Test-iri-percent.px \
             Test-iri-disabled.px \
             Test-iri-forced-remote.px \
             Test-iri-list.px \
             Test-meta-robots.px \
             Test-N-current.px \
             Test-N-HTTP-Content-Disposition.px \
             Test-N--no-content-disposition.px \
             Test-N--no-content-disposition-trivial.px \
             Test-N-no-info.px \
             Test--no-content-disposition.px \
             Test--no-content-disposition-trivial.px \
             Test-N-old.px \
             Test-nonexisting-quiet.px \
             Test-noop.px \
             Test-np.px \
             Test-N.px \
             Test-N-smaller.px \
             Test-O-HTTP-Content-Disposition.px \
             Test-O-nc.px \
             Test-O--no-content-disposition.px \
             Test-O--no-content-disposition-trivial.px \
             Test-O-nonexisting.px \
             Test-O.px \
             Test--post-file.px \
             Test-proxy-auth-basic.px \
             Test-restrict-ascii.px \
             Test-Restrict-Lowercase.px \
             Test-Restrict-Uppercase.px \
             Test-stdouterr.px \
             Test--spider-fail.px \
             Test--spider.px \
             Test--spider-r-HTTP-Content-Disposition.px \
             Test--spider-r--no-content-disposition.px \
             Test--spider-r--no-content-disposition-trivial.px \
             Test--spider-r.px \
             Test--start-pos.px \
             Test--start-pos--continue.px \
             Test--httpsonly-r.px \
             Test-204.px \
             Test-ftp-pasv-not-supported.px \
             $(HTTPS_TESTS)

EXTRA_DIST = FTPServer.pm FTPTest.pm HTTPServer.pm HTTPTest.pm \
             SSLTest.pm SSLServer.pm \
             WgetTests.pm WgetFeature.pm $(PX_TESTS) \
             certs valgrind-suppressions valgrind-suppressions-ssl

check_PROGRAMS = unit-tests
unit_tests_SOURCES = unit-tests.c unit-tests.h
LDADD = ../src/libunittest.a ../lib/libgnu.a \
 $(CLOCK_TIME_LIB) \
 $(GETADDRINFO_LIB) \
 $(GETRANDOM_LIB) \
 $(HARD_LOCALE_LIB) \
 $(HOSTENT_LIB) \
 $(INET_NTOP_LIB) \
 $(LIBSOCKET) \
 $(LIBTHREAD) \
 $(LIB_CRYPTO) \
 $(LIBC32CONV) \
 $(LIBICONV) \
 $(LIBINTL) \
 $(LIBUNISTRING) \
 $(MBRTOWC_LIB) \
 $(NANOSLEEP_LIB) \
 $(POSIX_SPAWN_LIB) \
 $(PTHREAD_SIGMASK_LIB) \
 $(SELECT_LIB) \
 $(SERVENT_LIB) \
 $(SETLOCALE_NULL_LIB)
AM_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 -I$(top_srcdir)/src -DLOCALEDIR=\"$(localedir)\"
AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)


CLEANFILES = *~ *.bak core core.[0-9]*

TESTS = unit-tests$(EXEEXT) $(PX_TESTS)
TEST_EXTENSIONS = .px
PX_LOG_COMPILER = $(PERL)
AM_PX_LOG_FLAGS = -I$(srcdir)
AM_TESTS_ENVIRONMENT = export WGETRC=; export SYSTEM_WGETRC=;\
 export VALGRIND_TESTS="@VALGRIND_TESTS@";
