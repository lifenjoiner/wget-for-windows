#!/usr/bin/env python3
from sys import exit
from test.http_test import HTTPTest
from misc.wget_file import WgetFile
from platform import platform

"""
    This test ensures that Wget handles Cookie expiry dates correctly.
    Simultaneuously, we also check if multiple cookies to the same domain
    are handled correctly
"""
############# File Definitions ###############################################
File1 = "Hello World!"
File2 = "'Ello! This is Amazing!"
File3 = "So what are we looking at?"
File4 = "This was downloaded"

File1_rules = {
    "SendHeader"        : {
        "Set-Cookie"    : "sess-id=0213; path=/"
    }
}
File2_rules = {
    "ExpectHeader"      : {
        "Cookie"        : "sess-id=0213"
    },
    "SendHeader"        : {
        "Set-Cookie"    : "new-sess=N"
    }
}
File3_rules = {
    "SendHeader"        : {
        # use upper case 'I' to provoke Wget failure with turkish locale
        "Set-Cookie"    : "sess-id=0213; path=/; ExPIRes=Sun, 06 Nov 2001 12:32:43 GMT"
    },
    "ExpectHeader"      : {
        # buildin `store_cookie` uses `hash_table_put` by domain
        # It puts cookies LIFO, the last in the frist.
        # The trick is that `qsort` (by domain and path) is UNSTABLE:
        #   msvcrt bubbles the biggest to the last!
        #   gnulibc bubbles the smallest to the first!
        #   They all set the 1st as initial selected. msvcrt is more unstable.
        "Cookie"        : "sess-id=0213; new-sess=N" if "Windows" in platform()
                            else "new-sess=N; sess-id=0213"
    }
}
File4_rules = {
    "RejectHeader"      : {
        "Cookie"        : "sess-id=0213"
    },
    "ExpectHeader"      : {
        "Cookie"        : "new-sess=N"
    }
}
A_File = WgetFile ("File1", File1, rules=File1_rules)
B_File = WgetFile ("File2", File2, rules=File2_rules)
C_File = WgetFile ("File3", File3, rules=File3_rules)
D_File = WgetFile ("File4", File4, rules=File4_rules)

WGET_OPTIONS = ""
WGET_URLS = [["File1", "File2", "File3", "File4"]]

Files = [[A_File, B_File, C_File, D_File]]

ExpectedReturnCode = 0
ExpectedDownloadedFiles = [A_File, B_File, C_File, D_File]

################ Pre and Post Test Hooks #####################################
pre_test = {
    "ServerFiles"       : Files
}
test_options = {
    "WgetCommands"      : WGET_OPTIONS,
    "Urls"              : WGET_URLS
}
post_test = {
    "ExpectedFiles"     : ExpectedDownloadedFiles,
    "ExpectedRetcode"   : ExpectedReturnCode
}

err = HTTPTest (
                pre_hook=pre_test,
                test_params=test_options,
                post_hook=post_test
).begin ()

exit (err)
