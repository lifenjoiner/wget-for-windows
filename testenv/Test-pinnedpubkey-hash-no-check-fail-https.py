#!/usr/bin/env python3
from sys import exit
from test.http_test import HTTPTest
from test.base_test import HTTPS, SKIP_TEST
from misc.wget_file import WgetFile
import os

"""
    This test ensures that Wget can download files from HTTPS Servers
"""
if os.getenv('SSL_TESTS') is None:
    exit (SKIP_TEST)

############# File Definitions ###############################################
File1 = "Would you like some Tea?"
File2 = "With lemon or cream?"

A_File = WgetFile ("File1", File1)
B_File = WgetFile ("File2", File2)

WGET_OPTIONS = "--no-check-certificate --pinnedpubkey=sha256//invalid"
WGET_URLS = [["File1", "File2"]]

Files = [[A_File, B_File]]

Servers = [HTTPS]

ExpectedReturnCode = 5
ExpectedDownloadedFiles = []

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
                post_hook=post_test,
                protocols=Servers
).begin ()

exit (err)
