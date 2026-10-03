#!/usr/bin/env python3
"""
Test that Authorization and Cookie headers are preserved on same-host redirects.

When wget follows a redirect to the same host (hostname parts of URLs are the
same), Authorization and Cookie headers must be forwarded to the new location.
This is the complementary case to Test-redirect-auth-cookie.py which tests the
cross-host redirect scenario (CVE-2021-31879).
"""
from sys import exit
from test.http_test import HTTPTest
from test.base_test import HTTP
from misc.wget_file import WgetFile

############# File Definitions ###############################################
# Server 1 (redirector): Returns a 301 redirect to another path on the same server
RedirectRules = {
    "Response": 301,
    "SendHeader": {"Location": "/target.txt"}
}
RedirectFile = WgetFile("redirect.txt", "", rules=RedirectRules)

# Server 1 (target): Should receive Authorization and Cookie headers
# If they are missing, the test will fail
TargetRules = {
    # ExpectHeader must come before Response because the server processes
    # rules in order, and Response raises an exception that short-circuits
    # further rule processing.
    "ExpectHeader": {
        "Authorization": "Bearer secret-token",
        "Cookie": "session=abc123"
    },
    "Response": 200
}
TargetFile = WgetFile("target.txt", "Success - headers were preserved!")

# wget will be invoked with --header options for both Authorization and Cookie
WGET_OPTIONS = '--header="Authorization: Bearer secret-token" --header="Cookie: session=abc123"'

# Request only from Server 1 (both redirector and target)
WGET_URLS = [["redirect.txt"]]

Servers = [HTTP]

Files = [[RedirectFile, TargetFile]]

ExpectedReturnCode = 0
ExpectedDownloadedFiles = [WgetFile("redirect.txt", "Success - headers were preserved!")]

################ Pre and Post Test Hooks #####################################
pre_test = {
    "ServerFiles": Files
}
test_options = {
    "WgetCommands": WGET_OPTIONS,
    "Urls": WGET_URLS
}
post_test = {
    "ExpectedFiles": ExpectedDownloadedFiles,
    "ExpectedRetcode": ExpectedReturnCode
}

err = HTTPTest(
    pre_hook=pre_test,
    test_params=test_options,
    post_hook=post_test,
    protocols=Servers
).begin()

exit(err)
