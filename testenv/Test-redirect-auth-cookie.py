#!/usr/bin/env python3
"""
Test for CVE-2021-31879: Authorization and Cookie headers must be discarded
on cross-host redirects.

This test verifies that when wget follows a redirect to a different host,
Authorization and Cookie headers are NOT forwarded to the new location.
"""
from sys import exit
from test.http_test import HTTPTest
from test.base_test import HTTP
from misc.wget_file import WgetFile

############# File Definitions ###############################################
# Server 1 (redirector): Returns a 301 redirect to Server 2
# The {{port}} placeholder will be replaced by the UpdateRedirect hook
RedirectRules = {
    "Response": 301,
    "SendHeader": {"Location": "http://localhost:{{port}}/target.txt"}
}
RedirectFile = WgetFile("redirect.txt", "", rules=RedirectRules)

# Server 2 (target): Should NOT receive Authorization or Cookie headers
# If it does, the RejectHeader rule will cause the server to return 400
TargetRules = {
    "Response": 200,
    "RejectHeader": {
        "Authorization": "Bearer secret-token",
        "Cookie": "session=abc123"
    }
}
TargetFile = WgetFile("target.txt", "Success - headers were discarded!")

# wget will be invoked with --header options for both Authorization and Cookie
WGET_OPTIONS = '--header="Authorization: Bearer secret-token" --header="Cookie: session=abc123"'

# Request only from Server 1 (the redirector)
WGET_URLS = [["redirect.txt"]]

Servers = [HTTP, HTTP]

Files = [[RedirectFile], [TargetFile]]
# Rules structure mirrors Files: [[rules_for_server_0], [rules_for_server_1]]
ServerRules = [[RedirectRules], [TargetRules]]

ExpectedReturnCode = 0
ExpectedDownloadedFiles = [WgetFile("redirect.txt", "Success - headers were discarded!")]

################ Pre and Post Test Hooks #####################################
# UpdateRedirect must come BEFORE ServerFiles so that the port replacement
# happens before the server is configured with the rules
pre_test = {
    # UpdateRedirect replaces {{port}} in redirect rules with actual port
    "UpdateRedirect": ServerRules,
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
