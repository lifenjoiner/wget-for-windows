#!/usr/bin/env python3

import platform
from sys import exit
from test.http_test import HTTPTest

from misc.wget_file import WgetFile

"""
Test that Wget handles the --convert-links (-k) option correctly.

Also tests that the --restrict-file-names option works as expected by using a
filename with restricted characters and ensuring that it uses the correct
characterset based on the current OS
"""

# MINGW32_NT-10.0-20348/MINGW64_NT-10.0-20348: requires Linux flavor
if platform.system()[0:10] in ["MINGW32_NT", "MINGW64_NT", "Windows"]:
    converted_filename = "site;sub%3A.html"
    converted_linkpath = "site%3Bsub%253A.html"
else:
    converted_filename = "site;sub:.html"
    converted_linkpath = "./site%3Bsub:.html"

############################## File Definitions ##############################
index = """
<html>
  <head>
    <title>Index</title>
  </head>
  <body>
    <a href="site;sub:.html">Site</a>
  </body>
</html>
"""

converted = '''
<html>
  <head>
    <title>Index</title>
  </head>
  <body>
    <a href="''' + converted_linkpath + '''">Site</a>
  </body>
</html>
'''

site = """
<html>
  <head>
    <title>Site</title>
  </head>
  <body>
    Subsite
  </body>
</html>
"""

IndexPage = WgetFile("index.html", index)
SubSite = WgetFile("site;sub:.html", site)
LocalSubSite = WgetFile(converted_filename, site)
LocalIndexPage = WgetFile("index.html", converted)

print(platform.system())
restrict = "unix" if platform.system() in ["Linux", "Darwin"] else "windows"

WGET_OPTIONS = f"-k -r -nH --restrict-file-names={restrict}"
WGET_URLS = [["index.html"]]

Files = [[IndexPage, SubSite]]

ExpectedReturnCode = 0
ExpectedDownloadedFiles = [LocalIndexPage, LocalSubSite]

########################### Pre and Post Test Hooks ##########################
pre_test = {
    "ServerFiles": Files,
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
).begin()

exit(err)
