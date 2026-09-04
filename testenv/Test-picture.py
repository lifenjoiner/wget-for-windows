#!/usr/bin/env python3
from sys import exit
from test.http_test import HTTPTest
from misc.wget_file import WgetFile

"""
    Test for Drupal <picture> block image downloading issue.
"""

############# File Definitions ###############################################
# HTML content with picture elements
HTML_CONTENT = """<!DOCTYPE html>
<html>
<head>
    <title>Picture Element Test</title>
</head>
<body>
    <h1>Picture Element Test</h1>

    <!-- Drupal picture block with lazy-loaded images -->
    <picture>
        <source data-srcset="find_scatter_low_res_alt_0.jpg" type="image/jpeg" srcset="find_scatter_low_res_alt_0.jpg">
        <img data-src="find_scatter_low_res_alt_0.jpg" alt="Test image" class="lazy error" title="" src="find_scatter_low_res_alt_0.jpg" data-was-processed="true">
    </picture>

    <!-- Normal img tag for comparison -->
    <img src="normal_image.jpg" alt="Normal image">

    <!-- Another picture block with normal srcset -->
    <picture>
        <source srcset="another_image.jpg" type="image/jpeg">
        <img src="another_image.jpg" alt="Another image">
    </picture>
</body>
</html>"""

# Create WgetFile objects for the files
# These represent files that will be "served" by the test server
picture_file = WgetFile("picture.html", HTML_CONTENT)
find_scatter_file = WgetFile("find_scatter_low_res_alt_0.jpg", "Fake image content 1")
normal_image_file = WgetFile("normal_image.jpg", "Fake image content 2")
another_image_file = WgetFile("another_image.jpg", "Fake image content 3")

# ServerFiles expects a list of lists - one inner list per server
# Since we have one server (HTTP), we wrap in an extra list
ServerFiles = [[
    picture_file,
    find_scatter_file,
    normal_image_file,
    another_image_file,
]]

# Wget command line options
WGET_OPTIONS = "-nH --recursive --level=0 --convert-links --page-requisites --no-parent --convert-file-only -e robots=off --adjust-extension"

# URLs to download (relative to the server base URL)
WGET_URLS = [["picture.html"]]

# Create WgetFile objects for the expected downloaded files
ExpectedDownloadedFiles = [
    WgetFile("picture.html", HTML_CONTENT),
    WgetFile("find_scatter_low_res_alt_0.jpg", "Fake image content 1"),
    WgetFile("normal_image.jpg", "Fake image content 2"),
    WgetFile("another_image.jpg", "Fake image content 3"),
]

ExpectedReturnCode = 0

################ Pre and Post Test Hooks #####################################
pre_test = {
    "ServerFiles": ServerFiles,
}
test_options = {
    "WgetCommands": WGET_OPTIONS,
    "Urls": WGET_URLS
}
post_test = {
    "ExpectedFiles": ExpectedDownloadedFiles,
    "ExpectedRetcode": ExpectedReturnCode
}

err = HTTPTest (
                pre_hook=pre_test,
                test_params=test_options,
                post_hook=post_test
).begin ()

exit (err)
