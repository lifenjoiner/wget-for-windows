from conf import hook

# Pre-Test Hook: UpdateRedirect
# This hook updates redirect rules to replace {{port}} placeholders with the
# actual port of the target server. This is needed because _replace_substring
# is only applied to file content, not to file rules.


@hook()
class UpdateRedirect:
    def __init__(self, rules):
        # rules is a list of lists: [[rules_for_server_0], [rules_for_server_1], ...]
        self.rules = rules

    def __call__(self, test_obj):
        if len(self.rules) != len(test_obj.servers):
            raise ValueError(
                "UpdateRedirect: rule count (%d) does not match server count (%d)"
                % (len(self.rules), len(test_obj.servers))
            )
        for _, rules_list in enumerate(self.rules):
            for file_rules in rules_list:
                if "SendHeader" in file_rules:
                    send_header = file_rules["SendHeader"]
                    if "Location" in send_header:
                        location = send_header["Location"]
                        # Replace {{port}} with the last server's port
                        # (the redirect target server's port)
                        if test_obj.ports:
                            target_port = test_obj.ports[-1]
                            location = location.replace("{{port}}", target_port)
                        send_header["Location"] = location
