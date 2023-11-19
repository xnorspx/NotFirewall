import subprocess
import requests
import os

"""
Config
"""
ufw_rule_url = "https://raw.githubusercontent.com/tszykl05/NotFirewall/main/config/vm.txt"
ufw_rule_comment_keyword = "NotFirewall"

"""
Security checks
"""
script_stat = os.stat(__file__)
script_permission = oct(script_stat.st_mode)[-3:]
script_owner = script_stat.st_uid
if script_permission != "644":
    print("Script permission is not set to 644. Leaving.")
    exit(1)
elif script_owner != 0:
    print("Script is not own by root. Leaving.")
    exit(1)

"""
Parse rule
"""
ufw_rules_raw = requests.get(ufw_rule_url, timeout=(5, 15), allow_redirects=True).text

"""
Parse rule
"""
ufw_rule = []
ufw_rule_lines = ufw_rules_raw.split("\n")
for item in ufw_rule_lines:
    if len(item) == 0:
        pass
    elif (item[0] != "#") and (":" in item):
        # Change ":" that may exist in IPv6 addresses into "|"
        item = item.replace(":", "|", 1)
        item = item.split("|")
        if "-" in item[0]:
            # Protocol-Port part
            proto, port = item.pop(0).split("-")
            network_list = [x.strip() for x in item[0].split(',')]
            # Add rules into list
            for network in network_list:
                ufw_rule.append(
                    (proto.lower(), port, network)  # Lower case the protocol to match ufw status expression
                )
        elif item[0] == "Interface":
            # Interface
            ufw_rule.append(
                ("Interface", item[1].strip())
            )
# Log
print("Applying following rules")
for i in ufw_rule:
    print(i)

"""
Fetch current UFW rules
"""
ufw_status = []
# Get ufw status
ufw_status_raw = subprocess.run(["ufw", "status"], capture_output=True).stdout.decode("utf-8")
ufw_status_raw = ufw_status_raw.split("\n")
# Filter the related rules
ufw_status_raw = [x for x in ufw_status_raw if ufw_rule_comment_keyword in x]
ufw_status_raw = [x.replace("ALLOW", "#") for x in ufw_status_raw]
for item in ufw_status_raw:
    item = item.split("#")
    # Rule details
    target = item[0].strip().replace(" (v6)", "")  # Ignore the IPv6 tag
    source = item[1].strip()
    # Change expression
    if source == "Anywhere":
        source = "0.0.0.0/0"
    elif source == "Anywhere (v6)":
        source = "::/0"
    # Parse rules
    if "Anywhere on" in target:  # Indicate as Interface rules
        interface = target.replace("Anywhere on ", "")
        # Add rules
        ufw_status.append(
            ("Interface", interface)
        )
    else:
        port, proto = target.split("/")
        # Add rules
        ufw_status.append(
            (proto, port, source)
        )

"""
Remove redundant
"""
old = list(dict.fromkeys(ufw_status))
new = list(dict.fromkeys(ufw_rule))
for i in range(len(old)):
    item = old.pop(0)
    if item in new:
        new.remove(item)
    else:
        old.append(item)

"""
Delete old rules
"""
for deleted_item in old:
    if deleted_item[0] == "Interface":
        subprocess.run(
            [
                "ufw",
                "delete",
                "allow",
                "in",
                "on",
                deleted_item[1],
                "comment",
                ufw_rule_comment_keyword
            ],
            capture_output=True
        )
    else:
        subprocess.run(
            [
                "ufw",
                "delete",
                "allow",
                "proto",
                deleted_item[0],
                "from",
                deleted_item[2],
                "to",
                "any",
                "port",
                deleted_item[1],
                "comment",
                ufw_rule_comment_keyword
            ],
            capture_output=True
        )

"""
Add new rules
"""
for new_item in new:
    if new_item[0] == "Interface":
        subprocess.run(
            [
                "ufw",
                "allow",
                "in",
                "on",
                new_item[1],
                "comment",
                ufw_rule_comment_keyword
            ],
            capture_output=True
        )
    else:
        subprocess.run(
            [
                "ufw",
                "allow",
                "proto",
                new_item[0],
                "from",
                new_item[2],
                "to",
                "any",
                "port",
                new_item[1],
                "comment",
                ufw_rule_comment_keyword
            ],
            capture_output=True
        )
