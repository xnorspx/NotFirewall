import subprocess
import requests
import os

"""
Config
"""
rule_url = "https://raw.githubusercontent.com/tszykl05/NotFirewall/main/config/vm.txt"
comment_keyword = "NotFirewall"

"""
Security check before running script
"""
self_stat = os.stat(__file__)
self_permission = oct(self_stat.st_mode)[-3:]
self_owner = self_stat.st_uid
ufw_status = subprocess.run(
    [
        "ufw",
        "status"
    ],
    capture_output=True
)
if self_permission != "644":
    print("File permission is not set to 644. Leaving.")
    exit(1)
elif self_owner != 0:
    print("File is not own by root. Leaving.")
    exit(1)
elif "inactive" in ufw_status.stdout.decode("utf-8"):
    print("UFW disabled. Leaving.")
    exit(1)

"""
Grab rule
"""
rule_txt = requests.get(rule_url, timeout=(5, 15), allow_redirects=True).text

"""
Parse rule
"""
rule_list_raw = rule_txt.split("\n")
rule_list = []
for item in rule_list_raw:
    if (":" in item) and (item[0] != "#"):
        item = item.replace(":", "|", 1)
        item = item.split("|")
        if "-" in item[0]:  # Protocol-Port
            proto, port = item.pop(0).split("-")
            network_list = [x.strip() for x in item]
            for network in network_list:
                rule_list.append(
                    (proto.lower(), port, network)
                )
        elif item[0] == "Interface":  # Interface
            rule_list.append(
                ("Interface", item[1].strip())
            )
print(rule_list)

"""
Fetch current UFW rules
"""
current_ufw_rules = []
ufw_status_output = ufw_status.stdout.decode("utf-8").split("\n")
controlled_rules = [x.replace("ALLOW", "#") for x in ufw_status_output if comment_keyword in x]
for rule in controlled_rules:
    rule = rule.split("#")
    target = rule[0].strip().replace(" (v6)", "")
    source = rule[1].strip()
    # Change expression
    if source == "Anywhere":
        source = "0.0.0.0/0"
    elif source == "Anywhere (v6)":
        source = "::/0"
    # Add to current rule list for matching
    if "Anywhere on" in target:
        # Interface rule
        interface = target.replace("Anywhere (v6) on ", "").replace("Anywhere on ", "")
        # Add rules
        current_ufw_rules.append(
            ("Interface", interface)
        )
    else:
        # Port rule
        port, proto = target.split("/")
        # Add rules
        current_ufw_rules.append(
            (proto, port, source)
        )

"""
Remove redundant
"""
existing_rules = list(dict.fromkeys(current_ufw_rules))
new_rules = list(dict.fromkeys(rule_list))
pending_delete_rules = []
while existing_rules:
    rule = existing_rules.pop(0)
    if rule in new_rules:
        new_rules.remove(rule)
    else:
        pending_delete_rules.append(rule)

"""
Delete rules
"""
for deleted_item in pending_delete_rules:
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
                comment_keyword
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
                comment_keyword
            ],
            capture_output=True
        )

"""
Add new rules
"""
for new_item in new_rules:
    if new_item[0] == "Interface":
        subprocess.run(
            [
                "ufw",
                "allow",
                "in",
                "on",
                new_item[1],
                "comment",
                comment_keyword
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
                comment_keyword
            ],
            capture_output=True
        )
