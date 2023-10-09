import os
import requests
import subprocess

"""
Config
"""
rule_url = ""

"""
Security check before running script
"""
self_stat = os.stat(__file__)
self_permission = oct(self_stat.st_mode)[-3:]
self_owner = self_stat.st_uid
if self_permission != "644":
    print("File permission is not set to 644. Leaving.")
    exit(1)
elif self_owner != 0:
    print("File is not own by root. Leaving.")
    exit(1)

"""
Grab rule
"""
rule_txt = requests.get(rule_url, timeout=(5, 15), allow_redirects=True).content
print(rule_txt)
