# Netwatcher
Python script for automatic replacement of a non-working VPN server and renewal of provider's subscription in passwall2

# Description and structure

## Project files:
- /usr/share/my/netwatcher.py — This script. (Must be created before launching)
- /etc/netwatcher/data.py — Configuration and secrets. (Must be created before launching)
- /var/log/netwatcher/state.json — The state between launches. (It's created automatically if it's missing)
- /var/log/netwatcher/netwatcher.log — Log. (It's created automatically if it's missing)

## The script performs the following steps:

1. Checks the network availability of Internet resources that are accessible via VPN (listed in the CHECK_URLS list in data.py ). If the check is successful, the script ends in state.A json entry is entered marked "result": "ok".
2. In case of an unsuccessful availability check (more than one error), the current server changes to _direct (direct traffic).
3. After that, all subscription links are updated.
4. Next, the server with the best performance in tcping and http get verification is selected (the blacklist and previous non-working nodes are taken into account)
5. After that, the server is installed back to the shut node.

# Installation

Make sure that you have the necessary utilities installed to run the script!
[tcping, curl, uci, lua, python3]

To run the script automatically on a schedule, use cron:

__*/2 * * * * flock -n /tmp/netwatcher.lock /usr/bin/python3.13 /usr/share/netwatcher/netwatcher.py >> /dev/null 2>&1__

(running every two minutes using flock to avoid parallel startup)
