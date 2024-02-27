# dapper
LDAP Enumeration Tool

Created as a learning exercise and for use in the OSCP exam.

Specifically intended to automate some common pre-auth enumeration queries that would be tedious to perform manually, and to help process the output of those queries.

My intention is to keep this tool light weight and compartmentalized.  This should allow newcomers to modify the tool to suit their particular needs and read the code to learn some basic ldap concepts.

In that spirit: I'm still learning LDAP and active directory concepts myself, so if you see issues with my code or terminology please let me know!

Client built for and tested on Kali Linux.

## Installation ##
- Run `pip install -r requirements.txt`

## Usage ##
- Run `./ldap-enumerator.py -h` to see all parameters
- Example usage (shell):
    * `ldap-enumerator.py -hostip 127.0.0.1 -hostdomain example.com -username auser@example.com -password mypass1`
    * `ldap-enumerator.py -hostip 127.0.0.1`
    * see examples/connect.sh
- Example usage (single command):
    * `python ldap-enumerator.py -hostip 1.2.3.4 -username 'WINDOMAIN\vagrant' -password vagrant -command "enum_spns" -commandargs "-user --outfile tesout2.test"`
    * see examples/single.sh

## Testing ##
- `./runtests.sh` will run existing tests.  
- Note that messages like "FAILURE: encountered the JSON object must be str, bytes or bytearray, not MagicMock.  Keeping connection alive" aren't (necessarily) indications of a failing test, just poorly written tests.  Look for the "OK" at the end of each test section

## Disclaimers: ## 
- This tool is intended for legitimate educational purposes only.
- This tool is licensed under the Apache License, version 2.0 (see LICENSE).
- This tool has the potential to cause a variety of adverse effects to the system it's run against, including (but not limited to) account lockouts, excessive network traffic, and blocked network traffic (owing to firewalls, security software, etc).  As such it's intended for test environments only.
- This tool has currently only been built and tested for single domain AD based LDAP configurations.

