# dapper
LDAP Enumeration Tool

Created as a learning exercise and for use in the OSCP exam.

Specifically intended to automate some common pre-auth enumeration queries that would be tedious to perform manually, and to help process the output of those queries.

My intention is to keep this tool light weight and compartmentalized.  This should allow newcomers to modify the tool to suit their particular needs and read the code to learn some basic ldap concepts.

In that spirit: I'm still learning LDAP and active directory concepts myself, so if you see issues with my code or terminology please let me know!

Client built for and tested on Kali Linux.

Thanks to everyone who created Impacket, I borrowed heavily from that when writing this

## Installation ##
- Run `pip install -r requirements.txt`
  * To use the kerberos ST/TGS functionality on linux, install MIT KRB5 abd  
    - sudo apt install libkrb5-dev
    - pip install gssapi (used version 1.8.3)
    - see https://stackoverflow.com/questions/30896343/how-to-install-gssapi-python-module for more context 

## Usage ##
- Run `./ldap-enumerator.py -h` to see all parameters
- Example usage (shell):
    * `ldap-enumerator.py -ldaphost 127.0.0.1 -hostdomain example.com -username auser@example.com -password mypass1`
    * `ldap-enumerator.py -ldaphost 127.0.0.1`
    * see examples/connect.sh
- Example usage (single command):
    * `python ldap-enumerator.py -ldaphost 1.2.3.4 -username 'WINDOMAIN\vagrant' -password vagrant -command "enum_spns" -commandargs "-user --outfile tesout2.test"`
    * see examples/single.sh
- Example usage (authenticating with pre-existing TGS, e.g. from impacket Get-ST):
    * `KRB5CCNAME=./admin-ldap-tgs.ccache python ldap-enumerator.py -debug True -ldaphost dc.windomain.local -port 636 -usetgs True -hostdomain WINDOMAIN.LOCAL`

## Authentication behavior ##
- Default behavior is to authenticate via ntlm w/ provided -username and -password
- If no -password is provided but -ntlmhash parameter is, will try to authenticate via ntlm with the hash
- If no -password is provided but the KRB5CCNAME env var points to a valid ccache file and -usetgs is provided, will try to authenticate using kerberos auth
  * Note: if the CCache provided contains a service ticket (ST/TGS) and kerberos based auth fails, dapper will create a copy w/ the spn changed to the appropriate one for this service and set the KRB5CCNAME to that, so that we can use a captured TGS for another service run under the same service account.  For an explanation of why this works, see: https://www.secureauth.com/blog/kerberos-delegation-spns-and-more/
- If none fo the above work, will attempt an anonymous bind
  * This behavior can be disabled by passing -tryanonymous=False

- TODO: Anon broken? see https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/anonymous-ldap-operations-active-directory-disabled
 * seems unrealistic, had to do ^ + https://activedirectoryfaq.com/2016/09/anonymous-access/ (add anonymous logon read rule for particular OUs)
- ***TODO: ntlm relay scenario, anon connection to server through the proxy? 

## Testing ##
- `./runtests.sh` will run existing tests.  

## Disclaimers: ## 
- This tool is intended for legitimate educational purposes only.
- This tool is licensed under the Apache License, version 2.0 (see LICENSE).
- This tool has the potential to cause a variety of adverse effects to the system it's run against, including (but not limited to) account lockouts, excessive network traffic, and blocked network traffic (owing to firewalls, security software, etc).  As such it's intended for test environments only.
- This tool has currently only been built and tested for single domain AD based LDAP configurations.

