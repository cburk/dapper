#!/usr/bin/env python3

import ldap3
import argparse
import cmd, sys
from code.src.connectionhelpers import try_connect,get_connection,get_server_supported_sasl_authentication_methods,try_get_authenticated_connection,get_authenticated_connection
from code.src.ldapenumshell import LDAPEnumShell
from code.src.queryformatter import format_ldap_domain_components
from code.src.consts import SSL_PORTS

# TODO:
# 3. Cleanup for github
#   - Should we add a minimal option? (-m)
#		* Could just be a small list of the one most important value (e.g. for users, just principalname)
#       * also want consistency between output format of -v and default 
#   - Improve unit tests
#   - Add readme?  Probably just pip installs / requirements, running tests, and how to get help prompt.  Might need legal disclaimer about legimate use? 
#     * Should also have disclaimer that it's a student project, untested for inter-domain scenarios AND be aware of lockout implications, logging, etc
#   - spellcheck lol? 

# Built in GetComputers query

# *** Built in GetPasswordPolicy query
# 	- is this actually a thing in ldap? 
#   - this might be fairly reliably there in ad: search -filter (&(objectClass=domainDNS)(objectClass=domain)) / https://docs.microsoft.com/en-us/windows/win32/adschema/c-domaindns
#   - but are the results legit?  says max 0 wrong guesses before lockout, can test but that seems innaccurate 
#   - ms-DS-Password-Settings also seems good for win server < 2012
# Built in Wildcard search for email type fields (this is really more of an attributes wildcard search I guess)? 

# *** Expand group or user func to describe relationship? ***
# 	- I think it'll be clarifying the group id on users

# Default to custom query
# TODO: Connection via domain name vs ip?  Could make a difference? 
# TODO: Multidomain scenarios we should consider? 
#  - Like if user passes in hutch.pg, do we want to sometimes search DC=hutch, or just DC=hutch,DC=pg?
#  - best way to handle might just be experiment and let users change domain (/ DCs) with method
#  - answer from reading seems to be that the realm (DC domain) determines 
# TODO: Consider stealthiness of the tool, are there things built into LDAP that will knock us or raise alarms if we try this stuff too much? 
# TODO: Consider checking for unauthenticated simple bind? https://ldap3.readthedocs.io/en/latest/bind.html#the-bind-operation
#  - Could be very useful potentially

# TODO: Is it possible we'll get other LDAP versions we need to try querying with?  (seemsl ike we default to 3)
#  - server info might have this it seems
#  - but is it going to impact us?  seems low priority (for now) since package seems to be able to handle it

parser = argparse.ArgumentParser(description='Pseudo shell to enumerate ldap')
parser.add_argument('-hostip', type=str, required=True)
parser.add_argument('-hostdomain', type=str)
parser.add_argument('-password', type=str)
parser.add_argument('-username', type=str)
args = parser.parse_args()

successfulPorts=[]
# Trying anonymous connection
if try_connect(args.hostip,389):
	successfulPorts.append(389)
if try_connect(args.hostip,636):
	successfulPorts.append(389)
if try_connect(args.hostip,3268):
	successfulPorts.append(3268)
if try_connect(args.hostip,3269):
	successfulPorts.append(3269)

def try_authenticate(hostip,realm,port,username,password,server_supported_sasl_authentication_methods):
	if (not username or username is None) or (not password or password is None):
		return (False,None)

	# Try simple authentication first
	if try_get_authenticated_connection(hostip,realm,port,username,password,"SIMPLE"):
		print(f"Authenticated connection - SUCCESS: SIMPLE")
		return (True,"SIMPLE")
	print("Could not bind with authentication method SIMPLE, proceeding...")

	# Try SASL methods next 
	# Treat None in server auth methods as any, since it could mean server isn't configured to return these values (for anonymous)
	viable_sasl_auth_methods = SUPPORTED_SASL_AUTH_METHODS if server_supported_sasl_authentication_methods == None else set(SUPPORTED_SASL_AUTH_METHODS).intersection(server_supported_sasl_authentication_methods) 
	if len(viable_sasl_auth_methods) == 0: 
		print(f"Authenticated connection - FAILURE: simple authentication failed, tool does not support {viable_sasl_auth_methods}")

	# If initial auth failed, could be because simple is unsupported, or because creds are invalid.  
	# Prompt user about trying other to avoid lockouts
	for auth_method in viable_sasl_auth_methods:
		val = input(f"Try with authentication method {auth_method}? (Y/N)")
		if val.lower() == "y":
			success=try_get_authenticated_connection(hostip,realm,port,username,password,auth_method)
			if success:
				print(f"Authenticated connection - SUCCESS: {auth_method}")
				return (True,auth_method)
			else:
				print(f"Could not bind with authentication method {auth_method}, proceeding...")

	print(f"Authenticated connection - FAILURE: all mutually supported SASL authentication methods failed")
	return (False,None)

if len(successfulPorts) > 0:
	currentPort=successfulPorts[0]
	print(f"Anonymous connection - SUCCESS: {len(successfulPorts)} working ports found, using {currentPort}")

	server_supports=get_server_supported_sasl_authentication_methods(args.hostip,currentPort)

	res=try_authenticate(args.hostip, args.hostdomain, currentPort, args.username, args.password, server_supports)
	if res[0] == True:
		print(f"Authenticated connection - SUCCESS: {args.username}:{args.password} at {args.hostip}:{currentPort}")
		connection_constructor = lambda ip,host,port,user,password:  get_authenticated_connection(ip,host,port,user,password,res[1])
	else:
		print(f"Authenticated connection - FAILURE: {args.username}:{args.password} at {args.hostip}:{currentPort}")
		connection_constructor = lambda ip,host,port,user,password: get_connection(ip,port)

	# TODO: Try various auth methods, see if we can get above anonymous user: https://ldap3.readthedocs.io/en/latest/tutorial_intro.html#logging-into-the-server
	# First, try to get supported auth mechanisms.  If we can't, shouldn't default to ntlm (only supported on AD)
		# TODO: Which default auth method instead?
		# - we shouldn't do SASL: External, we're not generating PEM files
		# - Should be md5, using signing + (default realm ) 
		# Fall back to simple bind? 
	# Third, should we make trying a different auth method something we prompt about?  Want to be allow users to avoid lockouts

	# Misc: is there a way we should differentiate between LDAP realm and domains we've discovered?  Is it part of server info? 
	# Answer from https://superuser.com/questions/1378721/what-is-the-difference-between-a-domain-and-a-realm seems to be that
	# the ad domain and the realm are basically the same thing, we can use these terms interchangeably here it seems (and
	# be confident in the results of authenticating to just the main DC domain)

	# Misc: want to understand difference between bind and other connections.  Might have auth implications

	# *** TODO: Move server info enum into shell.  Should make file redirect easier, and (afaik) it's not actually gonna help us authenticate or get an anon connection
	LDAPEnumShell(args.hostip, args.hostdomain, currentPort, args.username, args.password, connection_constructor).cmdloop()
else:
	print(f"FAILURE: Could not successfully connect to any ports")




