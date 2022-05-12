#!/usr/bin/env python3

import ldap3
import argparse
import cmd, sys
from code.src.connectionhelpers import SUPPORTED_SASL_AUTH_METHODS,try_connect,get_connection,get_server_supported_sasl_authentication_methods,try_get_authenticated_connection,get_authenticated_connection
from code.src.ldapenumshell import LDAPEnumShell
from code.src.queryformatter import format_ldap_domain_components
from code.src.consts import SSL_PORTS

# TODO:
# 3. Cleanup for github
#   - Should we add a minimal option? (-m)
#		* Could just be a small list of the one most important value (e.g. for users, just principalname)
#       * also want consistency between output format of -v and default 
#   - Improve unit tests
#     * Accidentally broke naming context formatting in do_search, need some tests around that (or extract to formatters and test)
#   - spellcheck lol? 

# Built in GetComputers query

# *** Built in Wildcard search for email type fields (this is really more of an attributes wildcard search I guess)? 
# - Not wildcard I think, but how about these Contact types: https://adsecurity.org/?p=2535#:~:text=Identify%20Partner%20Organizations
# - as well as just principalname

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

	LDAPEnumShell(args.hostip, args.hostdomain, currentPort, args.username, args.password, connection_constructor).cmdloop()
else:
	print(f"FAILURE: Could not successfully connect to any ports")




