#!/usr/bin/env python3

import ldap3
import argparse
import cmd, sys
from code.src.connectionhelpers import SUPPORTED_SASL_AUTH_METHODS,try_connect,get_connection,get_server_supported_sasl_authentication_methods,try_get_authenticated_connection,get_authenticated_connection
from code.src.ldapenumshell import LDAPEnumShell
from code.src.queryformatter import format_ldap_domain_components
from code.src.consts import SSL_PORTS
from code.src.logger import FileMuxLogger

parser = argparse.ArgumentParser(description='Pseudo shell to enumerate ldap')
parser.add_argument('-hostip', type=str, required=True)
parser.add_argument('-hostdomain', type=str)
parser.add_argument('-password', type=str)
parser.add_argument('-username', type=str)
parser.add_argument('-command', type=str, required=False, help="run single ldap-enumerator command as opposed to starting an interactive pseudo-shell (for ease of use w/ other command line utilities)")
parser.add_argument('-commandargs', type=str, required=False, help="run single ldap-enumerator command as opposed to starting an interactive pseudo-shell (for ease of use w/ other command line utilities)")
parser.add_argument('-debug', type=bool, required=False, default=False, help="Print additional debugging information (about auth, connection, args provided, etc)")
args = parser.parse_args()

# optional debugging logging
# eventually, should use (or write) a real logging lib that supports muxing (file+stdout) + 
# logging levels and di into all these different modules, but don't want to distract from
# OSCP prep working on the code
logger = FileMuxLogger(args.debug)

successfulPorts=[]
# Trying anonymous connection
if try_connect(args.hostip,389,logger):
	successfulPorts.append(389)
if try_connect(args.hostip,636,logger):
	successfulPorts.append(636)
if try_connect(args.hostip,3268,logger):
	successfulPorts.append(3268)
if try_connect(args.hostip,3269,logger):
	successfulPorts.append(3269)

def try_authenticate(hostip,realm,port,username,password,server_supported_sasl_authentication_methods):
	if (not username or username is None) or (not password or password is None):
		return (False,None)

	# Try simple authentication first
	if try_get_authenticated_connection(hostip,realm,port,username,password,"SIMPLE",logger):
		logger.print_debug(f"Authenticated connection - SUCCESS: SIMPLE")
		return (True,"SIMPLE")
	logger.print_debug("Could not bind with authentication method SIMPLE, proceeding...")

	# Try SASL methods next 
	# Treat None in server auth methods as any, since it could mean server isn't configured to return these values (for anonymous)
	viable_sasl_auth_methods = SUPPORTED_SASL_AUTH_METHODS if server_supported_sasl_authentication_methods == None else set(SUPPORTED_SASL_AUTH_METHODS).intersection(server_supported_sasl_authentication_methods) 
	if len(viable_sasl_auth_methods) == 0: 
		logger.print_debug(f"Authenticated connection - FAILURE: simple authentication failed, tool does not support {viable_sasl_auth_methods}")

	# If initial auth failed, could be because simple is unsupported, or because creds are invalid.  
	# Prompt user about trying other to avoid lockouts
	for auth_method in viable_sasl_auth_methods:
		val = input(f"Try with authentication method {auth_method}? (Y/N)")
		if val.lower() == "y":
			success=try_get_authenticated_connection(hostip,realm,port,username,password,auth_method,logger)
			if success:
				logger.print_debug(f"Authenticated connection - SUCCESS: {auth_method}")
				return (True,auth_method)
			else:
				logger.print_debug(f"Could not bind with authentication method {auth_method}, proceeding...")

	logger.print_debug(f"Authenticated connection - FAILURE: all mutually supported SASL authentication methods failed")
	return (False,None)

if len(successfulPorts) > 0:
	currentPort=successfulPorts[0]
	logger.print_debug(f"Anonymous connection - SUCCESS: {len(successfulPorts)} working ports found, using {currentPort}")

	server_supports=get_server_supported_sasl_authentication_methods(args.hostip,currentPort,logger)

	res=try_authenticate(args.hostip, args.hostdomain, currentPort, args.username, args.password, server_supports)
	if res[0] == True:
		logger.print_debug(f"Authenticated connection - SUCCESS: {args.username}:{args.password} at {args.hostip}:{currentPort}")
		connection_constructor = lambda ip,host,port,user,password:  get_authenticated_connection(ip,host,port,user,password,res[1],logger)
	else:
		logger.print_debug(f"Authenticated connection - FAILURE: {args.username}:{args.password} at {args.hostip}:{currentPort}")
		connection_constructor = lambda ip,host,port,user,password: get_connection(ip,port)

	if args.command:
		logger.print_debug(f"Running command {args.command} {args.commandargs}")
		# Note: cleaner approach would probably be 2 separate shell & individual command runner classes w/ mediator in b/w them and abstracted command handlers
		# this should work as a v1 though
		runner = LDAPEnumShell(args.hostip, args.hostdomain, currentPort, args.username, args.password, connection_constructor, logger)
		runner.onecmd(f"{args.command}{args.commandargs}")
	else:
		logger.print_debug("Starting pseudo-shell...")
		LDAPEnumShell(args.hostip, args.hostdomain, currentPort, args.username, args.password, connection_constructor, logger).cmdloop()
else:
	logger.print_debug(f"FAILURE: Could not successfully connect to any ports")




