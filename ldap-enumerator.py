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
parser.add_argument('-ldaphost', type=str, required=True, help="hostname or ip of the ldap service to run against")
parser.add_argument('-hostdomain', type=str, help="The FQDN of the AD domain (for use w/ kerberos based auth)")
parser.add_argument('-port', type=int, required=False, help="Port to use.  If not specified, will try to connect to all main ldap and ldaps ports")
parser.add_argument('-password', type=str)
parser.add_argument('-username', type=str)
parser.add_argument('-command', type=str, required=False, help="run single ldap-enumerator command as opposed to starting an interactive pseudo-shell (for ease of use w/ other command line utilities)")
parser.add_argument('-commandargs', type=str, required=False, help="run single ldap-enumerator command as opposed to starting an interactive pseudo-shell (for ease of use w/ other command line utilities)")
parser.add_argument('-debug', type=bool, required=False, default=False, help="Print additional debugging information (about auth, connection, args provided, etc)")
parser.add_argument('-usetgs', type=bool, required=False, default=False, help="Use the Service Ticket / TGS specified in the KRB5CCNAME env var to authenticate.  NOTE: if TGS is for an SPN other than the ldap service being authenticated to, will create and use a copy of the ccache w/ the spns set to the target ldap. sets the KRB5CCNAME env var as well")
parser.add_argument('-ntlmhash', type=str, required=False, help="The ntlm hash to use in lieu of a password")
parser.add_argument('-tryanonymous', type=bool, required=False, default=True, help="If authentication isn't attempted or doesn't succeed, try anonymous bind")
args = parser.parse_args()

# optional debugging logging
# eventually, should use (or write) a real logging lib that supports muxing (file+stdout) + 
# logging levels and di into all these different modules, but don't want to distract from
# OSCP prep working on the code
logger = FileMuxLogger(args.debug)

def try_authenticate(ldaphost,realm,port,username,password,ntlmhash,usekerb):
	# attempt ntlm auth
	if (username and username is not None) and (password and password is not None):
		res = try_get_authenticated_connection(ldaphost,realm,port,username,password,"NTLM",logger)
		if res[0]:
			logger.print_debug(f"Authenticated connection - SUCCESS: NTLM")
			return (True,res[1])
		logger.print_debug("Could not bind with authentication method NTLM, proceeding...")

	if (username and username is not None) and (ntlmhash and ntlmhash is not None):
		res = try_get_authenticated_connection(ldaphost,realm,port,username,ntlmhash,"NTLM",logger)
		if res[0]:
			logger.print_debug(f"Authenticated connection - SUCCESS: NTLM (hash)")
			return (True,res[1])
		logger.print_debug("Could not bind with authentication method NTLM, proceeding...")	
	
	if usekerb:
		res = try_get_authenticated_connection(ldaphost,realm,port,username,None,"Kerberos",logger)
		if res[0]:
			logger.print_debug(f"Authenticated connection - SUCCESS: Kerberos")
			return (True,res[1])
		logger.print_debug("Could not bind with authentication method Kerberos, proceeding...")	

	logger.print_debug(f"Authenticated connection - FAILURE: all methods failed or not enough information provided to authenticate")
	return (False,None)

	# TODO: Are we doing LDAPS correctly?  proper tls code?

	# TODO: Support ntlm here: https://ldap3.readthedocs.io/en/latest/bind.html#ntlm

def try_port(port):
	res = try_authenticate(args.ldaphost, args.hostdomain, port, args.username, args.password, args.ntlmhash, args.usetgs)
	if res[0]:
		logger.print_debug(f"Successful authenticated connection to {port}, returning")
		return (True, res[1])
	# Trying anonymous bind
	if args.tryanonymous:
		res = try_connect(args.ldaphost,port,logger)
		if res[0]:
			logger.print_debug(f"Successful unauthenticated connection to {port}, returning")
			return (True, res[1])
	logger.print_debug(f"Unsuccessful connecting to {port}, returning")
	return (False, None)

ports = []
if args.port is None:
	ports = [389,636,3268,3269]
else:
	ports = [args.port]

lastConnection = (False,None)
for port in ports:
	lastConnection = try_port(port)
	if lastConnection[0]:
		logger.print_debug(f"Connection - SUCCESS: {port}")
		break

if lastConnection[0]:
	if args.command:
		logger.print_debug(f"Running command {args.command} {args.commandargs}")
		# Note: cleaner approach would probably be 2 separate shell & individual command runner classes w/ mediator in b/w them and abstracted command handlers
		# this should work as a v1 though
		runner = LDAPEnumShell(args.hostdomain, lastConnection[1], logger)
		runner.onecmd(f"{args.command}{args.commandargs}")
		lastConnection[1].unbind()
	else:
		logger.print_debug("Starting pseudo-shell...")
		LDAPEnumShell(args.hostdomain, lastConnection[1], logger).cmdloop()
else:
	logger.print_debug(f"FAILURE: Could not successfully connect to any ports")




