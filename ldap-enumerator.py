#!/usr/bin/env python3

import ldap3
import argparse
import cmd, sys
from code.src.connectionhelpers import try_connect,get_connection,get_server_supported_sasl_authentication_methods
from code.src.ldapenumshell import LDAPEnumShell
from code.src.queryformatter import format_ldap_domain_components
from code.src.consts import SSL_PORTS

# Domain name - Dependencies:
# - dn > enum_*
# - dn > auth
# basically because anonymous might fail and we need it for auth, do want to allow users to pass it in.  but, we also want to
# make sure that by the time we get to enum if they don't have it they can still enumerate.  So in ***init*** we should pull the 
# rootDomainNamingContext and compare with domainname.  If latter is null or empty, just use it (formatted to domain name).  
# if they both exist and are different though, should prompt them to replace with valid one

# TODO:
# 1. Figure out Server's get_info=ALL https://ldap3.readthedocs.io/en/latest/unbind.html
#   - That field is what MUST be read: https://ldap3.readthedocs.io/en/latest/server.html
#     * But it doesn't seem to bea field1 & field2 & ..., because default is just schema (returns nothing) and all is schema+server info (does return info)
#   - Works really well in Hutch, even tho it's an anon session.  Gives us:
#     * Root naming context
#     * All naming contexts
#     * Supported ldap version
#     * ldapServiceName: (?)
#     * dnsHostName: hutchdc.hutch.offsec 
#   - Need to figure out if there are drawbacks to using ^, diffs between authd vs unauthed, how to make use of different contexts, etc
# 2. Auth
#   - https://ldap3.readthedocs.io/en/latest/tutorial_intro.html#logging-into-the-server
#   - See lines near bottom, seems like logical place for it (specifically conn.extend.standard.who_am_i())
#   - 
# 3. Cleanup for github
#   - Add unit tests ***
#   - Add readme?  Probably just pip installs / requirements, running tests, and how to get help prompt.  Might need legal disclaimer about legimate use? 
#     * Should also have disclaimer that it's a student project, untested for inter-domain scenarios AND be aware of lockout implications, logging, etc
#   - spellcheck lol? 
#   - fun name?
#     * Could try to keep with literary names
#     * Dap (like the fist bump, w/ ascii art) could be fun though
#     * maybe a le carre character, pre authenticated (untrusted) querier/interviewer?  smiley? 

# Handle different ports?
#   - Before dropping into shell list working ports, offer ability to switch between (might want to query
#   both global catologue and main domain ldap?  Think we should default to main since global has subset)

# Search tasks: 
# TODO: If we can get server info, shouldn't we be setting this to this:
#   server.info.rootDomainNamingContext or server.info.defaultNamingContext
#   We need to at least understand the difference I think
# TODO: auto_range
#   Seems important for the data sets we're interested in (i.e. biggish AD data sets where it's difficult to parse manually)


# Built in GetUsers query (&(objectClass=user)(objectClass=person))
#  - with ad username format, emails, description fields, etc
# Built in GetComputers query
# Built in GetGroups query
#   - e.g. CN=Users,DC=hutch,DC=offsec where objectClass=organizationalPerson
# Outfiles option for all these?
#   - Seems like we could build into OneCmd, look for that flag, and if so redirect output somehow (have each exec return a string?  pass in file descriptor for stdout or file name?)
# Built in GetPasswordPolicy query
# Default to custom query
# TODO: Better error handling / housekeeping
#   - calling unbind should disconnect everything
#   - should do this if any exception thrown in shell
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

# TODO: anonymous connection could've been turned off for all but user would still work.  In that case, should we prompt them
# before trying with creds on all ports? 

SUPPORTED_SASL_AUTH_METHODS = ["DIGEST-MD5","whateverntlmis"]

def get_authenticated_connection(hostip,realm,port,username,password,authentication_method):
	if authentication_method == "SIMPLE":
		s = ldap3.Server(hostip, port=port,get_info=ldap3.ALL)
		c = ldap3.Connection(s, user=username, password=password)
		c.bind()
		return c
	elif authentication_method ==  "DIGEST-MD5":
		realm = args.hostdomain if args.hostdomain else None # None leads to use of server default realm 
		# sounds like whatever user is probably fine
		raise Exception("Not yet implemented (TODO)")
	elif authentication_method == "whateverntlmis":
		username="a" # TODO: Should we try to do this smart (i.e. mydomain.local,userA => mydomain\userA) or just trust users on format?  
		# probably fine to just trust them, this should primarily be for unauth'd, after all.  maybe print warning if format isn't that of an AD user
		raise Exception("Not yet implemented (TODO)")
	else:
		raise Exception(f"Unknown or unsupported authentication method {authentication_method}")	

def try_get_authenticated_connection(hostip,realm,port,username,password,authentication_method):
	try:
		conn = get_authenticated_connection(hostip,realm,port,username,password,authentication_method)
		print(f"{authentication_method}: {username} - {conn.extend.standard.who_am_i()}")
		# TODO: Probably a more sophisticated way to check, but potentially difficult (e.g. encountered username user@dom.ain => whoami dom\user)
		# and doesn't seem that important to check.  Potential risk if a server ever returns "Anonymous" or similar, but seems unlikely
		connsucceeded = conn.bound and conn.extend.standard.who_am_i()
	except ldap3.core.exceptions.LDAPSocketOpenError:
		connsucceeded=False
	
	print(f"{port}: " + ("Connected successfully" if connsucceeded else "Failed to connect"))

	if not conn.closed:	
		conn.unbind()
	return connsucceeded

	# TODO: LDAPS ports

def try_authenticate(hostip,realm,port,username,password,server_supported_sasl_authentication_methods):
	if not (username or password):
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




