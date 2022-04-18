#!/usr/bin/env python3

import ldap3
import argparse
import cmd, sys
from src.ldapenumshell import LDAPEnumShell


# TODO:
# 1. Figure out Server's get_info=ALL https://ldap3.readthedocs.io/en/latest/unbind.html
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
# 3. Cleanup for github
#   - Add unit tests ***
#   - Add readme?  Probably just pip installs / requirements, running tests, and how to get help prompt.  Might need legal disclaimer about legimate use? 
#     * Should also have disclaimer that it's a student project, untested for inter-domain scenarios AND be aware of lockout implications, logging, etc
#   - spellcheck lol? 
#   - fun name?
#     * Could try to keep with literary names
#     * Dap (like the fist bump, w/ ascii art) could be fun though

# Handle different ports?
#   - Before dropping into shell list working ports, offer ability to switch between (might want to query
#   both global catologue and main domain ldap?  Think we should default to main since global has subset)
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
# TODO: Consider stealthiness of the tool, are there things built into LDAP that will knock us or raise alarms if we try this stuff too much? 

# TODO: Is it possible we'll get other LDAP versions we need to try querying with?  (seemsl ike we default to 3)
#  - server info might have this it seems

parser = argparse.ArgumentParser(description='Pseudo shell to enumerate ldap')
parser.add_argument('-hostip', type=str, required=True)
parser.add_argument('-hostdomain', type=str)
parser.add_argument('-password', type=str)
parser.add_argument('-username', type=str)
args = parser.parse_args()

SSL_PORTS=[3269, 636]

class LDAPEnumShell(cmd.Cmd):
	intro = '\n\n\nLDAP Enumerator Shell\n\nFor LDAP Enumeration.  ? or help for more info\n\n\n'
	prompt = '> '

	def __init__(self, hostip, hostdomain, port, username, password):
		self.hostip = hostip
		self.hostdomain = hostdomain
		self.port = port
		self.username = username
		self.password = password
		print(f"trying {self.hostip}:{self.port}")
		self.connection = get_connection(hostip, username, password, port)
		super().__init__()

	def onecmd(self, line):
		try:
			return super().onecmd(line)
		except ldap3.core.exceptions.LDAPSocketOpenError as e:
			print(f"FAILURE: LDAPSocketOpenError {e.args} thrown attempting to query users, if \"invalid server address\" and base connection works, then domain name (or formatted domain components query string) is likely invalid")
			if not self.connection.closed:	
				self.connection.unbind()
			quit()
		except BaseException as e:
			print(f"FAILURE: encountered {e}")
			if not self.connection.closed:	
				self.connection.unbind()
			quit()


	def do_enum_users(self, arg):
		#print(f"Executing command: {arg}")
		domaincomponents=FormatLDAPDomainComponents(self.hostdomain)

		self.connection.search(search_base=domaincomponents,
			search_filter='(&(objectClass=user)(objectClass=person))',
			search_scope='SUBTREE',
			attributes='*')

		print(self.connection.entries)
		# TODO: Clear entries after query?  

	def do_quit(self, args):
		print("Exiting...")
		if not connection.closed:	
			connection.unbind()
		quit()


	def default(self, arg):
		print(f"Executing search with query: {arg}")
		#ErlRce.EXECUTE_REMOTE_COMMAND(arg, self.cookie, self.port, self.host)

successfulPorts=[]
if try_enumerate_server_info(389):
	successfulPorts.append(389)
if try_enumerate_server_info(636):
	successfulPorts.append(389)
if try_enumerate_server_info(3268):
	successfulPorts.append(3268)
if try_enumerate_server_info(3269):
	successfulPorts.append(3269)

if len(successfulPorts) > 0:
	currentPort=successfulPorts[0]
	print(f"SUCCESS: {len(successfulPorts)} working ports found, using {currentPort}")

	# TODO: Try various auth methods, see if we can get above anonymous user: https://ldap3.readthedocs.io/en/latest/tutorial_intro.html#logging-into-the-server


	LDAPEnumShell(args.hostip, args.hostdomain, currentPort, args.username, args.password, lambda ip,host,port,user,password: get_connection(ip,user,password,port)).cmdloop()
else:
	print(f"FAILURE: Could not successfully connect to any ports")




