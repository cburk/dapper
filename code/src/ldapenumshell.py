#!/usr/bin/env python3
import ldap3
import cmd, sys
from code.src.connectionhelpers import try_connect,get_connection
from code.src.queryformatter import format_ldap_domain_components

class LDAPEnumShell(cmd.Cmd):
	intro = '\n\n\nLDAP Enumerator Shell\n\nFor LDAP Enumeration.  ? or help for more info\n\n\n'
	prompt = '> '

	def __init__(self, hostip, hostdomain, port, username, password, create_connection):
		self.hostip = hostip
		self.hostdomain = hostdomain
		self.port = port
		self.username = username
		self.password = password
		print(f"trying {self.hostip}:{self.port}")
		self.connection = create_connection(hostip,hostdomain,port,username,password)
		super().__init__()

	def onecmd(self, line):
		try:
			return super().onecmd(line)
		except ldap3.core.exceptions.LDAPSocketOpenError as e:
			print(f"FAILURE: LDAPSocketOpenError {e.args} thrown attempting to query users, if \"invalid server address\" and base connection works, then domain name (or formatted domain components query string) is likely invalid")
			if not self.connection.closed:	
				print(f"Closing {self.connection}")
				self.connection.unbind()
			return False
		except BaseException as e:
			print(f"FAILURE: encountered {e}")
			if not self.connection.closed:	
				self.connection.unbind()
				print(f"Closing {self.connection}")
			return False

	def do_enum_users(self, arg):
		#print(f"Executing command: {arg}")

		# TODO: If we can get server info, shouldn't we be setting this to this:
		# server.info.rootDomainNamingContext or server.info.defaultNamingContext

		domaincomponents=format_ldap_domain_components(self.hostdomain)

		self.connection.search(search_base=domaincomponents,
			search_filter='(&(objectClass=user)(objectClass=person))',
			search_scope='SUBTREE',
			attributes='*')

		print(self.connection.entries)
		# TODO: Clear entries after query?  

	def do_enum_server_info(self, args):
		print(self.connection.server.info.__dict__)
		# useful (non verbose output):
		# server.info.naming_contexts
		# server.info.alt_servers
		# server.info.supported_ldap_versions
		# server.info.supported_sasl_mechanisms
		# server.info.other.dnsHostName
		# server.info.other.rootDomainNamingContext
		# server.info.other.dnsHostName
		# supportedcontrols doesn't seem too useful, except for https://ldapwiki.com/wiki/Get%20Effective%20Rights%20Control 
		print(self.connection.server.info)

	def do_whoami(self, args):
		ldapuser=self.connection.extend.standard.who_am_i() if self.connection.extend != None else None
		if ldapuser:
			print(f"User: {ldapuser}")
		else:
			print(f"Connection returned no current user.  This is likely because authentication failed or wasn't attempted (i.e. this is an anonymous bind)")

	def do_quit(self, args):
		print("Exiting...")
		if not self.connection.closed:	
			print(f"Closing {self.connection}")
			self.connection.unbind()
		return True


	def default(self, arg):
		print(f"Executing search with query: {arg}")
		#ErlRce.EXECUTE_REMOTE_COMMAND(arg, self.cookie, self.port, self.host)