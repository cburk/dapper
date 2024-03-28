#!/usr/bin/env python3
import ldap3
import cmd, sys, os, json
from code.src.connectionhelpers import try_connect,get_connection
from code.src.queryformatter import UAC_FLAG_DESCRS_TO_FLAGS,UAC_FLAGS,parse_security_descriptor,get_user_account_spns_filter,get_all_with_spns_filter,response_properties_all_formatted,format_ldap_domain_components,response_properties_subset,uac_bitstring_to_flags,get_common_spns_filter,is_common_spn,get_users_filter
from code.src.shellargumentparser import find_args, find_args_allowduplicates

# Command handler pattern
from code.src.CommandHandlers.CommandMediator import CommandMediator
from code.src.Commands.writeMsDSAllowedToActOnBehalfOfOtherIdentityCommand import writeMsDSAllowedToActOnBehalfOfOtherIdentityCommand
from code.src.Commands.writeMsDSAllowedToDelegateToCommand import writeMsDSAllowedToDelegateToCommand
from code.src.Commands.writeUacFlagsCommand import writeUacFlagsCommand
from code.src.Commands.writeSPNToUserCommand import writeSPNToUserCommand
from code.src.Commands.writeUserToGroupCommand import writeUserToGroupCommand
from code.src.Commands.enumGroupsCommand import enumGroupsCommand

class LDAPEnumShell(cmd.Cmd):
	intro = '\n\n\nLDAP Enumerator Shell\n\nFor LDAP Enumeration.  ? or help for more info\n\n\n'
	prompt = '> '
	common_args_description = "--outfile {filename} to output results to file.  -v for verbose output (unformatted ldap response)"

	def get_server_domain_components(self):
		serverinfo=self.connection.server.info

		rootcontexts = None
		if serverinfo is not None and serverinfo.other is not None and "rootDomainNamingContext" in serverinfo.other.keys():
			rootcontexts=serverinfo.other["rootDomainNamingContext"]
		if rootcontexts is None:
			return None
		if len(rootcontexts) > 1:
			print(f"Warning: expected one root naming context, found: {rootcontexts}")
			
		return rootcontexts[0]
	
	def do_help(self, arg):
		print(self.common_args_description)
		super().do_help(arg)

	def __init__(self, hostdomain, connection,logger):
		self.hostdomain = hostdomain
		self.logger = logger
		self.connection = connection
		self.filedescriptor = None
		self.mediator = CommandMediator()

		# Note: As I understand it, the root naming context isn't always a function of the domain name.
		# But, since this tool is primarily designed for use against AD, and to simplify for users who don't yet know the domain, I'm adding this as an option 
		serverdomaincomponents=self.get_server_domain_components()
		if hostdomain is None and serverdomaincomponents is None:
			raise Exception("Could not format root domain components: domain argument not provided, server did not supply")
		elif hostdomain is None:
			self.logger.print_debug(f"Setting root naming context to server specified: {serverdomaincomponents}")
			self.domaincomponents=serverdomaincomponents
		elif serverdomaincomponents is None:
			hostdomaincomponents=format_ldap_domain_components(self.hostdomain)
			self.logger.print_debug(f"Setting root naming context based on domain: {hostdomaincomponents}")
			self.domaincomponents=hostdomaincomponents
		else:
			hostdomaincomponents=format_ldap_domain_components(self.hostdomain)
			self.logger.print_debug(f"Setting root naming context to server specified: {serverdomaincomponents} (vs domain {self.hostdomain} and {hostdomaincomponents})")
			self.domaincomponents=serverdomaincomponents

		super().__init__()

	def cleanup(self):
		if not self.connection.closed:	
			print(f"Closing {self.connection}")
			self.connection.unbind()

		if self.filedescriptor is not None:
			print(f"Closing {self.filedescriptor}")
			self.filedescriptor=None

	def onecmd(self, line):
		try:
			# Handle shared args
			if line:
				args = find_args(["-v","--outfile"],line)
				if "--outfile" in args.keys():
					if args["--outfile"] is not None and args["--outfile"]:
						filename = args["--outfile"]
						print(f"Opening file {filename} to write output")
						fd = open(filename,"w")
						print(f"Using file descriptor {fd}")
						self.filedescriptor=fd
					else:
						print(f"Error: Expected filename after --outfile")
				if "-v" in args.keys():
					self.verbose=True
				else:
					self.verbose=False					

			return super().onecmd(line)
		except ldap3.core.exceptions.LDAPSocketOpenError as e:
			print(f"FAILURE: LDAPSocketOpenError {e.args} thrown attempting to query ldap, if \"invalid server address\" and base connection works, then domain name (or formatted domain components query string) is likely invalid")
			self.cleanup()
			return True
		except BaseException as e:
			print(f"FAILURE: encountered {e}.  Keeping connection alive")
			return False

	def writeline(self, line):
		self.logger.print(line, self.filedescriptor)

	def postcmd(self, stop,line):
		if self.filedescriptor is not None:
			print(f"Closing {self.filedescriptor}")
			self.filedescriptor=None

		return stop

	def do_enum_password_settings(self, arg):
		'Look for common AD password settings (msDS-PasswordSettings, domainDNS, )'
	
		# msDS-PasswordSettings
		self.writeline("===================================")
		self.writeline("msDS-PasswordSettings	   ")
		self.writeline("===================================")
		filt = "(objectClass=msDS-PasswordSettings)"
		self.connection.search(search_base=self.domaincomponents,
			search_filter=filt,
			search_scope='SUBTREE',
			attributes='*')
		res = self.connection.response_to_json()
		formattedentries = response_properties_all_formatted(res)

		self.writeline(json.dumps(formattedentries, indent=4))

		# domain dns
		self.writeline("===================================")
		self.writeline("DomainDNS			   ")
		self.writeline("===================================")
		filt = "(&(objectClass=domainDNS)(objectClass=domain))"
		self.connection.search(search_base=self.domaincomponents,
			search_filter=filt,
			search_scope='SUBTREE',
			attributes='*')
		res = self.connection.response_to_json()
		formattedentries = response_properties_all_formatted(res)

		self.writeline(json.dumps(formattedentries, indent=4))

		
		# CN=Password Settings Container
		self.writeline("===================================")
		self.writeline("Password Settings Container	   ")
		self.writeline("===================================")
		self.connection.search(search_base= "CN=Password Settings Container,CN=System," + self.domaincomponents,
			search_filter="(objectClass=*)",
			search_scope='SUBTREE',
			attributes='*')
		res = self.connection.response_to_json()
		formattedentries = response_properties_all_formatted(res)

		self.writeline(json.dumps(formattedentries, indent=4))
		
	def do_enum_users(self, args):
		'gets users.  if -like NAME is passed, looks for users with similar principal names'		
		
		argsparsed = find_args(["-like"], args)
		if argsparsed:
			filter = get_users_filter(argsparsed["-like"])
		else:
			filter = get_users_filter()
		if self.verbose:
			self.writeline(f"Query: {filter}")

		self.connection.search(search_base=self.domaincomponents,
			search_filter=filter,
			search_scope='SUBTREE',
			attributes=[ldap3.ALL_ATTRIBUTES, 'nTSecurityDescriptor'])

		res = self.connection.response_to_json()
		
		# TODO: Rewrite it to be part of the rest of the parsing
		for e in self.connection.entries:
			#print(e.entry_to_json())
			p = json.loads(e.entry_to_json())
			print(p)
			print("Secd: " + p["attributes"]["nTSecurityDescriptor"][0]["encoded"])
			print("Change")
			parse_security_descriptor(p["attributes"]["nTSecurityDescriptor"][0]["encoded"])

		if self.verbose:
			formattedentries = response_properties_all_formatted(res)
		else:
			formattedentries = response_properties_subset(res,["userAccountControl","sAMAccountName","userPrincipalName","description","memberOf"])
		
		for entry in formattedentries:
			if "userAccountControl" in entry.keys():
					uacbitstring = entry["userAccountControl"]
					try:
						entry["userAccountControlFormatted"] = uac_bitstring_to_flags(int(uacbitstring))
					except ValueError:
						print(f"Error: Could not parse UAC: {uacbitstring}")

		# TODO: Figure out the logging situation, really need 2 self.writelines (one for debug level, one for normal)
		# e.g. printing filter is a debug level log, -verbose should just add the additional properties
		
		# TODO: Turn back on
		#self.writeline(json.dumps(formattedentries, indent=4))
				
		# TODO: Clear entries after query?  

	def do_enum_groupsandusers2(self, arg):
		self.connection.search(search_base=self.domaincomponents,
		search_filter='(objectClass=*)',
		search_scope='SUBTREE',
		attributes=['CN','ACL'])
		print(self.connection.response_to_json())
		print("==============================\n\n")
		print("Starting Entries parsing\n\n")
		print("==============================\n\n")
		for e in self.connection.entries:
			print(e.entry_to_json())

	def do_enum_groups(self, args):
		'gets groups. -like <phrase> to search for groups w/ that phrase in their name'		

		argsparsed = find_args(["-like"], args)
		like = ''
		if argsparsed:
			like = argsparsed["-like"]
	
		command = enumGroupsCommand(like)
		res = self.mediator.handle(command, self.connection, self.domaincomponents)
		if self.verbose:
			formattedentries = response_properties_all_formatted(res)
		else:
			formattedentries = response_properties_subset(res,["name","member","memberOf"])
		
		self.writeline(json.dumps(formattedentries, indent=4))	

	def do_enum_computers(self, arg):
		dn = "CN=computers," + self.domaincomponents
		self.connection.search(search_base=self.domaincomponents,
			search_filter='(objectclass=computer)',
			search_scope='SUBTREE',
			attributes=[ldap3.ALL_ATTRIBUTES, 'nTSecurityDescriptor'])

		res = self.connection.response_to_json()
		
		formattedentries = response_properties_all_formatted(res)
		self.writeline(json.dumps(formattedentries, indent=4))	
		
		
		print("==============================\n\n")
		print("Starting Entries parsing\n\n")
		print("==============================\n\n")
		for e in self.connection.entries:
			#print(e.entry_to_json())
			p = json.loads(e.entry_to_json())
			print(p)
			print("Secd: " + p["attributes"]["nTSecurityDescriptor"][0]["encoded"])
			print("Change")
			parse_security_descriptor(p["attributes"]["nTSecurityDescriptor"][0]["encoded"])
			#parse_security_descriptor(e.ntSecurityDescriptor)

		
	def do_enum_spns(self, args):
		'Looks for some common spns that indicate useful services. -v for all spns, -user for only SPNs assigned to regular users (kerberoasting potentially feasible)'
		
		if self.verbose:
			filt = get_all_with_spns_filter()
		elif find_args(["-user"], args):
			filt = get_user_account_spns_filter()
		else:
			filt = get_common_spns_filter()
		
		self.connection.search(search_base=self.domaincomponents,
			search_filter=filt,
			search_scope='SUBTREE',
			attributes='*')
		res = self.connection.response_to_json()

		if self.verbose:
			formattedentries = response_properties_all_formatted(res)
		else:
			formattedentries = response_properties_subset(res,["servicePrincipalName"])
			for entry in formattedentries:
				spns = entry["servicePrincipalName"]
				if isinstance(spns,list):
					interestingspns = []
					for spn in spns:
						if is_common_spn(spn):
							interestingspns.append(spn)
					entry["servicePrincipalName"] = interestingspns

		self.writeline(json.dumps(formattedentries, indent=4))

	def do_enum_service_accounts(self, args):
		'Looks for some service accounts (with useful spns, unless -v specified, then any with spns).'
		filt = get_common_spns_filter()
		
		if self.verbose:
			filt = get_all_with_spns_filter()
		
		self.connection.search(search_base=self.domaincomponents,
			search_filter=filt,
			search_scope='SUBTREE',
			attributes='*')
		
		res = self.connection.response_to_json()
		
		if self.verbose:
			formattedentries = response_properties_all_formatted(res)
		else:			
			formattedentries = response_properties_subset(res,["servicePrincipalName","description","sAMAccountName","objectClass"])
			for entry in formattedentries:
				spns = entry["servicePrincipalName"]
				if isinstance(spns,list):
					interestingspns = []
					for spn in spns:
						if is_common_spn(spn):
							interestingspns.append(spn)
					entry["servicePrincipalName"] = interestingspns
					
		# Determine which are group managed
		for entry in formattedentries:
			classestolower = [x.lower() for x in entry["objectClass"]]
			if "msds-groupmanagedserviceaccount" in classestolower or "msds-managedserviceaccount" in classestolower:
				entry["isManagedServiceAccount"] = True
			else:
				entry["isManagedServiceAccount"] = False
			
			if not self.verbose:
				entry["objectClass"] = None

		self.writeline(json.dumps(formattedentries, indent=4))
			
	def help_write_uac_flags(self):
		print(f'Set or unset uac flags for entity specified by -sid.  -set <flag> to flip on, -unset <flag> to flip off (multiples allowed).  Flags can be specified w/ the integer value of the mask (e.g. 524288 for TrustedForDelegation) or one of these string representations (sans quotes): {UAC_FLAG_DESCRS_TO_FLAGS.keys()}')
	def do_write_uac_flags(self,args):
		argsparsed = find_args_allowduplicates(["-sid","-set","-unset"],args)
		if "-sid" in argsparsed.keys():
			entitysid = argsparsed["-sid"][0]
			sets = []
			unsets = []
			if "-set" in argsparsed.keys():
				for setflag in argsparsed["-set"]:
					sets.append(UAC_FLAGS[int(setflag)] if setflag.isdecimal() else setflag)
			if "-unset" in argsparsed.keys():
				for unsetflag in argsparsed["-unset"]:
					unsets.append(UAC_FLAGS[int(unsetflag)] if unsetflag.isdecimal() else unsetflag)

			command = writeUacFlagsCommand(entitysid, sets, unsets)
			self.mediator.handle(command, self.connection, self.domaincomponents)
		else:
			print("ERROR: no -sid passed") # Error log

	def do_write_spn_to_user(self, args):
		'create spn -spn for user w/ sid=-sid'
		argsparsed = find_args_allowduplicates(["-sid","-spn"], args)
		if "-sid" in argsparsed.keys():
			entitysid = argsparsed["-sid"][0]
			command = writeSPNToUserCommand(entitysid, argsparsed["-spn"])
			self.mediator.handle(command, self.connection, self.domaincomponents)
		else:
			print("ERROR: no -sid passed") # Error log

	def do_write_user_to_group(self, args):
		'write -usersid to group -groupsid'
		argsparsed = find_args(["-usersid","-groupsid"], args)
		usersid = argsparsed["-usersid"]
		groupsid = argsparsed["-groupsid"]
		command = writeUserToGroupCommand(groupsid,usersid)
		self.mediator.handle(command, self.connection, self.domaincomponents)

	def do_write_msDS_AllowedToActOnBehalfOfOtherIdentity(self, args):
		'write -valuesid sid to the msDS-AllowedToActOnBehalf... attribute of object w/ sid=-victimsid'
		argsparsed = find_args(["-valuesid","-victimsid"], args)
		valuesid = argsparsed["-valuesid"]
		victimsid = argsparsed["-victimsid"]
		cmd = writeMsDSAllowedToActOnBehalfOfOtherIdentityCommand(victimsid, valuesid)
		self.mediator.handle(cmd, self.connection, self.domaincomponents)
		# TODO: Any printing or post-proc

	def do_write_msDS_AllowedToDelegateTo(self, args):
		'write -spn spn to the msDS-AllowedToDelegateTo attribute of object w/ sid=-sid'

		argsparsed = find_args(["-spn","-sid"], args)
		spn = argsparsed["-spn"]
		sid = argsparsed["-sid"]
		self.writeline(f"Adding {spn} to entity w/ sid {sid}") #debug level

		command = writeMsDSAllowedToDelegateToCommand(spn,sid)
		self.mediator.handle(self.connection, self.domaincomponents, command)

	def do_enum_server_info(self, arg):
		'gets server info from DSE. '		

		
		# useful (non verbose output):
		# server.info.naming_contexts
		# server.info.alt_servers
		# server.info.supported_ldap_versions
		# server.info.supported_sasl_mechanisms
		# server.info.other.dnsHostName
		# server.info.other.rootDomainNamingContext
		# server.info.other.dnsHostName
		# supportedcontrols doesn't seem too useful, except for https://ldapwiki.com/wiki/Get%20Effective%20Rights%20Control 
		self.writeline(self.connection.server.info)

	def do_whoami(self, args):
		ldapuser=self.connection.extend.standard.who_am_i() if self.connection.extend != None else None
		if ldapuser:
			self.writeline(f"User: {ldapuser}")
		else:
			self.writeline(f"Connection returned no current user.  This is likely because authentication failed or wasn't attempted (i.e. this is an anonymous bind)")

			
	def exit(self, args):
		print("Exiting...")
		
		if "-f" in args:
			try:
				self.cleanup()
			except:
				return True
		else:
			self.cleanup()
		
		return True
	
	def do_quit(self, args):
		'Exit the application.  -f to force (i.e. exit even if connection cleanup fails)'

		return self.exit(args)

	def do_exit(self, args):
		'Exit the application.  -f to force (i.e. exit even if connection cleanup fails)'
		
		return self.exit(args)
		
	def do_search(self, arg):
		'executes custom query under root context.\nflags are -rdns and -filter (e.g. -rdns ou=pwpolicies -filter x)'
		
		dn = self.domaincomponents
		filt = "(objectClass=*)"

		args = find_args(["-rdns","-filter"],arg)
		
		if "-filter" in args.keys():
			filt = args["-filter"]
		if "-rdns" in args.keys():
			rdns = args["-rdns"]
			dn = args["-rdns"] + ("," if rdns[-1] != "," else "") + dn
		
		self.logger.print_debug(f"filter: {filt}")
		self.logger.print_debug(f"dn: {dn}")
					
		self.connection.search(search_base=dn,
			search_filter=filt,
			search_scope='SUBTREE',
			attributes='*')

		self.writeline(self.connection.entries)

	

