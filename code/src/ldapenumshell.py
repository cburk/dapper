#!/usr/bin/env python3
import ldap3
import cmd, sys, os, json
from code.src.connectionhelpers import try_connect,get_connection
from code.src.queryformatter import get_user_account_spns_filter,get_all_with_spns_filter,response_properties_all_formatted,format_ldap_domain_components,response_properties_subset,uac_bitstring_to_flags,get_common_spns_filter,is_common_spn

def find_args(argnames, stringinput):
	indtoname = {}

	for arg in argnames:
		if arg in stringinput:
			startind = stringinput.index(arg)
			indtoname[startind] = arg
			
	keyvaluepairs = {}
	indssorted = list(indtoname.keys())
	indssorted.sort()
	i = 0
	for i in range(len(indssorted)):
		argind = indssorted[i]
		arg = indtoname[argind]

		valuestartind = argind + len(arg)
		if i + 1 == len(indssorted):
			valueendind = len(stringinput)
		else:
			valueendind = indssorted[i+1] - 1
		value = stringinput[valuestartind:valueendind]
		value = value.lstrip().rstrip()
		keyvaluepairs[arg] = value
	return keyvaluepairs


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

	def __init__(self, hostip, hostdomain, port, username, password, create_connection):
		self.hostip = hostip
		self.hostdomain = hostdomain
		self.port = port
		self.username = username
		self.password = password
		print(f"trying {self.hostip}:{self.port}")
		self.connection = create_connection(hostip,hostdomain,port,username,password)
		self.filedescriptor = None

		# Note: As I understand it, the root naming context isn't always a function of the domain name.
		# But, since this tool is primarily designed for use against AD, and to simplify for users who don't yet know the domain, I'm adding this as an option 
		serverdomaincomponents=self.get_server_domain_components()
		if hostdomain is None and serverdomaincomponents is None:
			raise Exception("Could not format root domain components: domain argument not provided, server did not supply")
		elif hostdomain is None:
			print(f"Setting root naming context to server specified: {serverdomaincomponents}")
			self.domaincomponents=serverdomaincomponents
		elif serverdomaincomponents is None:
			hostdomaincomponents=format_ldap_domain_components(self.hostdomain)
			print(f"Setting root naming context based on domain: {hostdomaincomponents}")
			self.domaincomponents=hostdomaincomponents
		else:
			hostdomaincomponents=format_ldap_domain_components(self.hostdomain)
			print(f"Setting root naming context to server specified: {serverdomaincomponents} (vs domain {self.hostdomain} and {hostdomaincomponents})")
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
						filename = components[outind+1]
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
		print(line)
		if self.filedescriptor is not None:
			self.filedescriptor.write(str(line))

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
		
	def do_enum_users(self, arg):
		'gets users'		
		
		self.connection.search(search_base=self.domaincomponents,
			search_filter='(&(objectClass=user)(objectClass=person))',
			search_scope='SUBTREE',
			attributes='*')

		res = self.connection.response_to_json()
		
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
						print(f"Could not parse UAC: {uacbitstring}")

		self.writeline(json.dumps(formattedentries, indent=4))
				
		# TODO: Clear entries after query?  

	def do_enum_groups(self, arg):
		'gets groups'		
		self.connection.search(search_base=self.domaincomponents,
			search_filter='(objectClass=group)',
			search_scope='SUBTREE',
			attributes='*')

		res = self.connection.response_to_json()
		
		if self.verbose:
			formattedentries = response_properties_all_formatted(res)
		else:
			formattedentries = response_properties_subset(res,["name","member","memberOf"])
		self.writeline(json.dumps(formattedentries, indent=4))	
	
	def do_enum_computers(self, arg):
		dn = "CN=computers," + self.domaincomponents
		self.connection.search(search_base=self.domaincomponents,
			search_filter='(objectClass=*)',
			search_scope='SUBTREE',
			attributes='*')

		res = self.connection.response_to_json()
		
		formattedentries = response_properties_all_formatted(res)
		self.writeline(json.dumps(formattedentries, indent=4))	

		
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
		
		print(f"filter: {filt}")
		print(f"dn: {dn}")
					
		self.connection.search(search_base=dn,
			search_filter=filt,
			search_scope='SUBTREE',
			attributes='*')

		self.writeline(self.connection.entries)

	

