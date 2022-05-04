#!/usr/bin/env python3

import ldap3
from code.src.consts import SSL_PORTS


SUPPORTED_SASL_AUTH_METHODS = ["DIGEST-MD5","whateverntlmis"]	

def get_connection(hostip, port):

	server = ldap3.Server(hostip, port =port, use_ssl = (port in SSL_PORTS), get_info=ldap3.ALL)

	connection = ldap3.Connection(server, auto_range=True)

	connection.bind()

	return connection

def try_connect(hostip, port):
	server = ldap3.Server(hostip, port =port, use_ssl = (port in SSL_PORTS), get_info=ldap3.NONE)

	connection = ldap3.Connection(server)

	try:
		connsucceeded = connection.bind()
	except ldap3.core.exceptions.LDAPSocketOpenError:
		connsucceeded=False
	
	print(f"{port}: " + ("Connected successfully" if connsucceeded else "Failed to connect"))

	if not connection.closed:	
		connection.unbind()
	return connsucceeded

def get_server_supported_sasl_authentication_methods(hostip, port):
	server = ldap3.Server(hostip, port =port, use_ssl = (port in SSL_PORTS), get_info=ldap3.ALL)

	connection = ldap3.Connection(server)

	connection.bind()

	# Treat none as any
	supported = server.info.supported_sasl_mechanisms if (server.info != None and server.info.supported_sasl_mechanisms != None) else None 
	print(f"Supported sasl auth methods: {supported}")

	if not connection.closed:	
		connection.unbind()

	return supported

def get_authenticated_connection(hostip,realm,port,username,password,authentication_method):
	if authentication_method == "SIMPLE":
		s = ldap3.Server(hostip, port=port,get_info=ldap3.ALL)
		c = ldap3.Connection(s, user=username, password=password, auto_range=True)
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
