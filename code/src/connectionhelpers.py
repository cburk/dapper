#!/usr/bin/env python3

import ldap3
from code.src.consts import SSL_PORTS

# def can_user_authenticate(hostip, username, password, port):
	

def get_connection(hostip, port):

	server = ldap3.Server(hostip, port =port, use_ssl = (port in SSL_PORTS), get_info=ldap3.ALL)

	connection = ldap3.Connection(server)

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


