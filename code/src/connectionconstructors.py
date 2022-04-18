#!/usr/bin/env python3

def get_connection(hostip, username, password, port):
	server = ldap3.Server(hostip, port =port, use_ssl = (port in SSL_PORTS))

	connection = ldap3.Connection(server)

	connection.bind()

	return connection

def try_enumerate_server_info(port):
	server = ldap3.Server(args.hostip, port =port, use_ssl = (port in SSL_PORTS))	
	# server = ldap3.Server(args.hostip, port =port, use_ssl = (port in SSL_PORTS), get_info=ldap3.ALL)

	connection = ldap3.Connection(server)

	try:
		connsucceeded = connection.bind()
	except ldap3.core.exceptions.LDAPSocketOpenError:
		connsucceeded=False
	
	print(f"{port}: " + ("Connected successfully" if connsucceeded else "Failed to connect"))

	if connsucceeded:
		print(server.info)

	if not connection.closed:	
		connection.unbind()
	return connsucceeded
