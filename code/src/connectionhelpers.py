#!/usr/bin/env python3

import ldap3
from code.src.consts import SSL_PORTS
from impacket.krb5 import ccache, types
import os

SUPPORTED_SASL_AUTH_METHODS = ["DIGEST-MD5"]	

def get_connection(ldaphost, port):

	server = ldap3.Server(ldaphost, port =port, use_ssl = (port in SSL_PORTS), get_info=ldap3.ALL)

	connection = ldap3.Connection(server, auto_range=True)

	connection.bind()

	return connection

def try_connect(ldaphost, port, logger):
	server = ldap3.Server(ldaphost, port =port, use_ssl = (port in SSL_PORTS), get_info=ldap3.NONE)

	connection = ldap3.Connection(server)

	failure_msg_abridged = ""
	try:
		connsucceeded = connection.bind()
	except Exception as e:
		connsucceeded=False
		failure_msg_abridged = str(type(e))
	
	logger.print_debug(f"{port}: " + ("Connected successfully" if connsucceeded else f"Failed to connect with: {failure_msg_abridged}"))

	if connsucceeded and not connection.closed:	
		connection.unbind()
	return connsucceeded

def get_server_supported_sasl_authentication_methods(ldaphost, port, logger):
	server = ldap3.Server(ldaphost, port =port, use_ssl = (port in SSL_PORTS), get_info=ldap3.ALL)

	connection = ldap3.Connection(server)

	connection.bind()

	# Treat none as any
	supported = server.info.supported_sasl_mechanisms if (server.info != None and server.info.supported_sasl_mechanisms != None) else None 
	logger.print_debug(f"Supported sasl auth methods: {supported}")

	if not connection.closed:	
		connection.unbind()

	return supported

def modify_ccache_spns():
	# TODO
	r = 'r'


def get_authenticated_connection(ldaphost,realm,port,username,password,authentication_method, logger):
	if authentication_method == "SIMPLE":
		s = ldap3.Server(ldaphost, port=port,get_info=ldap3.ALL)
		c = ldap3.Connection(s, user=username, password=password, auto_range=True)
		c.bind()
		return c
	elif authentication_method ==  "DIGEST-MD5":
		realm = realm if realm else None # None leads to use of server default realm 
		logger.print_debug(f"User:{username} --- Pass:{password} --- Realm: {realm}")
		s = ldap3.Server(ldaphost, port=port,get_info=ldap3.ALL)
		c = ldap3.Connection(s, auto_bind = True, version = 3, authentication = ldap3.SASL,
                         sasl_mechanism = ldap3.DIGEST_MD5, sasl_credentials = (realm, username, password, None, 'sign'))
		return c
	elif authentication_method == "NTLM":
		# TODO
		r = 'r'
	elif authentication_method == "Kerberos":
		# TODO: Imports here or in helper so users who do't need kerb auth do't have to configure gssapi
		tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
		# TODO: tls & ssl?
		server = Server('ldap://dc.windomain.local', use_ssl=True, tls=tls)
		# TODO: update host to prefix w/ ldaps or ldap? 
		# Prefix seems necessary here
		# TODO: Specify user? Do we need TGS for particular host w/ particular service type?
		c = Connection(
			server, authentication=SASL, sasl_mechanism=KERBEROS)
	else:
		raise Exception(f"Unknown or unsupported authentication method {authentication_method}")	

def try_get_authenticated_connection(ldaphost,realm,port,username,password,authentication_method, logger):
	try:
		conn = get_authenticated_connection(ldaphost,realm,port,username,password,authentication_method,logger)
		logger.print_debug(f"{authentication_method}: {username} - {conn.extend.standard.who_am_i()}")
		# TODO: Probably a more sophisticated way to check, but potentially difficult (e.g. encountered username user@dom.ain => whoami dom\user)
		# and doesn't seem that important to check.  Potential risk if a server ever returns "Anonymous" or similar, but seems unlikely
		connsucceeded = conn.bound and conn.extend.standard.who_am_i()
	except ldap3.core.exceptions.LDAPSocketOpenError:
		connsucceeded=False
	
	logger.print_debug(f"{port}: " + ("Connected successfully" if connsucceeded else "Failed to connect"))

	if not connsucceeded and not conn.closed:	
		conn.unbind()
	return (connsucceeded, conn)

	# TODO: LDAPS ports
