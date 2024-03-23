#!/usr/bin/env python3

import ldap3
from code.src.consts import SSL_PORTS
from impacket.krb5 import ccache, types
from pathlib import Path
import os
import ssl

SUPPORTED_SASL_AUTH_METHODS = ["DIGEST-MD5"]	

def get_connection(ldaphost, port):

	server = ldap3.Server(ldaphost, port =port, use_ssl = (port in SSL_PORTS), get_info=ldap3.ALL)

	connection = ldap3.Connection(server, auto_range=True)

	connection.bind()

	return connection

def try_connect(ldaphost, port, logger):
	tls = None 
	if port in SSL_PORTS:
		tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

	server = ldap3.Server(ldaphost, port =port, use_ssl = (port in SSL_PORTS), tls=tls, get_info=ldap3.ALL)

	connection = ldap3.Connection(server)

	failure_msg_abridged = ""
	try:
		connsucceeded = connection.bind()
	except Exception as e:
		connsucceeded=False
		failure_msg_abridged = str(type(e)) + str(e)
	
	logger.print_debug(f"{port}: " + ("Connected successfully" if connsucceeded else f"Failed to connect with: {failure_msg_abridged}"))

	if not connsucceeded and not connection.closed:	
		connection.unbind()
	return (connsucceeded, connection)

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

def format_ldap_principal_name(ldaphost, realm):
	return f"ldap/{ldaphost}@{realm}"

# Change the SPN on (a copy of) the TGS provided by KRB5CCNAME env var
# in case the provided TGS is for the same service account as ldap
# but for a different SPN
def use_tgs_modifiedspn(logger, new_principal):
	cacheFileName = os.environ["KRB5CCNAME"]
	# Note: could do more formal verification that this is actually a TGS, support going TGT=>TGS, etc, but 
	# this should be sufficient for now
	if not cacheFileName or cacheFileName[-7:] != ".ccache":
		logger.print_debug(f"found KRB5CCNAME={cacheFileName}, need valid tgs ccache ending w/ '.ccache' to take modified SPN approach.")
		return 
	my_file = Path(cacheFileName)
	if not my_file.is_file():
		logger.print_debug(f"found KRB5CCNAME={cacheFileName}, doesn't seem to exist")
		return
	
	forgedCacheName = cacheFileName[:-7] + "-backup.ccache"
	cache = ccache.CCache.loadFile(cacheFileName)

	for impcred in cache.credentials:
		np = types.Principal(new_principal, type=impcred.header["server"].header['name_type'])
		newprincipal = ccache.Principal()
		newprincipal.fromPrincipal(np)
		impcred.header["server"] = newprincipal

	cache.saveFile(forgedCacheName)

	os.environ["KRB5CCNAME"] = forgedCacheName


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
		c.bind()
		return c
	elif authentication_method == "NTLM":
		# TODO: TLS & SSL?
		tls = None 
		if port in SSL_PORTS:
			tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

		s = ldap3.Server(ldaphost, port=port, use_ssl = (port in SSL_PORTS), tls=tls, get_info=ldap3.ALL)
		#s = ldap3.Server(ldaphost, port=port, get_info=ldap3.ALL)
		c = ldap3.Connection(s, user=username, password=password, authentication=ldap3.NTLM, raise_exceptions=True)
		c.bind()
		return c
	elif authentication_method == "Kerberos":
		# Imports here so users who do't need kerb auth do't have to configure gssapi
		import gssapi
		import gssapi.raw as gr
		tls = None
		if port in SSL_PORTS:
			tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

		# TODO: tls & ssl?  ldaps vs ldap? 
		proto = "ldaps" if port in SSL_PORTS else "ldap"
		server = ldap3.Server(f'{proto}://{ldaphost}', port=port, use_ssl=True, tls=tls, get_info=ldap3.ALL)
		c = ldap3.Connection(
			server, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS)
		try:
			c.bind(read_server_info=True)
		# If ST doesn't match this ldap service but is for same service acct, try changing spn
		# on provided ST to match
		except gr.misc.GSSError as e:
			logger.print_debug(f"Initial kerberos bind failed with {str(e)}, trying to modify ST/TGS w/ appropriate SPN")
			if not realm:
				logger.print_debug(f"Realm not provided, cannot modify ST/TGS SPN.  Returning")
				return c
			principal = format_ldap_principal_name(ldaphost,realm)
			logger.print_debug(f"Connecting with provided ccache failed, attempting to modify spn to: {principal}")
			use_tgs_modifiedspn(logger, principal)
			c = ldap3.Connection(
				server, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS)
			try:
				c.bind(read_server_info=True)
			# Error formatting here instead of in the handler b/c of the aforementioned dependency issue
			except gr.misc.GSSError as e:
				raise Exception(f"gssapi error, issue with spelling/casing of hostdomain for modified ticket (e.g. used hostdomain=windomain.local, need WINDOMAIN.LOCAL)?  Error message: " + str(e))
		return c
	else:
		raise Exception(f"Unknown or unsupported authentication method {authentication_method}")
	

def try_get_authenticated_connection(ldaphost,realm,port,username,password,authentication_method, logger):
	conn = None
	try:
		conn = get_authenticated_connection(ldaphost,realm,port,username,password,authentication_method,logger)
		logger.print_debug(f"{authentication_method}: {username} - {conn.extend.standard.who_am_i()}")
		# TODO: Probably a more sophisticated way to check, but potentially difficult (e.g. encountered username user@dom.ain => whoami dom\user)
		# and doesn't seem that important to check.  Potential risk if a server ever returns "Anonymous" or similar, but seems unlikely
		connsucceeded = conn.bound and conn.extend.standard.who_am_i()
		if not connsucceeded:
			errormsg = str(conn.last_error) if conn.last_error else "None"
	except ldap3.core.exceptions.LDAPSocketOpenError as e:
		connsucceeded=False
		errormsg = str(e)
	except Exception as e:
		connsucceeded = False
		errormsg = str(e)

	logger.print_debug(f"{port}: " + ("Connected successfully" if connsucceeded else f"Failed to connect: {errormsg}"))

	if conn and not connsucceeded and not conn.closed:	
		conn.unbind()
	return (connsucceeded, conn)

	# TODO: LDAPS ports
