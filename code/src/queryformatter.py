#!/usr/bin/env python3
import json
from impacket.ldap import ldaptypes
from ldap3 import MODIFY_REPLACE,MODIFY_ADD
import base64

UAC_FLAGS = {
	1: "SCRIPT",
	2: "ACCOUNTDISABLE",
	8: "HOMEDIR_REQUIRED",
	16: "LOCKOUT",
	32: "PASSWD_NOTREQD",
	64: "PASSWD_CANT_CHANGE",
	128: "ENCRYPTED_TEXT_PWD_ALLOWED",
	256: "TEMP_DUPLICATE_ACCOUNT",
	512: "NORMAL_ACCOUNT",
	2048: "INTERDOMAIN_TRUST_ACCOUNT",
	4096: "WORKSTATION_TRUST_ACCOUNT",
	8192: "SERVER_TRUST_ACCOUNT",
	65536: "DONT_EXPIRE_PASSWORD",
	131072: "MNS_LOGON_ACCOUNT",
	262144: "SMARTCARD_REQUIRED",
	524288: "TRUSTED_FOR_DELEGATION",
	1048576: "NOT_DELEGATED",
	2097152: "USE_DES_KEY_ONLY",
	4194304: "DONT_REQ_PREAUTH",
	8388608: "PASSWORD_EXPIRED",
	16777216: "TRUSTED_TO_AUTH_FOR_DELEGATION",
	67108864: "PARTIAL_SECRETS_ACCOUNT"
}
UAC_FLAG_DESCRS_TO_FLAGS = {v: k for k, v in UAC_FLAGS.items()}

# Should be case insensitive by default
USEFUL_SPNS = [
	"cifs",
	"exchange",
	"dns",
	"ftp",
	"http",
	"imap",
	"ipp",
	"mongo",
	"sql",
	"kafka",
	"pop",
	"postgres",
	"smtp",
	"terms",
	"vnc",
	"vpn"
]

def is_common_spn(spn):
	for useful_spn in USEFUL_SPNS:
		if useful_spn in spn.lower():
			return True
	return False

# ldap3 get queries
def get_users_filter(nameLike = ''):
	base = "(&(objectClass=user)(objectClass=person))"
	if nameLike != '':
		base = f"(& (userPrincipalName=*{nameLike}*) {base})"
	return base

def get_user_account_spns_filter():
	return "(& (objectCategory=person) (servicePrincipalName=*))"

def get_common_spns_filter():
	filt = "(|"
	for spn in USEFUL_SPNS:
		filt += f"(serviceprincipalname=*{spn}*)"
	filt += ")"
	return filt

def get_all_with_spns_filter():
	filt = "(serviceprincipalname=*)"
	return filt

def get_object_with_sid_filter(sid):
	filt = f"(objectSid={sid})"
	return filt

# ldap3 modify operations
def get_append_msds_allowedtodelegateto_operation(spn):
	command = { "msDS-AllowedToDelegateTo": [(MODIFY_ADD, [spn])] }
	return command

def get_set_msds_allowedtoactonbehalfof_operation(securitydescriptor):
	command = { "msds-allowedtoactonbehalfofotheridentity": [(MODIFY_REPLACE, [securitydescriptor])] }
	return command

def get_set_uac_operation(newuac):
	command = { "userAccountControl": [(MODIFY_REPLACE, [newuac])]}
	return command

def format_ldap_domain_components(domainName):
	domains=domainName.split(".")
	formatted_domains = [f"DC={x}" for x in domains]
	ldapstr = ",".join(formatted_domains)
	return ldapstr

# Return json representation of query response, with only a subset of each entry's properties (for legibility)
def response_properties_subset(resjson, props):
	jsonentries = json.loads(resjson)["entries"]
	formatted=[]
	for entry in jsonentries:
		attrs = entry["attributes"]
		attrskeys = attrs.keys()
		if "dn" in entry.keys():
			newentry = {"dn": entry["dn"]}
		else:
			newentry = {}
		for prop in props:
			if prop not in attrskeys:
				continue
			val = attrs[prop]			
			if isinstance(val, list) and len(val) == 1: # LDAP library has lots of rules about when it returns one value or single element collections, condensing for readability
				newentry[prop] = val[0]
			else:
				newentry[prop] = val
		formatted.append(newentry)
	return formatted

# Same structure as response_properties_subset, but with all entry properties (for verbose output with consistent formatting)
def response_properties_all_formatted(resjson):
	jsonentries = json.loads(resjson)["entries"]
	formatted=[]
	for entry in jsonentries:
		attrs = entry["attributes"]
		attrskeys = attrs.keys()
		if "dn" in entry.keys():
			newentry = {"dn": entry["dn"]}
		else:
			newentry = {}
		for attr in attrskeys:
			val = attrs[attr]			
			if isinstance(val, list) and len(val) == 1: # LDAP library has lots of rules about when it returns one value or single element collections, condensing for readability
				newentry[attr] = val[0]
			else:
				newentry[attr] = val
		formatted.append(newentry)
	return formatted


def uac_bitstring_to_flags(uac):
	flags = []
	for key in UAC_FLAGS.keys():
		if key & uac == key:
			flags.append(UAC_FLAGS[key])
	return flags

def parse_security_descriptor(b64_ntsecuritydescriptor):
	# secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR()
	# secDesc.fromString(b64_ntsecuritydescriptor)
	# print(str(secDesc))

	# TODO: Almost perfect example of what I'm doing: https://github.com/the-useless-one/pywerview/blob/71e70889347f726dd9f9ba15f0d953bba07b9bd8/pywerview/functions/net.py#L68C1-L69C1
	print("START")
	print(b64_ntsecuritydescriptor)
	secDesc2 = ldaptypes.SR_SECURITY_DESCRIPTOR()
	#secDesc2.fromString(b64_ntsecuritydescriptor.values[0].decode("UTF-8"))
	secDesc2.fromString(base64.b64decode(b64_ntsecuritydescriptor))
	print(type(secDesc2['OwnerSid']))
	print(secDesc2['OwnerSid'].formatCanonical()) # Works!  Just need way to display
	print("END")

