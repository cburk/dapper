#!/usr/bin/env python3
import json

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

def format_ldap_domain_components(domainName):
	domains=domainName.split(".")
	formatted_domains = [f"DC={x}" for x in domains]
	ldapstr = ",".join(formatted_domains)
	print(ldapstr)
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

def uac_bitstring_to_flags(uac):
	flags = []
	for key in UAC_FLAGS.keys():
		if key & uac == key:
			flags.append(UAC_FLAGS[key])
	return flags
