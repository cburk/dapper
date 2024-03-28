#!/usr/bin/env python3
import json
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR,ACE_TYPE_MAP,ACE,ACCESS_ALLOWED_OBJECT_ACE,ACCESS_ALLOWED_ACE,ACCESS_DENIED_OBJECT_ACE,ACCESS_DENIED_ACE
from ldap3 import MODIFY_REPLACE,MODIFY_ADD
import base64
from uuid import UUID

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

def get_groups_filter(like = ''):
	filter = '(objectClass=group)'
	if like != '':
		filter = f'(& (name=*{like}*) {filter})'
	return filter

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

def get_add_user_to_group_operation(user):
	return { "member": [(MODIFY_ADD, [user])] }

def get_set_uac_operation(newuac):
	command = { "userAccountControl": [(MODIFY_REPLACE, [newuac])]}
	return command

def get_add_spn_operation(spn):
	command = {"servicePrincipalName": [(MODIFY_ADD, [spn])]}
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

# Note:
# leaning a lot on impacket for the parsing of the data structure,
# then mapping their more low level types to something human readable
def parse_security_descriptor(b64_ntsecuritydescriptor):
	# secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR()
	# secDesc.fromString(b64_ntsecuritydescriptor)
	# print(str(secDesc))

	# TODO: Almost perfect example of what I'm doing: https://github.com/the-useless-one/pywerview/blob/71e70889347f726dd9f9ba15f0d953bba07b9bd8/pywerview/functions/net.py#L68C1-L69C1
	print("START")
	print(b64_ntsecuritydescriptor)
	# secDesc2 = ldaptypes.SR_SECURITY_DESCRIPTOR() # Working w/ import ldaptypes
	secDesc2 = SR_SECURITY_DESCRIPTOR()
	#secDesc2.fromString(b64_ntsecuritydescriptor.values[0].decode("UTF-8"))
	secDesc2.fromString(base64.b64decode(b64_ntsecuritydescriptor))
	print(type(secDesc2['OwnerSid']))
	print(f"OwnerSid: {secDesc2['OwnerSid'].formatCanonical()}") # Works!  Just need way to display
	# TODO: if GroupSid then print that like ownersid
	# parse acls (just unless we're already admin I think?)
	# TODO: Sacl
	# Dacl

	dacl = secDesc2['Dacl']
	print(f"DACL - ace count? {dacl['AceCount']}")
	print(f"DACL - data? {dacl['Data']}")
	# daclaces = []
	# for i in range(dacl["AceCount"]):
	# 	ace = ACE(data=dacl['Data'])
	# 	daclaces.append(ace)
	# 	self['Data'] = dacl['Data'][ace['AceSize']:]
	# ***Note: interestingly, ['Data'] here is a list of impacket.ldap.ldaptypes.ACE's
	# Strongly implies that the fromString method is being called as part of the constructor
	# call, maybe because of how the type is specified?
	# could be base class struct behavior of calling fromString in constr? 
	for ace in dacl['Data']:
		# I think ace is already the subclass at this point 
		#mappedace = ACE_TYPE_MAP[ace['AceType']](data=ace['Ace'])
		body = { "Warning": "Not implemented" }
		mappedtype = ACE_TYPE_MAP[ace["AceType"]]

		# Already specific subclass, e.g. ACCESS_ALLOWED_OBJECT_ACE
		specificace = ace['Ace']
		print(f"particular ace: {type(specificace)}")
		if mappedtype == ACCESS_ALLOWED_ACE or mappedtype == ACCESS_DENIED_ACE:
			print(f"Parsing aaa or ada")
			print(f'fields: {specificace.__dict__}')
			impacketmask = specificace["Mask"]
			readablemask = AccessMask(specificace["Mask"])
			print(f'our mask: {readablemask}')
			body = {
				"mask": readablemask.flags,
				"sid": specificace["Sid"].formatCanonical()
			}
		if mappedtype == ACCESS_ALLOWED_OBJECT_ACE or mappedtype == ACCESS_DENIED_OBJECT_ACE:
			print(f"Parsing aaoa or adoa")
			print(f'fields: {specificace.__dict__}')
			# WORKS
			# print(f'mask: {specificace["Mask"]}')
			impacketmask = specificace["Mask"]
			readablemask = AccessMask(specificace["Mask"])
			print(f'our mask: {readablemask}')
			objflags = ObjectAceFlags(specificace["Flags"])
			print(f"object flags: {objflags.flags}")

			body = {
				"mask": readablemask.flags,
				"sid": specificace["Sid"].formatCanonical(), # TODO: Str?
				"objectflags": objflags.flags
				# TODO: Object type as string (e.g. extended rights convo below) if known / useful
				# TODO: Inheritance?  more to it?
				# TODO: this and objecttype only used if certain flags set. see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe?redirectedfrom=MSDN
			}

			if ObjectAceFlags.ACE_OBJECT_TYPE_PRESENT in objflags.flags:
				print(f"adding objecttype...")
				# TODO Object type as guid
				body["objecttype"] = str(UUID(bytes=specificace["ObjectType"]))
			if ObjectAceFlags.ACE_INHERITED_OBJECT_TYPE_PRESENT in objflags.flags:
				print(f"adding inheritedobjecttype...")
				# TODO Object type as guid
				body["inheritedobjecttype"] = str(UUID(bytes=specificace["InheritedObjectType"]))

		parsedflags = AceFlags(ace["AceFlags"])
		print(f'Type: {ace["AceType"]}')
		print(f'Flags: {parsedflags}')
		print(f'Body: {json.dumps(body)}')
		# Serialization of particular body

	    # ('AceType','B'),
        # ('AceFlags','B'),
        # ('AceSize','<H'),
        # # Virtual field to calculate data length from AceSize
        # ('AceLen', '_-Ace', 'self["AceSize"]-4'),
        # #
        # # ACE body, is parsed depending on the type
		# # NOTE: probably not gonna do all, especially because
		# # SOME HAVE DIFFERENT MASK MEANINGS
		# # - can consult file:///C:/Users/Christian/Downloads/Attacking%20Active%20Directory-%200%20to%200.9%20_%20zer1t0.pdf
		# # for which are most important 
		# # - also, https://github.com/the-useless-one/pywerview/blob/master/pywerview/formatters.py#L132C1-L133C1
		# # etc could help 
		# # 
		# # based off reading, seems like following are important:
		# # - Access_Allowed_ACE and Access_Allowed_Callback...
		# # - Access_Allowed_Object_ACE and Access_Allowed_callback...
		# #   * NOTE: For these it's particularly important that we 
		# #   map the object-type to the (popular, at least) object name
		# #   it corresponds to.  Based on pdf, seems like this is how extended rights works
		# #   (e.g. objecttype = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 means 
		# #   ds-replication-get-changes https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes)
		# #     - good example here using built in ad query: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync
		# # - Access_Denied and Object and Callbacks
        # # ***TODO***: verify these w/ icacls, pywerview/sharpsploit, etc
		# # - test case: Parent has ds-replication-get-changes and generic_all over brother
		# #   * note: might have to write these ourselves / w/ mimikatz
        # ('Ace',':')

	print("END")
# Flags specific to ACCESS_ALLOWED_OBJECT_ACE / ACCESS_DENIED_OBJECT_ACE
class ObjectAceFlags():
	ACE_OBJECT_TYPE_PRESENT = "ACE_OBJECT_TYPE_PRESENT"
	ACE_INHERITED_OBJECT_TYPE_PRESENT = "ACE_INHERITED_OBJECT_TYPE_PRESENT"
	bits_to_description = {
    	0x01: ACE_OBJECT_TYPE_PRESENT,
    	0x02: ACE_INHERITED_OBJECT_TYPE_PRESENT
	}

	def __init__(self, flagsasint):
		self.flagsasint = flagsasint
		self.flags = []
		for flag in self.bits_to_description.keys():
			if flag & flagsasint == flag:
				self.flags.append(self.bits_to_description[flag])

	def __str__(self):
		return json.dumps(self.flags)

class AceFlags():
	bits_to_description = {
		0x02 : "CONTAINER_INHERIT_ACE",
		0x80 : "FAILED_ACCESS_ACE_FLAG",
		0x08 : "INHERIT_ONLY_ACE",
		0x10 : "INHERITED_ACE",
		0x04 : "NO_PROPAGATE_INHERIT_ACE",
		0x01 : "OBJECT_INHERIT_ACE",
		0x40 : "SUCCESSFUL_ACCESS_ACE_FLAG"
	}
	# TODO: Compare w/: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe?redirectedfrom=MSDN
	# 2 tiers of flags?

	def __init__(self, flagsasint):
		self.flagsasint = flagsasint
		self.flags = []
		for flag in self.bits_to_description.keys():
			if flag & flagsasint == flag:
				self.flags.append(self.bits_to_description[flag])

	def __str__(self):
		return json.dumps(self.flags)


class AccessMask():
	bit_to_description = {
		0x80000000 : "GENERIC_READ",
		0x40000000 : "GENERIC_WRITE",
		0x20000000 : "GENERIC_EXECUTE",
		0x10000000 : "GENERIC_ALL",
		0x02000000 : "MAXIMUM_ALLOWED",
		0x01000000 : "ACCESS_SYSTEM_SECURITY",
		0x00100000 : "SYNCHRONIZE",
		0x00080000 : "WRITE_OWNER",
		0x00040000 : "WRITE_DACL",
		0x00020000 : "READ_CONTROL",
		0x00010000 : "DELETE",
		0x00000100 : "ADS_RIGHT_DS_CONTROL_ACCESS",
		0x00000001 : "ADS_RIGHT_DS_CREATE_CHILD",
		0x00000002 : "ADS_RIGHT_DS_DELETE_CHILD",
		0x00000010 : "ADS_RIGHT_DS_READ_PROP",
		0x00000020 : "ADS_RIGHT_DS_WRITE_PROP",
		0x00000008 : "ADS_RIGHT_DS_SELF",
	}

	def __init__(self, impacketaccessmask):
		# TODO: The appropriate term here is bitstring, right?
		# a bit mask would be something like (READ_CONTROL & WRITE_DACL)
		# that we would then use to modify / check those parts of a bitstring  
		self.impacketaccessmask = impacketaccessmask
		self.flags = []
		for flag in self.bit_to_description.keys():
			# TODO: Not working, endianness?  def as little endian long in impacket
			if impacketaccessmask.hasPriv(flag):
				self.flags.append(self.bit_to_description[flag])

	def __str__(self):
		return json.dumps(self.flags)

