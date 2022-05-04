#!/usr/bin/env python3
import json

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
