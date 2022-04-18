#!/usr/bin/env python3

def format_ldap_domain_components(domainName):
	domains=domainName.split(".")
	formatted_domains = [f"DC={x}" for x in domains]
	ldapstr = ",".join(formatted_domains)
	print(ldapstr)
	return ldapstr