import unittest
from unittest.mock import MagicMock, Mock, patch, ANY, call
from code.src.ldapenumshell import LDAPEnumShell, find_args
from code.src.queryformatter import format_ldap_domain_components, response_properties_subset
import ldap3
import io
import sys
import json

def raise_exception(e):
	raise e

class TestArgsFormatter(unittest.TestCase):
	def test_one_arg(self):
		aval = "has spaces and stuff"
		argstr = f"-a {aval}"
		
		res = find_args(["-a","-b"], argstr)
		
		self.assertTrue(res["-a"] == aval)
		self.assertFalse("-b" in res.keys())
		
	def test_multi_arg(self):
		aval = "has spaces and stuff"
		bval = "more-standard"
		argstr = f"-b {bval} -a {aval}"
		
		res = find_args(["-a","-b"], argstr)
		
		self.assertTrue(res["-a"] == aval)
		self.assertTrue(res["-b"] == bval)

	def test_whitespace(self):
		aval = "onlythismatters"
		argstr = f" -a       {aval}   "
		
		res = find_args(["-a","-b"], argstr)
		
		self.assertTrue(res["-a"] == aval)
		
class TestDisposal(unittest.TestCase):
	def test_dispose_on_error(self):
		mockconnection=MagicMock()
		mockconnection.closed=False
		mockconnection.server.info.other = { "rootDomainNamingContext": ["c.d.e"] }
		mockconnection.search = lambda search_base,search_filter,search_scope,attributes: raise_exception(ldap3.core.exceptions.LDAPSocketOpenError("assertexceptioninternalmessage"))

		capturedOutput = io.StringIO()          # For capturing print output
		sys.stdout = capturedOutput                   

		shell=LDAPEnumShell("a.b.c",mockconnection,MagicMock())
		shell.onecmd("enum_users")

		mockconnection.unbind.assert_called()

		self.assertTrue("assertexceptioninternalmessage" in capturedOutput.getvalue())
		sys.stdout = sys.__stdout__                   # Reset redirect.

	def test_dispose_on_quit(self):
		mockconnection=MagicMock()
		mockconnection.closed=False
		mockconnection.server.info.other = { "rootDomainNamingContext": ["c.d.e"] }

		shell=LDAPEnumShell("a.b.c",mockconnection,MagicMock())
		shell.onecmd("quit")

		mockconnection.unbind.assert_called()


class TestSearch(unittest.TestCase):
	def test_enum_users_should_formatrequestproperly_serverrootdomaincomponents(self):
		serverrootdomaincomponents = "c.d.e"		

		actualcall={}
		mockconnection=MagicMock()
		mockconnection.closed=False
		searchmock=MagicMock()
		mockconnection.server.info.other = { "rootDomainNamingContext": [serverrootdomaincomponents] }
		searchres = '{ "entries": [{ "attributes": { "description": "helloworld" }}] }'
		mockconnection.response_to_json = Mock(return_value=searchres)
		mocklogger = MagicMock()

		domain="a.b.c"
		shell=LDAPEnumShell(domain,mockconnection,mocklogger)
		shell.onecmd("enum_users")

		mapped = response_properties_subset(searchres,["userAccountControl","sAMAccountName","userPrincipalName","description","memberOf"])
		expectedoutput = json.dumps(mapped, indent=4)

		self.assertTrue(mocklogger.print.call_args[0][0] == expectedoutput)
		mockconnection.search.assert_called_with(search_base=serverrootdomaincomponents,search_filter="(&(objectClass=user)(objectClass=person))",search_scope=ANY, attributes=ANY)
		# TODO: For more complex tests: https://ldap3.readthedocs.io/en/latest/mocking.html

	def test_enum_users_should_formatrequestproperly_domainformatteddomaincomponents(self):
		actualcall={}
		mockconnection=Mock()
		mockconnection.closed=False
		mockconnection.server.info = None
		searchres = '{ "entries": [{ "attributes": { "description": "helloworld" }}] }'
		mockconnection.response_to_json = Mock(return_value=searchres)

		domain="a.b.c"
		shell=LDAPEnumShell(domain,mockconnection,MagicMock())
		shell.onecmd("enum_users")

		mockconnection.search.assert_called_with(search_base=format_ldap_domain_components(domain),search_filter="(&(objectClass=user)(objectClass=person))",search_scope=ANY, attributes=ANY)

		# TODO: For more complex tests: https://ldap3.readthedocs.io/en/latest/mocking.html

if __name__ == '__main__':
	unittest.main()


