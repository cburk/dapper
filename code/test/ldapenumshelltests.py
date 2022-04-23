import unittest
from unittest.mock import MagicMock, patch
from code.src.ldapenumshell import LDAPEnumShell 
import ldap3

class FakeConnection():
	closed=False

	

	def unbind():
		print("Hello world")
	

def raise_exception(e):
	raise e

class TestEnumerationMethods(unittest.TestCase):
	def test_dispose(self):
		mockconnection=MagicMock()
		mockconnection.closed=False
		mockconnection.search = lambda search_base,search_filter,search_scope,attributes: raise_exception(ldap3.core.exceptions.LDAPSocketOpenError())

		#shell=LDAPEnumShell(hostip=args.hostip, hostdomain=args.hostdomain, port="111", username=args.username, password=args.password, create_connection=lambda ip,host,port,user,password: "asdf")
		shell=LDAPEnumShell("1.2.3.4","a.b.c","111",None,None,lambda ip,host,port,user,password: mockconnection)
		shell.onecmd("enum_users")

		mockconnection.unbind.assert_called()

if __name__ == '__main__':
	unittest.main()