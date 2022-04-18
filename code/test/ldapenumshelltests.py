import unittest
from code.src.ldapenumshell import LDAPEnumShell 

class TestEnumerationMethods(unittest.TestCase):

    def test_dispose(self):
        self.assertEqual('foo'.upper(), 'bbb')


if __name__ == '__main__':
    unittest.main()