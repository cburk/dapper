import unittest
from code.src.queryformatter import response_properties_subset 
import json

class TestDisposal(unittest.TestCase):
	def test_response_properties_subset_happypath(self):
		obj = json.dumps({"entries": [{"attributes": {
			"a":"b",
			"c":["d","e"],
			"d":"shouldntbereturned"
		}}]})
		res = response_properties_subset(obj, ["a","c"])

		self.assertTrue(res[0]["a"] == "b")
		self.assertTrue(len(res[0]["c"]) == 2)
		self.assertTrue("d" not in res[0].keys())
		
	def test_response_properties_subset_handlenonexistent(self):
		try:
			obj = json.dumps({"entries": [{"attributes": {
				"a":"b",
				"c":"d"
			}}]})
			res = response_properties_subset(obj, ["a","doesnotexist"])
		except Exception as e:
			self.fail(f"response formatting should've ignored nonexistent properties, instead threw exception {e}")

		self.assertTrue(res[0]["a"] == "b")
		
if __name__ == '__main__':
	unittest.main()
