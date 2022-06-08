import unittest

from gigue.method import Method


class MethodTest(unittest.TestCase):

    def test_initialization(self):
        method = Method(size=12, address=0x7FFFFF, call_number=15, registers=[])
        self.assertEqual(method.size, 12)
        self.assertEqual(method.address, 0x7FFFFF)
        self.assertEqual(method.call_number, 15)


if __name__ == "__main__":
    unittest.main()
