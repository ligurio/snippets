from __future__ import print_function

import unittest


def sum(a, b):

    return a+b


def setUpModule():
    print("setup module")


def tearDownModule():
    print("teardown module")


class TestTestres(unittest.TestCase):

    def setUp(self):
        print("setUp")
        self.a = 10
        self.b = 20

    def tearDown(self):
        print("tearDown")
        del self.a
        del self.b

    @classmethod
    def setUpClass(cls):
        print("setUpClass")

    @classmethod
    def tearDownClass(cls):
        print("tearDownClass")

    def test_sum_assert_equal(self):
        self.assertEqual(sum(self.a, self.b), 30)

    def test_sum_assert_true(self):
        self.assertTrue(sum(self.a, self.b) == 30)


if __name__ == "__main__":
    unittest.main()
