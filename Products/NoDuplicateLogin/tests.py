import unittest

from Products.CMFPlone.tests import PloneTestCase

PloneTestCase.setupPloneSite()

class DoStuffWithUnitTest(unittest.TestCase):
    def setUp(self):
        pass

    def testFoo(self):
        pass

class DoStuffWithPTC(PloneTestCase.PloneTestCase):
    def setUp(self):
        pass

    def testFoo(self):
        pass
