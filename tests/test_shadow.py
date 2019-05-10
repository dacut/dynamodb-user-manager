#!/usr/bin/env python3
from datetime import date
from unittest import TestCase
from dynamodbusermanager.shadow import ShadowDatabase

EPOCH = date(1970, 1, 1)

class ShadowTest(TestCase):
    def test_load(self):
        sdb = ShadowDatabase()
        print(sdb.users.values())
