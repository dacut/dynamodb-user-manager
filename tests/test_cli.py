#!/usr/bin/env python3
# pylint: disable=redefined-builtin,missing-docstring
from io import StringIO
from unittest import TestCase

class TestCLI(TestCase):
    def test_usage(self):
        from dynamodbusermanager.cli import usage
        help_writer = StringIO()

        usage(help_writer)
        help = help_writer.getvalue()
        self.assertTrue(help.startswith("DynamoDB User Manager Daemon\n"))
