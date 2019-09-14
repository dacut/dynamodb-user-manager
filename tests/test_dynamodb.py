#!/usr/bin/env python3
from logging import getLogger, Formatter, DEBUG, WARNING
from os import stat
from os.path import exists
from unittest import TestCase
import boto3
from moto import mock_dynamodb2

from dynamodbusermanager.daemon import Daemon
from dynamodbusermanager.cli import parse_config

DUMMY_KEY_1 = """\
ssh-rsa EXAMPLEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA== \
example@example.com"""

class DynamoDBTest(TestCase):
    def setUp(self):
        rootLogger = getLogger()
        fmt = Formatter(fmt="%(levelname)-8s %(name)s %(filename)s %(lineno)d: %(message)s")
        rootLogger.handlers[0].setFormatter(fmt)
        rootLogger.setLevel(DEBUG)
        getLogger("botocore").setLevel(WARNING)
        getLogger("botocore.handlers").setLevel(WARNING)
        getLogger("botocore.hooks").setLevel(WARNING)
        getLogger("boto3").setLevel(WARNING)

    @mock_dynamodb2
    def test_scan(self):
        ddb = boto3.client("dynamodb", region_name="us-east-2") # type: "botocore.client.DynamoDB"
        ddb.create_table(
            TableName="Groups",
            AttributeDefinitions=[
                {"AttributeName": "Name", "AttributeType": "S"},
                {"AttributeName": "GID", "AttributeType": "N"},
            ],
            KeySchema=[{"AttributeName": "Name", "KeyType": "HASH"}],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GIDIndex",
                    "KeySchema": [{"AttributeName": "GID", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    }
                }
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            }
        )
        ddb.put_item(
            TableName="Groups",
            Item={
                "Name": {"S": "testscan1"},
                "GID": {"N": "6001"},
                "Members": {"SS": ["testscan1"]},
            }
        )
        ddb.put_item(
            TableName="Groups",
            Item={
                "Name": {"S": "testscan2"},
                "GID": {"N": "6002"},
                "Members": {"SS": ["testscan2"]},
            }
        )

        ddb.create_table(
            TableName="Users",
            AttributeDefinitions=[
                {"AttributeName": "Name", "AttributeType": "S"},
                {"AttributeName": "UID", "AttributeType": "N"},
            ],
            KeySchema=[{"AttributeName": "Name", "KeyType": "HASH"}],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "UIDIndex",
                    "KeySchema": [{"AttributeName": "UID", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    }
                }
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            }
        )
        ddb.put_item(
            TableName="Users",
            Item={
                "Name": {"S": "testscan1"},
                "UID": {"N": "6001"},
                "GID": {"N": "6001"},
                "RealName": {"S": "Test User 6001"},
                "Home": {"S": "/home/testscan1"},
                "Shell": {"S": "/bin/bash"},
                "LastPasswordChangeDate": {"S": "2019-01-01"},
                "PasswordAgeMinDays": {"N": "2"},
                "PasswordAgeMaxDays": {"N": "90"},
                "PasswordWarnDays": {"N": "15"},
                "PasswordDisableDays": {"N": "0"},
                "AccountExpireDate": {"S": "2025-01-01"},
                "SSHPublicKeys": {"SS": [DUMMY_KEY_1]},
            }
        )
        ddb.put_item(
            TableName="Users",
            Item={
                "Name": {"S": "testscan2"},
                "UID": {"N": "6002"},
                "GID": {"N": "6002"},
                "RealName": {"S": "Test User 6002"},
                "Home": {"S": "/home/testscan2"},
                "Shell": {"S": "/bin/bash"},
                "LastPasswordChangeDate": {"S": "2019-01-01"},
                "PasswordAgeMinDays": {"N": "2"},
                "PasswordAgeMaxDays": {"N": "90"},
                "PasswordWarnDays": {"N": "15"},
                "PasswordDisableDays": {"N": "0"},
                "AccountExpireDate": {"S": "2025-01-01"},
                "SSHPublicKeys": {"SS": [DUMMY_KEY_1]},
            }
        )

        ddb.put_item(
            TableName="Users",
            Item={
                "Name": {"S": "testscan3"},
                "UID": {"N": "6003"},
                "GID": {"N": "6003"},
            }
        )

        with open("/etc/dynamodb-user-manager.cfg", "w") as fd:
            fd.write("""\
{
    "full_update_jitter": 2,
    "full_update_period": 1,
    "group_table_name": "Groups",
    "user_table_name": "Users"
}
""")

        config = parse_config()
        daemon = Daemon(ddb, config=config)

        class TestDone(Exception):
            pass

        def exit_loop(*args):
            raise TestDone()

        daemon.main_loop_done_hook = exit_loop
        try:
            daemon.main_loop()
        except TestDone:
            pass

        self.assertTrue(exists("/home/testscan1"), "/home/testscan1 missing")
        s = stat("/home/testscan1")
        self.assertEqual(
            s.st_uid, 6001, f"Expected testscan1 to own /home/testscan1: owner={s.st_uid}")

        self.assertTrue(
            exists("/home/testscan1/.ssh/authorized_keys"),
            "/home/testscan1/.ssh/authorized_keys missing")
        with open("/home/testscan1/.ssh/authorized_keys", "r") as fd:
            key = fd.read().strip()
            self.assertEqual(key, DUMMY_KEY_1)

        # Make sure the user with the empty home, shell, and real name was
        # created.
        with open("/etc/passwd", "r") as fd:
            self.assertIn("testscan3:", fd.read())
