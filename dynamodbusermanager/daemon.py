"""
Daemon for keeping users in-sync with the DynamoDB table.
"""
from logging import getLogger
from typing import Dict, Set
import botocore # pylint: disable=W0611
from .group import Group
from .shadow import ShadowDatabase
from .user import User

# pylint: disable=C0103

log = getLogger(__name__)

class Daemon():
    """
    Runtime daemon for process control.
    """

    def __init__(self, ddb: "botocore.client.DynamoDB", table_name: str) -> None:
        """
        Daemon(ddb: botocore.client.DynamoDB, table_name: str) -> Daemon
        Create a new Daemon for keeping users up-to-date.
        """
        super(Daemon, self).__init__()
        self.ddb = ddb
        self.table_name = table_name
        self.shadow = ShadowDatabase()

    def full_update(self) -> None:
        """
        daemon.full_update()
        Perform a full update by scanning the entire DynamoDB table and adding
        users who exist in DynamoDB but not locally, deleting users who exist
        locally but not in DynamoDB, and updating any users who exist in both
        repositories.
        """
        # We rely entirely on the Boto3 client to retry failed reads here.
        paginator = self.ddb.get_paginator("scan")
        page_iterator = paginator.paginate(
            TableName=self.table_name, ConsistentRead=True)

        dynamodb_users = {}     # type: Dict[str, User]

        # Fetch all of the users from DynamoDB before doing anything.
        for page in page_iterator:
            items = page.get("Items", [])
            for item in items:
                username = item["Username"]
                assert username not in dynamodb_users

                user = self.shadow.users.get(username)
                if user is None:
                    user = User.from_dynamodb_item(item)
                    self.shadow.users[username] = user
                else:
                    user.update_from_dynamodb_item(item)
