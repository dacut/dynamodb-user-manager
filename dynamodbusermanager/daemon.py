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

    def __init__(
            self, ddb: "botocore.client.DynamoDB", user_table_name: str,
            group_table_name: str) -> None:
        """
Daemon(ddb: botocore.client.DynamoDB, user_table_name: str, group_table_name: str) -> Daemon
Create a new Daemon for keeping users up-to-date.
        """
        super(Daemon, self).__init__()
        self.ddb = ddb
        self.user_table_name = user_table_name
        self.group_table_name = group_table_name
        self.shadow = ShadowDatabase()
        self.dynamodb_users = {} # type: Dict[str, User]
        self.dynamodb_groups = {} # type: Dict[str, Group]

    def reload_users(self) -> None:
        """
        daemon.load_users() -> None
        Reload the entire users table.
        """
        self.dynamodb_users.clear()
        paginator = self.ddb.get_paginator("scan")
        page_iterator = paginator.paginate(
            TableName=self.user_table_name, ConsistentRead=True)

        # We rely entirely on the Boto3 client to retry failed reads here.
        for page in page_iterator:
            items = page.get("Items", [])
            for item in items:
                username = item["Name"]["S"]
                assert username not in self.dynamodb_users

                user = self.shadow.users.get(username)
                if user is None:
                    user = User.from_dynamodb_item(item)
                    self.shadow.users[username] = user
                else:
                    user.update_from_dynamodb_item(item)

                self.dynamodb_users[username] = user

    def reload_groups(self) -> None:
        """
        daemon.reload_groups() -> None
        Reload the entire groups table.
        """
        self.dynamodb_groups.clear()
        paginator = self.ddb.get_paginator("scan")
        page_iterator = paginator.paginate(
            TableName=self.group_table_name, ConsistentRead=True)

        # We rely entirely on the Boto3 client to retry failed reads here.
        for page in page_iterator:
            items = page.get("Items", [])
            for item in items:
                groupname = item["Name"]["S"]
                assert groupname not in self.dynamodb_groups

                group = self.shadow.groups.get(groupname)
                if group is None:
                    group = Group.from_dynamodb_item(item)
                    self.shadow.groups[groupname] = group
                else:
                    group.update_from_dynamodb_item(item)

                self.dynamodb_groups[groupname] = group

    def full_update(self) -> None:
        """
        daemon.full_update()
        Perform a full update by scanning the entire DynamoDB table and adding
        users who exist in DynamoDB but not locally, deleting users who exist
        locally but not in DynamoDB, and updating any users who exist in both
        repositories.
        """
        # First, refetch everything from DynamoDB
        self.reload_groups()
        self.reload_users()

        # Rewrite the /etc/group, /etc/passwd, /etc/gshadow, and
        # /etc/shadow files.
        self.shadow.write()

        # For each DynamoDB user, make sure they have a valid home and ssh keys.
        for user in self.dynamodb_users.values():
            self.shadow.create_user_home(user)
            self.shadow.write_user_ssh_keys(user)
