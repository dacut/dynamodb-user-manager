"""
Daemon for keeping users in-sync with the DynamoDB table.
"""
from logging import getLogger
from random import randint
from time import sleep
from typing import Any, Dict
import botocore # pylint: disable=W0611
from .constants import (
    KEY_FULL_UPDATE_JITTER, KEY_FULL_UPDATE_PERIOD,
    KEY_GROUP_TABLE_NAME, KEY_USER_TABLE_NAME)
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
            self, ddb: "botocore.client.DynamoDB", config: Dict[str, Any]) -> None:
        """
        Daemon(ddb: botocore.client.DynamoDB, user_table_name: str, group_table_name: str) -> Daemon
        Create a new Daemon for keeping users up-to-date.
        """
        super(Daemon, self).__init__()
        self.ddb = ddb
        self.config = config
        self.shadow = ShadowDatabase()
        self.dynamodb_users = {} # type: Dict[str, User]
        self.dynamodb_groups = {} # type: Dict[str, Group]

    def reload_users(self) -> None:
        """
        daemon.load_users() -> None
        Reload the entire users table.
        """
        table_name = self.config.get(KEY_USER_TABLE_NAME, "Users")
        log.info("Reloading users from DynamoDB table %s", table_name)

        users = {} # type: Dict[str, User]
        paginator = self.ddb.get_paginator("scan")
        page_iterator = paginator.paginate(
            TableName=table_name, ConsistentRead=True)

        # We rely entirely on the Boto3 client to retry failed reads here.
        for page in page_iterator:
            items = page.get("Items", [])
            for item in items:
                username = item["Name"]["S"]
                assert username not in users

                user = self.shadow.users.get(username)
                if user is None:
                    user = User.from_dynamodb_item(item)
                    self.shadow.users[username] = user
                else:
                    user.update_from_dynamodb_item(item)

                users[username] = user

        self.dynamodb_users = users

    def reload_groups(self) -> None:
        """
        daemon.reload_groups() -> None
        Reload the entire groups table.
        """
        table_name = self.config.get(KEY_GROUP_TABLE_NAME, "Groups")
        log.info("Reloading groups from DynamoDB table %s", table_name)

        groups = {} # type: Dict[str, Group]
        paginator = self.ddb.get_paginator("scan")
        page_iterator = paginator.paginate(
            TableName=table_name, ConsistentRead=True)

        # We rely entirely on the Boto3 client to retry failed reads here.
        for page in page_iterator:
            items = page.get("Items", [])
            for item in items:
                groupname = item["Name"]["S"]
                assert groupname not in groups

                group = self.shadow.groups.get(groupname)
                if group is None:
                    group = Group.from_dynamodb_item(item)
                    self.shadow.groups[groupname] = group
                else:
                    group.update_from_dynamodb_item(item)

                groups[groupname] = group

        self.dynamodb_groups = groups

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
        if self.shadow.modified:
            log.info("Shadow database modified; rewriting")
            self.shadow.write()

        # For each DynamoDB user, make sure they have a valid home and ssh keys.
        for user in self.dynamodb_users.values():
            try:
                self.shadow.create_user_home(user)
                self.shadow.write_user_ssh_keys(user)
            except Exception as e: # pylint: disable=W0703
                log.error("Failed to create/update user %s: %s", user.name, e,
                          exc_info=True)

    def main_loop(self) -> None:
        """
        daemon.main_loop() -> None
        Run continuously until interrupted, polling the DynamoDB table and
        rewriting the shadow files (if needed) periodicially.

        The periodicity is controlled by the following config keys:
            full_update_period <int>
                The interval, in seconds, between polls. If unspecified, this
                defaults to 3600 seconds (1 hour).

            full_update_jitter <int>
                Maximum jitter, in seconds, to add to the period. This prevents
                many instances of DynamoDBUserManager from simultaneously
                overloading DynamoDB. If unspecified, this defaults to
                600 seconds (10 minutes)
        """
        log.info("Starting main_loop")
        while True:
            jitter_max = self.config.get(KEY_FULL_UPDATE_JITTER, 600)
            jitter = randint(0, jitter_max)
            log.info(
                "Jitter sleeping for %d seconds (of %d maximum)", jitter,
                jitter_max)

            sleep(jitter)

            log.info("Executing full update")
            try:
                self.full_update()
                log.info("Full update completed successfully")
            except Exception as e: # pylint: disable=W0703
                log.error("Full update failed: %s", e, exc_info=True)

            period = self.config.get(KEY_FULL_UPDATE_PERIOD)
            log.info("Regular sleeping for %d seconds", period)
            sleep(period)

            # For testing purposes
            self.main_loop_done_hook()

    def main_loop_done_hook(self) -> Any: # pragma: nocover
        """
        daemon.main_loop_done_hook() -> None
        Hook method called at the end of main_loop. Not used except in unit
        tests as an escape hatch.
        """
        # pylint: disable=R0201
        return
