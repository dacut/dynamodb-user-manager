"""\
Utility for exporting user/group files to DynamoDB
Usage: {argv0} [options]

Options:
    -h | --help
        Show this usage information.

    --passwd <filename> | --password <filename>
        Read password file from <filename> instead of {PASSWD_FILE}.

    --no-passwd | --no-password
        Skip reading the password file. If specified, this also skips reading
        the shadow file and exporting any users.

    --shadow <filename>
        Read shadow password file from <filename> instead of {SHADOW_FILE}.

    --no-shadow
        Skip reading the shadow password file.

    --group <filename>
        Read group file from <filename> intead of {GROUP_FILE}.

    --no-group
        Skip reading the group file. If specified, this also skips reading the
        gshadow file and exporting any groups.

    --gshadow <filename>
        Read group shadow password file from <filename> instead of
        {GSHADOW_FILE}.

    --no-gshadow
        Skip reading the group shadow password file.

    --user-table <name>
        Write users to this DynamoDB table.

    --group-table <name>
        Write groups to this DynamoDB table.

    --region <region>
        Use the specified AWS region.

    --profile <profile>
        Use the specified profile from ~/.aws/credentials.
"""
# pylint: disable=C0103,R0912,R0914,R0915
from getopt import getopt, GetoptError
from sys import argv, stdout, stderr
from time import time
from typing import Any, Dict, Optional, Sequence, TextIO
from boto3.session import Session
import botocore # pylint: disable=W0611
from botocore.exceptions import ClientError
from .constants import GROUP_FILE, GSHADOW_FILE, PASSWD_FILE, SHADOW_FILE
from .group import Group
from .shadow import ShadowDatabase
from .user import User

def user_to_dynamodb_item(user: User) -> Dict[str, Any]:
    """
    Convert a User to a dict item for insertion into DynamoDB.
    """
    item = {
        "Name": {"S": user.name},
        "UID": {"N": str(user.uid)},
        "GID": {"N": str(user.gid)},
    }

    # Empty strings cannot be stored in DynamoDB.

    if user.home:
        item["Home"] = {"S": user.home}

    if user.shell:
        item["Shell"] = {"S": user.shell}

    if user.real_name:
        item["RealName"] = {"S": user.real_name}

    if user.password:
        item["Password"] = {"S": user.password}

    if user.last_password_change_date is not None:
        item["LastPasswordChangeDate"] = {
            "S": user.last_password_change_date.isoformat()
        }

    if user.password_age_min_days is not None:
        item["PasswordAgeMinDays"] = {"N": str(user.password_age_min_days)}

    if user.password_age_max_days is not None:
        item["PasswordAgeMaxDays"] = {"N": str(user.password_age_max_days)}

    if user.password_warn_days is not None:
        item["PasswordWarnDays"] = {"N": str(user.password_warn_days)}

    if user.account_expire_date is not None:
        item["AccountExpireDate"] = {"S": user.account_expire_date.isoformat()}

    if user.ssh_public_keys:
        item["SSHPublicKeys"] = {"SS": list(user.ssh_public_keys)}

    return item

def group_to_dynamodb_item(group: Group) -> Dict[str, Any]:
    """
    Convert a Group to a dict item for insertion into DynamoDB.
    """
    item = {
        "Name": {"S": group.name},
        "GID": {"N": str(group.gid)},
    }

    if group.password is not None:
        item["Password"] = {"S": group.password}

    if group.administrators:
        item["Administrators"] = {"SS": list(group.administrators)}

    if group.members:
        item["Members"] = {"SS": list(group.members)}

    return item

def main(args: Optional[Sequence[str]] = None) -> int:
    """
    main(args: Optional[Sequence[str]]) -> int
    Main entry point of the export program.
    """
    passwd_file: Optional[str] = PASSWD_FILE
    shadow_file: Optional[str] = SHADOW_FILE
    group_file: Optional[str] = GROUP_FILE
    gshadow_file: Optional[str] = GSHADOW_FILE
    users_table: Optional[str] = None
    groups_table: Optional[str] = None
    boto_kw: Dict[str, Any] = {}

    if args is None:
        args = argv[1:]

    try:
        opts, args = getopt(
            list(args), "h",
            ["help", "passwd=", "password=", "no-passwd", "no-password",
             "shadow=", "no-shadow", "group=", "gshadow=", "no-gshadow",
             "users-table=", "groups-table=", "region=", "profile="])

        for opt, val in opts:
            if opt in ("-h", "--help",):
                usage(stdout)
                return 0

            if opt in ("--passwd", "--password",):
                passwd_file = val

            if opt in ("--no-passwd", "--no-password",):
                passwd_file = None

            if opt == "--shadow":
                shadow_file = val

            if opt == "--no-shadow":
                shadow_file = None

            if opt == "--group":
                group_file = val

            if opt == "--no-group":
                group_file = None

            if opt == "--gshadow":
                gshadow_file = val

            if opt == "--no-gshadow":
                gshadow_file = None

            if opt == "--users-table":
                users_table = val

            if opt == "--groups-table":
                groups_table = val

            if opt == "--region":
                boto_kw["region_name"] = val

            if opt == "--profile":
                boto_kw["profile_name"] = val

    except GetoptError as e:
        print(str(e), file=stderr)
        return 1

    if args:
        print(f"Unknown argument {args[0]}", file=stderr)
        usage()
        return 1

    start = time()
    shadow_db = ShadowDatabase(skip_load=True)
    if passwd_file is not None:
        shadow_db.load_passwd_file(passwd_file)
        if shadow_file is not None:
            shadow_db.load_gshadow_file(shadow_file)

    if group_file is not None:
        shadow_db.load_group_file(group_file)
        if gshadow_file is not None:
            shadow_db.load_gshadow_file(gshadow_file)
    elapsed = "%.2f" % (time() - start)
    print(f"Imported {len(shadow_db.users)} user(s) and "
          f"{len(shadow_db.groups)} group(s) in {elapsed} s.")

    ddb = Session(**boto_kw).client("dynamodb")
    users_exported = groups_exported = 0

    start = time()
    if passwd_file is not None and users_table is not None:
        for user in shadow_db.users.values():
            item = user_to_dynamodb_item(user)
            try:
                ddb.put_item(Item=item, TableName=users_table)
                users_exported += 1
            except ClientError as e:
                print(f"Failed to export {user.name}: item={item}: {e}",
                      file=stderr)

    if group_file is not None and groups_table is not None:
        for group in shadow_db.groups.values():
            item = group_to_dynamodb_item(group)
            try:
                ddb.put_item(Item=item, TableName=groups_table)
                groups_exported += 1
            except ClientError as e:
                print(f"Failed to export {group.name}: item={item}: {e}",
                      file=stderr)
    elapsed = "%.2f" % (time() - start)

    print(f"Exported {users_exported} user(s) and {groups_exported} "
          f"group(s) in {elapsed} s.")

    return 0

def usage(fd: TextIO = stderr) -> None:
    """
    Print usage information to the specified descriptor.
    """
    fd.write(__doc__.format(argv0=argv[0]))
    fd.flush()
