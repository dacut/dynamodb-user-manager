# DynamoDB User Manager
Manage Linux users from DynamoDB.

This module runs as a daemon that periodically scans a pair of DynamoDB tables
for user and group information and updates the local password/shadow password
files for users and groups. This is done so there are no network dependencies
in the PAM chain -- the goal is to allow administrators to continue to log in
even when the network is adversely affected.

When installed via setup.py using the defaults, a daemon script installed as
`/usr/local/bin/dynamodb-user-manager`.

# Configuration
Configuring the daemon requires a JSON configuration file; by default, this is
`/etc/dynamodb-user-manager.cfg`. You can override this with the `--config`
flag to `dynamodb-user-manager`.

The configuration file is a JSON document in the form:

```json
{
    "aws_access_key": "AKIDEXAMPLE",
    "aws_profile": "default",
    "aws_region": "us-east-1",
    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    "aws_session_token": "",
    "full_update_jitter": 600,
    "full_update_period": 3600,
    "group_table_name": "Groups",
    "user_table_name": "Users",
    "logging": {
        "version": 1,
        ...
    }
}
```

The valid configuration keys are:

* `aws_access_key` / `aws_secret_key` / `aws_session_token` / `aws_profile` (str)
    Static AWS credentials to use.

    If aws_access_key and aws_secret_key (and, optionally,
    aws_session_token) are specified, these are fed directly into Boto and
    will be used.

    Otherwise, if aws_profile is specified, this is fed into Boto, which
    reads the the credentials from ~/.aws/credentials (usually the root
    user).

    On EC2 instances, these parameters should not be used. Boto will fetch
    the credentials from the EC2 instance metadata.
* `aws_region` (str)
    The AWS region to use. If unspecified, this uses the first value found
    from:
        The environment variable `AWS_REGION`
        The environment variable `AWS_DEFAULT_REGION`
        If running on EC2, the EC2 instance metadata.
        `"us-east-1"`
* `full_update_period` / `full_update_jitter` (int)
    The time, in seconds, between polls of the DynamoDB tables. The wait
    period is always used, plus a random value from 0 to `full_update_jitter`
    is selected; this helps distribute the load on the DynamoDB tables when
    run across multiple instances.

    The default is 3600 seconds (1 hour) for full_update_period, and
    600 seconds (10 minutes) for full_update_jitter.
* `group_table_name` (str)
    The name of the DynamoDB table to use to fetch for groups. This defaults
    to `"Groups"`.
* `user_table_name` (str)
    The name of the DynamoDB table to use to fetch for users. This defaults
    to `"Users"`.
* `logging` (dict)
    If present, this is passed to the Python configuration function
    [`logging.config.dictConfig`](http://bit.ly/2JROo0t).

# Field restrictions
Linux does not have a well-defined set of rules for what can appear in various
fields -- a lot depends on the internal implementation of various libraries.

DynamoDB User Manager imposes the following restrictions:

*   User and group names: 1-256 ASCII characters. Valid characters are
    letters, digits, period, underscore, and hyphen; the hyphen cannot be the
    first character of the name. (See [POSIX 3.437](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_437),
    [portable filename character set](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_282), [`LOGIN_NAME_MAX`](https://linux.die.net/man/3/sysconf).)
*   GECOS (realname, office, phone, etc): 256 characters, since 512
    characters is a commonly used buffer size for the entire passwd line.
    Colons, newlines, vertical tabs, formfeeds, and the NUL character are
    disallowed. This is interpreted as Unicode and written in UTF-8 locally,
    though most libraries handle this field as bytes with no well-defined
    encoding.

# Users table
The users table has the following schema. (DynamoDB type codes: `S` = string; `N` = number; `SS` = string set)

Field                    | Key          | Type | Required | Description
-------------------------|--------------|-----|-----|----
`Name`                   | PartitionKey | `S` | Yes | The name of the user. Must be unique (enforced by DynamoDB).
`UID`                    |              | `N` | Yes | The user id of the user. Must be an integer (enforced) and unique (not enforced).
`GID`                    |              | `N` | Yes | The primary group id of the user. Must be an integer (enforced).
`RealName`               |              | `S` | Yes | The GECOS field for the user, usually the real name.
`Home`                   |              | `S` | Yes | The home directory of the user.
`Shell`                  |              | `S` | Yes | The login shell for the user.
`Password`               |              | `S` | No  | The encrypted password for the user. If not specified, the user cannot login using a password.
`LastPasswordChangeDate` |              | `S` | No  | The date when the user last changed their password in ISO 8601 (YYYY-MM-DD) format.
`PasswordAgeMinDays`     |              | `N` | No  | The minimum age of the users's password (in days) before it can be changed. Must be an integer if specified.
`PasswordAgeMaxDays`     |              | `N` | No  | The maximum age of the users's password (in days) before it must be changed. Must be an integer if specified.
`PasswordWarnDays`       |              | `N` | No  | The number of days to warn the user before `PasswordAgeMaxDays` that their password is about to expire.
`PasswordDisableDays`    |              | `N` | No  | The number of days after `PasswordAgeMaxDays` to disable the user's password (requiring them to find an administrator to reset it).
`AccountExpireDate`      |              | `S` | No  | The date when the account is to be disabled in ISO 8601 (YYYY-MM-DD) format. This is similar to removing the account from `/etc/passwd` but preserves name information.
`SSHPublicKeys`          |              | `SS` | No | A list of SSH public keys the user can use to log in. These are written to the user's `~/.ssh/authorized_keys` file.

# Groups table
The groups table has the following schema. (DynamoDB type codes: `S` = string; `N` = number; `SS` = string set)


Field             | Key          | Type | Required | Description
------------------|--------------|--------------|----------|----
`Name`            | PartitionKey | `S` | Yes  | The name of the group. Must be unique (enforced by DynamoDB).
`GID`             |              | `N` | Yes  | The group id of the group. Must be an integer (enforced) and unique (not enforced).
`Password`        |              | `S` | No   | The encrypted password used to get access to the group via the `newgrp` command. Not commonly used.
`Administrators`  |              | `SS` | No  | A list of user names who can modify the group membership.
`Members`         |              | `SS` | No  | A list of user names who are members of the group.
