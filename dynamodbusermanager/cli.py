#!/usr/bin/env python3
"""\
DynamoDB User Manager Daemon
Usage: {argv0} [options]

Options:
    -h | --help
        Show this usage information.

    -c <filename> | --config <filename>
        Read configuration from <filename> instead of
        /etc/dynamodb-user-manager.cfg.

    -f | --foreground
        Don't fork into the background (don't daemonize).

    -p <filename> | --pidfile <filename>
        Write the process pid to <filename> instead of
        /var/run/dynamodb-user-manager.pid.


Configuration file:
The configuration file is a JSON document in the form:
{{
    "aws_access_key": "AKIDEXAMPLE",
    "aws_profile": "default",
    "aws_region": "us-east-1",
    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    "aws_session_token": "",
    "full_update_jitter": 600,
    "full_update_period": 3600,
    "group_table_name": "Groups",
    "user_table_name": "Users",
    "logging": {{
        "version": 1,
        ...
    }}
}}

The valid configuration keys are:
    aws_access_key / aws_secret_key / aws_session_token / aws_profile <str>
        Static AWS credentials to use.

        If aws_access_key and aws_secret_key (and, optionally,
        aws_session_token) are specified, these are fed directly into Boto and
        will be used.

        Otherwise, if aws_profile is specified, this is fed into Boto, which
        reads the the credentials from ~/.aws/credentials (usually the root
        user).

        On EC2 instances, these parameters should not be used. Boto will fetch
        the credentials from the EC2 instance metadata.

    aws_region <str>
        The AWS region to use. If unspecified, this uses the first value found
        from:
            The environment variable AWS_REGION
            The environment variable AWS_DEFAULT_REGION
            If running on EC2, the EC2 instance metadata.
            "us-east-1"

    full_update_period / full_update_jitter <int>
        The time, in seconds, between polls of the DynamoDB tables. The wait
        period is always used, plus a random value from 0 to full_update_jitter
        is selected; this helps distribute the load on the DynamoDB tables when
        run across multiple instances.

        The default is 3600 seconds (1 hour) for full_update_period, and
        600 seconds (10 minutes) for full_update_jitter.

    group_table_name <str>
        The name of the DynamoDB table to use to fetch for groups. This defaults
        to "Groups".

    user_table_name <str>
        The name of the DynamoDB table to use to fetch for users. This defaults
        to "Users".

    logging <dict>
        If present, this is passed to the Python configuration function
        logging.config.dictConfig (http://bit.ly/2JROo0t).
"""
# pylint: disable=C0103

from functools import partial
from getopt import getopt, GetoptError
import json
from logging.config import dictConfig
from sys import argv, stderr, stdout
from typing import Any, Dict, Optional, Sequence, TextIO
from daemonize import Daemonize
from .constants import (
    DDBUM_CONFIG_FILENAME, KEY_AWS_ACCESS_KEY, KEY_AWS_PROFILE, KEY_AWS_REGION,
    KEY_AWS_SECRET_KEY, KEY_AWS_SESSION_TOKEN, KEY_LOGGING)

# Do *not* import other dynamodbusermanager modules here. They configure
# loggers at the module scope that will become disabled when we initialize
# logging. Instead, they're imported just-in-time within main itself.

def main(args: Optional[Sequence[str]] = None) -> int:
    """
    main(args: Optional[Sequence[str]]) -> int
    Main entrypoint of the program.
    """
    config_filename = DDBUM_CONFIG_FILENAME
    foreground = False
    pidfile = "/var/run/dynamodb-user-manager.pid"

    if args is None:
        args = argv[1:]

    try:
        opts, args = getopt(
            list(args), "hc:fp:", ["help", "config=", "foreground", "pidfile="])
        for opt, val in opts:
            if opt in ("-h", "--help"):
                usage(stdout)
                return 0

            if opt in ("-c", "--config"):
                config_filename = val

            if opt in ("-f", "--foreground"):
                foreground = True

            if opt in ("-p", "--pidfile"):
                pidfile = val
    except GetoptError as e:
        print(str(e), file=stderr)
        return 1

    if args:
        print(f"Unknown argument {args[0]}", file=stderr)
        usage()
        return 1

    # Ingest the config file.
    try:
        config = parse_config(config_filename)
    except IOError as e:
        print(f"{config_filename}: {e}", file=stderr)
        return 1

    if not foreground:
        daemonize = Daemonize(
            app="dynamodb-user-manager", pid=pidfile, action=partial(run, config))
        daemonize.start()
        return 0

    return run(config)

def run(config: Dict[str, Any]) -> int:
    """
    Main loop after daemonization (if applicable)
    """
    boto_kw = {}
    # Logging *must* be configured before we import the daemon or Boto.
    if KEY_LOGGING in config:
        logging_config = config.pop(KEY_LOGGING)
        dictConfig(logging_config)

    # Now we can import other dynamodbusermanager modules.
    from .daemon import Daemon
    from .utils import get_region
    from boto3.session import Session as Boto3Session

    if KEY_AWS_ACCESS_KEY in config and KEY_AWS_SECRET_KEY in config:
        boto_kw["aws_access_key_id"] = config.pop(KEY_AWS_ACCESS_KEY)
        boto_kw["aws_secret_access_key"] = config.pop(KEY_AWS_SECRET_KEY)

        if KEY_AWS_SESSION_TOKEN in config:
            boto_kw["aws_session_token"] = config.pop(KEY_AWS_SESSION_TOKEN)

    if KEY_AWS_PROFILE in config:
        boto_kw["profile_name"] = config.pop(KEY_AWS_PROFILE)

    if KEY_AWS_REGION in config:
        boto_kw["region_name"] = config.pop(KEY_AWS_REGION)
    else:
        boto_kw["region_name"] = get_region()

    session = Boto3Session(**boto_kw)
    ddb = session.client("dynamodb")
    daemon = Daemon(ddb, config)
    daemon.main_loop()
    return 0

def parse_config(filename: str = DDBUM_CONFIG_FILENAME) -> Dict[str, Any]:
    """
    read_config(filename: str = "/etc/dynamodb-user-manager.cfg") -> None
    Return configuration from the specified JSON file.
    """
    with open(filename, "r") as fd:
        return json.load(fd)

def usage(fd: TextIO = stderr) -> None:
    """
    usage(fd: TextIO = stderr) -> None
    Print usage information to the specified descriptor.
    """
    fd.write(__doc__.format(argv0=argv[0]))
    fd.flush()
