"""
Miscellanous utilities for dynamodb-user-manager
"""

from datetime import datetime
from functools import lru_cache
from logging import getLogger
from os import (
    chmod, chown, environ, getegid, geteuid, mkdir, rename, setegid, seteuid,
    stat, urandom)
from os.path import exists
from stat import S_IMODE, S_ISDIR, S_ISREG
from struct import unpack
from typing import Callable, Optional

import requests
from requests.exceptions import ConnectTimeout

# pylint: disable=C0103

AZ_METADATA_URL = (
    "http://169.254.169.254/2018-09-24/meta-data/placement/"
    "availability-zone")
METADATA_TIMEOUT = 0.1

log = getLogger(__name__)

@lru_cache()
def get_region():
    """
    get_region() -> str
    Returns the name of the region to use.

    This returns the first result found from:
      * The environment variable AWS_REGION
      * The environment variable AWS_DEFAULT_REGION
      * Instance availability zone
      * us-east-1
    """
    region = environ.get("AWS_REGION")
    if not region:
        region = environ.get("AWS_DEFAULT_REGION")
    if not region:
        try:
            az = requests.get(AZ_METADATA_URL, timeout=METADATA_TIMEOUT).text
            region = az[:-1]
        except ConnectTimeout:
            pass
    if not region:
        region = "us-east-1"

    return region

def parse_bool(s: str, default: bool = False, strict: bool = False) -> bool:
    """
    parse_bool(s: str, default: bool = False, strict: bool = False) -> bool
    Parse a boolean string value. If the string is not recognized as a valid
    True/False string value, the default is returned if strict is False;
    otherwise, a ValueError is raised.

    True values are strings (case-insensitive): t true y yes 1
    False values are strings (case-insensitive): f false n no 0
    """
    s = s.lower()

    if s in ("t", "true", "y", "yes", "1"):
        return True
    if s in ("f", "false", "n", "no", "0"):
        return False
    if strict:
        raise ValueError(f"Not a valid boolean string: {s!r}")

    return default

def parse_opt_int(s: Optional[str]) -> Optional[int]:
    """
    parse_opt_int(s: Optional[str]) -> Optional[int]
    If s is a string, parse it for an integer value (raising a ValueError if
    it cannot be parsed correctly.)
    If s is None, return None.
    Otherwise, raise a TypeError.
    """
    if s is None:
        return None

    if isinstance(s, str):
        return int(s)

    raise TypeError(f"value must be a string or None: {type(s).__name__}")

def move_aside(filename: str) -> None:
    """
    move_aside(filename: str) -> None
    Move the specified file/directory aside, renaming it from {filename} to
    {filename}.old.{timestamp}.{random}.
    """
    backup_date = datetime.utcnow().strftime("%Y.%m.%d")
    random = unpack("I", urandom(4))[0]
    backup_name = f"{filename}.old.{backup_date}.{random:x}"

    log.info("Moving %r aside to %r", filename, backup_name)
    try:
        rename(filename, backup_name)
    except OSError as e:
        log.error(
            "Unable to rename %s to %s: %s", filename, backup_name, e)
        raise

def _ensure_user_owns( # pylint: disable=R0913
        uid: int, filename: str, check_fn: Callable[[int], bool],
        filetype: str, mode: int, mode_cmp_mask: int = 0o777) -> bool:
    """
_ensure_user_owns(
    uid: int, gid: int, filename: str, check_fn: Callable[[int], bool],
    filetype: str, mode: int, mode_cmp_mask: int = 0o777) -> bool
Common code for ensure_user_owns_dir, ensure_user_owns_file.

If the file/directory exists and has the proper permissions, returns True.
Otherwise, returns False
    """
    if not exists(filename):
        return False

    # Make sure permissions are set correctly.
    s = stat(filename)
    if s.st_uid != uid:
        log.warning(
            "Incorrect ownership on %s: expected uid %d, actual uid %d",
            filename, uid, s.st_uid)
        move_aside(filename)
        return False

    if not check_fn(s.st_mode):
        log.warning("Not a %s: %s", filetype, filename)
        move_aside(filename)
        return False

    if (S_IMODE(s.st_mode) & mode_cmp_mask) != (mode & mode_cmp_mask):
        log.info(
            "Incorrect permissions on %s: expected %03o, actual %03o; "
            "resetting", filename, S_IMODE(s.st_mode), mode)
        chmod(filename, mode)

    return True

def ensure_user_owns_dir(
        uid: int, gid: int, dirname: str, mode: int,
        mode_cmp_mask: int = 0o777) -> None:
    """
ensure_user_owns_dir(
    uid: int, gid: int, dirname: str, mode: int,
    mode_cmp_mask: int = 0o777) -> None
Ensure the specified directory exists and is owned by the user with the
specified permissions.

If the directory exists but is owned by another user or is not a directory, it
is moved aside and a new, empty directory is created in its place.
    """
    if _ensure_user_owns(
            uid, dirname, S_ISDIR, "directory", mode, mode_cmp_mask):
        return

    # Directory does not exist; create it.
    log.info("Creating %s with mode %03o", dirname, mode)
    mkdir(dirname, mode=mode)

    # Change ownership on the directory
    log.info("Changing ownership on %s to %d:%d", dirname, uid, gid)
    chown(dirname, uid, gid)

def ensure_user_owns_file(
        uid: int, filename: str, mode: int, mode_cmp_mask: int = 0o777) -> None:
    """
ensure_user_owns_file(
    uid: int, filename: str, mode: int, mode_cmp_mask: int = 0o777) -> None
Ensure the specified filename exists and is owned by the user with the
specified permissions.

If the file exists but is owned by another user or is not a file, it is moved
aside.
    """
    _ensure_user_owns(uid, filename, S_ISREG, "file", mode, mode_cmp_mask)

class ChangeEffectiveId():
    """
    Context handler for temporarily setting the effective user or group id.
    """

    def __init__(
            self, euid: Optional[int] = None,
            egid: Optional[int] = None) -> None:
        super(ChangeEffectiveId, self).__init__()
        self.euid = euid
        self.egid = egid
        self.old_euid = None # type: Optional[int]
        self.old_egid = None # type: Optional[int]

    def __enter__(self) -> None:
        try:
            if self.egid is not None:
                self.old_egid = getegid()
                try:
                    setegid(self.egid)
                except:
                    self.old_egid = None
                    raise

            if self.euid is not None:
                self.old_euid = geteuid()
                try:
                    seteuid(self.euid)
                except:
                    self.old_euid = None
                    raise
        except:
            self.reset()
            raise

    def __exit__(self, etype, evalue, traceback) -> None:
        self.reset()

    def reset(self) -> None:
        """
        Reset the effective uid/gid to what they were before any
        seteuid/setegid calls were made.
        """
        if self.old_egid is not None:
            setegid(self.old_egid)
            self.old_egid = None

        if self.old_euid is not None:
            seteuid(self.old_euid)
            self.old_euid = None
