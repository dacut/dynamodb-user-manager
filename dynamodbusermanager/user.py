"""
Class for manipulating user information.
"""
from datetime import date, timedelta
from functools import total_ordering
from logging import getLogger
from os import stat
from os.path import exists
from re import compile as re_compile
from stat import (S_IMODE, S_ISDIR, S_ISREG)
from typing import (
    Any, Collection, Dict, FrozenSet, Optional, NamedTuple, Set, Type, TypeVar,
    Union)

from .constants import (
    EPOCH, FIELD_PATTERN, REAL_NAME_MAX_LENGTH, UID_MIN, UID_MAX)
from .entity import Entity
from .utils import parse_opt_int

# pylint: disable=C0103

log = getLogger(__name__)

class UserTuple(NamedTuple):
    """
    UserTuple(NamedTuple)
    Holds the data for a User object in an immutable format.
    """
    name: str
    uid: int
    gid: int
    real_name: str
    home: str
    shell: str
    password: Optional[str]
    last_password_change_date: Optional[date]
    password_age_min_days: Optional[int]
    password_age_max_days: Optional[int]
    password_warn_days: Optional[int]
    password_disable_days: Optional[int]
    account_expire_date: Optional[date]
    ssh_public_keys: FrozenSet[str]
    modified: bool

U = TypeVar("U", bound="User")

@total_ordering
class User(Entity):
    """
    User object for holding data about a single user entry in the /etc/passwd
    and /etc/shadow files.
    """
    # pylint: disable=W0201,R0902

    def __init__( # pylint: disable=R0913,R0914
            self, name: str, uid: int, gid: int, real_name: str, home: str,
            shell: str, password: Optional[str] = None,
            last_password_change_date: Optional[date] = None,
            password_age_min_days: Optional[int] = None,
            password_age_max_days: Optional[int] = None,
            password_warn_days: Optional[int] = None,
            password_disable_days: Optional[int] = None,
            account_expire_date: Optional[date] = None,
            ssh_public_keys: Optional[Set[str]] = None,
            modified: bool = False) -> None:
        """
User(
    name: str, uid: int, gid: int, real_name: str, home: str, shell: str,
    password: Optional[str] = None,
    last_password_change_date: Optional[date] = None,
    password_age_min_days: Optional[int] = None,
    password_age_max_days: Optional[int] = None
    password_warn_days: Optional[int] = None,
    password_disable_days: Optional[int] = None,
    account_expire_date: Optional[date] = None,
    ssh_public_keys: Optional[str] = None, modified: bool = False) -> User
Create a new User object.
        """
        super(User, self).__init__(name=name, gid=gid, password=password, modified=modified)
        self.name = name
        self.uid = uid
        self.real_name = real_name
        self.home = home
        self.shell = shell
        self.last_password_change_date = last_password_change_date
        self.password_age_min_days = password_age_min_days
        self.password_age_max_days = password_age_max_days
        self.password_warn_days = password_warn_days
        self.password_disable_days = password_disable_days
        self.account_expire_date = account_expire_date
        self.ssh_public_keys = ssh_public_keys

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, User):
            return False

        return self.as_tuple == other.as_tuple

    def __ne__(self, other: Any) -> bool:
        if not isinstance(other, User):
            return True

        return self.as_tuple != other.as_tuple

    def __lt__(self, other: "User") -> bool:
        self._lt_check_other_type(other)
        return self.as_tuple < other.as_tuple

    @property
    def uid(self) -> int:
        """
        The integer user id of the user.
        """
        return self._uid

    @uid.setter
    def uid(self, value: int) -> None:
        if not isinstance(value, int):
            raise TypeError("uid must be an int")

        if not UID_MIN <= value <= UID_MAX:
            raise ValueError(
                f"uid must be between {UID_MIN} and {UID_MAX}, inclusive: "
                f"{value}")

        self._uid = value

    @property
    def real_name(self) -> str:
        """
        The real name of the user.
        This _may_ be a comma-delimited list of values containing the following
        fields:
            * The user's full name
            * The building and room number
            * Office telephone number
            * Home telephone number
            * Other contact information
        """
        return self._real_name

    @real_name.setter
    def real_name(self, value: Optional[str]) -> None:
        if value is None:
            self._real_name = ""
            return

        if not isinstance(value, str):
            raise TypeError("real_name must be a string or None")
        if not FIELD_PATTERN.match(value):
            raise ValueError("real_name contains illegal characters")
        if len(value.encode("utf-8")) > REAL_NAME_MAX_LENGTH:
            raise ValueError(
                f"real_name is longer than {REAL_NAME_MAX_LENGTH} bytes "
                f"(UTF-8 encoded)")

        self._real_name = value

    @property
    def home(self) -> str:
        """
        The home directory of the user.
        """
        return self._home

    @home.setter
    def home(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("home must be a string")

        if not FIELD_PATTERN.match(value):
            raise TypeError("home contains illegal characters")

        self._home = value

    @property
    def shell(self) -> str:
        """
        The login shell of the user.
        """
        return self._shell

    @shell.setter
    def shell(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("shell must be a string")

        if not FIELD_PATTERN.match(value):
            raise ValueError(
                "shell is not an absolute path or contains doubled or "
                f"trailing slashes: {value}")

        self._shell = value

    @property
    def ssh_public_keys(self) -> FrozenSet[str]:
        """
        The SSH public keys of the user.
        """
        return frozenset(self._ssh_public_keys)

    @ssh_public_keys.setter
    def ssh_public_keys(
            self, value: Optional[Union[Collection[str], str]]) -> None:
        if value is None:
            self._ssh_public_keys = set() # type: Set[str]
            return

        if isinstance(value, str):
            self._ssh_public_keys = set([value])
            return

        if not isinstance(value, (list, tuple, set)):
            raise TypeError("ssh_public_keys must be a collection of strings")

        new_ssh_public_keys = set() # type: Set[str]
        for el in value:
            if not isinstance(el, str):
                raise TypeError(
                    "ssh_public_keys must be a collection of strings")

            new_ssh_public_keys.add(el)

        self._ssh_public_keys = new_ssh_public_keys

    @property
    def ssh_dir_permissions_ok(self) -> bool:
        """
        Indicates whether ~/.ssh exists, is a directory owned by the user,
        and is only writable by the user.
        """
        # pylint: disable=R0911
        home = self.home
        if not home:
            log.debug(
                "User %s does not have a home directory set", self.name)
            return False

        ssh_dir = home + "/.ssh"
        if not exists(ssh_dir):
            log.debug(
                "User %s does not have ~/.ssh directory: %s", self.name,
                ssh_dir)
            return False

        try:
            ssh_stat = stat(ssh_dir)
        except OSError as e:
            log.error("Unable to stat %s: %s", ssh_dir, e)
            return False

        if ssh_stat.st_uid != self.uid:
            log.warning(
                "User %s does not own ~/.ssh directory %s: user uid %d, "
                "owner uid %d", self.name, ssh_dir, self.uid, ssh_stat.st_uid)
            return False

        if not S_ISDIR(ssh_stat.st_mode):
            log.warning(
                "User %s ~/.ssh direcotry %s is not a directory", self.name,
                ssh_dir)
            return False

        mode_bits = S_IMODE(ssh_stat.st_mode)
        if mode_bits & 0o020:
            log.warning(
                "User %s ~/.ssh directory %s is group-writable", self.name,
                ssh_dir)
            return False

        if mode_bits & 0o002:
            log.warning(
                "User %s ~/.ssh directory %s is other-writable", self.name,
                ssh_dir)
            return False

        return True

    @property
    def authorized_keys_permissions_ok(self) -> bool:
        """
        Indicates whether ~/.ssh/authorized_keys exists, is owned by the
        user, and is only writable by the user.
        """
        # pylint: disable=R0911
        if not self.ssh_dir_permissions_ok:
            return False

        auth_keys = self.home + "/.ssh/authorized_keys"
        if not exists(auth_keys):
            log.debug(
                "User %s does not have ~/.ssh/authorized_keys: %s", self.name,
                auth_keys)
            return False

        try:
            auth_keys_stat = stat(auth_keys)
        except OSError as e:
            log.error("Unable to stat %s: %s", auth_keys, e)
            return False

        if auth_keys_stat.st_uid != self.uid:
            log.warning(
                "User %s does not own ~/.ssh/authorized_keys file %s: user "
                "uid %d, owner uid %d", self.name, auth_keys, self.uid,
                auth_keys_stat.st_uid)
            return False

        if not S_ISREG(auth_keys_stat.st_mode):
            log.warning(
                "User %s ~/.ssh/authorized_keys file %s is not a file",
                self.name, auth_keys)
            return False

        mode_bits = S_IMODE(auth_keys_stat.st_mode)
        if mode_bits & 0o020:
            log.warning(
                "User %s ~/.ssh/authorized_keys file %s is group-writable",
                self.name, auth_keys)
            return False

        if mode_bits & 0o002:
            log.warning(
                "User %s ~/.ssh/authorized_keys file %s is other-writable",
                self.name, auth_keys)
            return False

        return True

    @property
    def authorized_keys(self) -> Set[str]:
        """
        Return the authorized keys found in ~/.ssh
        """
        result = set() # type: Set[str]
        auth_keys = self.home + "/.ssh/authorized_keys"
        if not self.authorized_keys_permissions_ok:
            return result

        with open(auth_keys, "r") as fd:
            for line in fd:
                line = line.strip()
                if line:
                    result.add(line)

        return result

    @property
    def as_tuple(self) -> UserTuple:
        """
        The user represented as an immutable tuple object.
        """
        return UserTuple(
            name=self.name,
            uid=self.uid,
            gid=self.gid,
            real_name=self.real_name,
            home=self.home,
            shell=self.shell,
            password=self.password,
            last_password_change_date=self.last_password_change_date,
            password_age_min_days=self.password_age_min_days,
            password_age_max_days=self.password_age_max_days,
            password_warn_days=self.password_warn_days,
            password_disable_days=self.password_disable_days,
            account_expire_date=self.account_expire_date,
            ssh_public_keys=self.ssh_public_keys,
            modified=self.modified,
        )

    def __repr__(self):
        return repr(self.as_tuple)

    @staticmethod
    def date_from_days(days: Optional[int]) -> Optional[date]:
        """
        User.date_from_days(days: Optional[int]) -> Optional[date]
        Convert a count of days-from-epoch to an optional date field.
        If days is negative or None, the result is None.

        This standardizes negative values returned by the Python spwd library
        to None values.
        """
        if days is None or days < 0:
            return None

        return EPOCH + timedelta(days=days)

    @staticmethod
    def age_from_days(days: int) -> Optional[int]:
        """
        User.age_from_days(days: Optional[int]) -> Optional[int]
        Convert an age in days to an optional age field.
        If days is negative or None, the result is None.

        This standardizes negative values returned by the Python spwd library
        to None values.
        """
        if days is None or days < 0:
            return None

        return days

    _iso8601_date_pattern = re_compile(
        r"^(?P<year>[0-9]{4})-?"
        r"(?P<month>[0-9][1-9]|1[0-2])-?"
        r"(?P<day>0[1-9]|[12][0-9]|3[01])$")
    @staticmethod
    def date_from_string(s: Optional[str]) -> Optional[date]:
        """
        User.date_from_string(s: Optional[str]) -> Optional[date]
        Convert a string date in YYYY-MM-DD form to a date object. If s is
        None, this returns None.
        """
        if s is None:
            return None

        m = User._iso8601_date_pattern.match(s)
        if not m:
            raise ValueError("Cannot parse as date: %r" % s)
        year = int(m.group("year"))
        month = int(m.group("month"))
        day = int(m.group("day"))
        return date(year, month, day)

    def update_from_dynamodb_item(self, item: Dict[str, Any]) -> bool:
        """
        user.update_from_dynamodb_item(item: Dict[str, Any]) -> bool
        Update the user from a given DynamoDB item. If an attribute has been
        modified, the modified flag is set to true.

        The name field cannot be updated.

        The return value is the value of the modified flag.
        """
        super(User, self).update_from_dynamodb_item(item)

        uid = int(item["UID"]["N"])
        if self.uid != uid:
            self.uid = uid
            self.modified = True

        real_name = item.get("RealName", {"S": ""})["S"]
        if self.real_name != real_name:
            self.real_name = real_name
            self.modified = True

        home = item.get("Home", {"S": ""})["S"]
        if self.home != home:
            self.home = home
            self.modified = True

        shell = item.get("Shell", {"S": ""})["S"]
        if self.shell != shell:
            self.shell = shell
            self.modified = True

        last_password_change_date = User.date_from_string(
            item.get("LastPasswordChangeDate", {}).get("S"))
        if self.last_password_change_date != last_password_change_date:
            self.last_password_change_date = last_password_change_date
            self.modified = True

        password_age_min_days = parse_opt_int(
            item.get("PasswordAgeMinDays", {}).get("N"))
        if self.password_age_min_days != password_age_min_days:
            self.password_age_min_days = password_age_min_days
            self.modified = True

        password_age_max_days = parse_opt_int(
            item.get("PasswordAgeMaxDays", {}).get("N"))
        if self.password_age_max_days != password_age_max_days:
            self.password_age_max_days = password_age_max_days
            self.modified = True

        password_warn_days = parse_opt_int(
            item.get("PasswordWarnDays", {}).get("N"))
        if self.password_warn_days != password_warn_days:
            self.password_warn_days = password_warn_days
            self.modified = True

        password_disable_days = parse_opt_int(
            item.get("PasswordDisableDays", {}).get("N"))
        if self.password_disable_days != password_disable_days:
            self.password_disable_days = password_disable_days
            self.modified = True

        account_expire_date = User.date_from_string(
            item.get("AccountExpireDate", {}).get("S"))
        if self.account_expire_date != account_expire_date:
            self.account_expire_date = account_expire_date
            self.modified = True

        ssh_public_keys = item.get("SSHPublicKeys", {}).get("SS", set())
        if self.ssh_public_keys != ssh_public_keys:
            self.ssh_public_keys = ssh_public_keys
            self.modified = True

        return self.modified

    @classmethod
    def from_dynamodb_item(cls: Type[U], item: Dict[str, Any]) -> U:
        """
User.from_dynamodb_item(item: Dict[str, Any]) -> User
Create a user from a given DynamoDB item. The modified flag is
automatically set to true.
        """
        return cls(
            name=item["Name"]["S"],
            uid=int(item["UID"]["N"]),
            gid=int(item["GID"]["N"]),
            real_name=item.get("RealName", {"S": ""})["S"],
            home=item.get("Home", {"S": ""})["S"],
            shell=item.get("Shell", {"S": ""})["S"],
            password=item.get("Password", {}).get("S"),
            last_password_change_date=User.date_from_string(
                item.get("LastPasswordChangeDate", {}).get("S")),
            password_age_min_days=parse_opt_int(
                item.get("PasswordAgeMinDays", {}).get("N")),
            password_age_max_days=parse_opt_int(
                item.get("PasswordAgeMaxDays", {}).get("N")),
            password_warn_days=parse_opt_int(
                item.get("PasswordWarnDays", {}).get("N")),
            password_disable_days=parse_opt_int(
                item.get("PasswordDisableDays", {}).get("N")),
            account_expire_date=User.date_from_string(
                item.get("AccountExpireDate", {}).get("S")),
            ssh_public_keys=item.get("SSHPublicKeys", {}).get("SS", set()),
            modified=True)
