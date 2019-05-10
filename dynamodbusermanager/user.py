"""
Class for manipulating user information.
"""
from datetime import date, timedelta
from functools import total_ordering
from typing import Any, Dict, Optional, NamedTuple, Type, TypeVar

from .constants import (
    EPOCH, FIELD_PATTERN, REAL_NAME_MAX_LENGTH, UID_MIN, UID_MAX)
from .entity import Entity

# pylint: disable=C0103

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
    modified: bool

U = TypeVar("U", bound="User")  # pylint: disable=C0103

@total_ordering
class User(Entity):
    """
    User object for holding data about a single user entry in the /etc/passwd
    and /etc/shadow files.
    """
    # pylint: disable=W0201

    def __init__(
            self,
            name: str,
            uid: int,
            gid: int,
            real_name: str,
            home: str,
            shell: str,
            password: Optional[str] = None,
            last_password_change_date: Optional[date] = None,
            password_age_min_days: Optional[int] = None,
            password_age_max_days: Optional[int] = None,
            password_warn_days: Optional[int] = None,
            password_disable_days: Optional[int] = None,
            account_expire_date: Optional[date] = None,
            modified: bool = False) -> None:
        """
        User(
            name: str,
            uid: int,
            gid: int,
            real_name: str,
            home: str,
            shell: str,
            password: Optional[str] = None,
            last_password_change_date: Optional[date] = None,
            password_age_min_days: Optional[int] = None,
            password_age_max_days: Optional[int] = None
            password_warn_days: Optional[int] = None,
            password_disable_days: Optional[int] = None,
            account_expire_date: Optional[date] = None,
            modified: bool = False) -> User
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

    @staticmethod
    def date_from_string(s: Optional[str]) -> Optional[date]:
        """
        User.date_from_string(s: Optional[str]) -> Optional[date]
        Convert a string date in YYYY-MM-DD form to a date object. If s is
        None, this returns None.
        """
        if s is None:
            return None

        return date.fromisoformat(s)

    def update_from_dynamodb_item(self, item: Dict[str, Any]) -> bool:
        """
        user.update_from_dynamodb_item(item: Dict[str, Any]) -> bool
        Update the user from a given DynamoDB item. If an attribute has been
        modified, the modified flag is set to true.

        The name field cannot be updated.

        The return value is the value of the modified flag.
        """
        super(User, self).update_from_dynamodb_item(item)

        uid = item["UID"]["N"]
        if self.uid != uid:
            self.uid = uid
            self.modified = True

        real_name = item["RealName"]["S"]
        if self.real_name != real_name:
            self.real_name = real_name
            self.modified = True

        home = item["Home"]["S"]
        if self.home != home:
            self.home = home
            self.modified = True

        shell = item["Shell"]["S"]
        if self.shell != shell:
            self.shell = shell
            self.modified = True

        last_password_change_date = User.date_from_string(
            item.get("LastPasswordChangeDate", {}).get("S"))
        if self.last_password_change_date != last_password_change_date:
            self.last_password_change_date = last_password_change_date
            self.modified = True

        password_age_min_days = item.get("PasswordAgeMinDays", {}).get("N")
        if self.password_age_min_days != password_age_min_days:
            self.password_age_min_days = password_age_min_days
            self.modified = True

        password_age_max_days = item.get("PasswordAgeMaxDays", {}).get("N")
        if self.password_age_max_days != password_age_max_days:
            self.password_age_max_days = password_age_max_days
            self.modified = True

        password_warn_days = item.get("PasswordWarnDays", {}).get("N")
        if self.password_warn_days != password_warn_days:
            self.password_warn_days = password_warn_days
            self.modified = True

        password_disable_days = item.get("PasswordDisableDays", {}).get("N")
        if self.password_disable_days != password_disable_days:
            self.password_disable_days = password_disable_days
            self.modified = True

        account_expire_date = User.date_from_string(
            item.get("AccountExpireDate", {}).get("S"))
        if self.account_expire_date != account_expire_date:
            self.account_expire_date = account_expire_date
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
            uid=item["UID"]["N"],
            gid=item["GID"]["N"],
            real_name=item["RealName"]["S"],
            home=item["Home"]["S"],
            shell=item["Shell"]["S"],
            password=item.get("Password", {}).get("S"),
            last_password_change_date=User.date_from_string(
                item.get("LastPasswordChangeDate", {}).get("S")),
            password_age_min_days=item.get("PasswordAgeMinDays", {}).get("N"),
            password_age_max_days=item.get("PasswordAgeMaxDays", {}).get("N"),
            password_warn_days=item.get("PasswordWarnDays", {}).get("N"),
            password_disable_days=item.get("PasswordDisableDays", {}).get("N"),
            account_expire_date=User.date_from_string(
                item.get("AccountExpireDate", {}).get("S")),
            modified=True)
