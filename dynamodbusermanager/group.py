"""
Class for manipulating group information.
"""
from functools import total_ordering
from typing import (Any, Collection, Dict, List, NamedTuple, Optional, Set,
                    Tuple, Union)

from .constants import GID_MIN, GID_MAX, NAME_MAX_LENGTH, NAME_PATTERN

class GroupTuple(NamedTuple):
    """
    UserTuple(NamedTuple)
    Holds the data for a Group object in an immutable format.
    """
    group_name: str
    gid: int
    administrators: Set[str]
    members: Set[str]
    password: Optional[str]
    modified: bool

@total_ordering
class Group(): # pylint: disable=W0201
    """
    Group object for holding data about a single group entry in the /etc/group
    and /etc/gshadow files.
    """

    def __init__(
            self,
            group_name: str,
            gid: int,
            administrators: Optional[Collection[str]] = None,
            members: Optional[Collection[str]] = None,
            password: Optional[str] = None,
            modified: bool = False) -> None:
        """
        Group(
            group_name: str,
            gid: int,
            administrators: Optional[Collection[str]] = None,
            members: Optional[Collection[str]] = None,
            password: Optional[str] = None,
            modified: bool = False) -> Group
        Create a new Group object.
        """
        super(Group, self).__init__()
        self.group_name = group_name
        self.gid = gid
        self.administrators = administrators
        self.members = members
        self.password = password
        self.modified = modified

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Group):
            return False

        return self.as_tuple == other.as_tuple

    def __ne__(self, other: Any) -> bool:
        if not isinstance(other, Group):
            return True

        return self.as_tuple != other.as_tuple

    def __lt__(self, other: "Group") -> bool:
        if not isinstance(other, Group):
            raise TypeError(
                f"'<' not supported between instances of "
                f"{type(self).__name__!r} and {type(other).__name__!r}")

        return self.as_tuple < other.as_tuple

    @property
    def group_name(self) -> str:
        """
        The name of the group.
        """
        return self._group_name

    @group_name.setter
    def group_name(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("group_name must be a string")
        if not value:
            raise ValueError("group_name cannot be empty")
        if len(value) > NAME_MAX_LENGTH:
            raise ValueError(
                f"group_name cannot be longer than {NAME_MAX_LENGTH} characters")
        if not NAME_PATTERN.match(value):
            raise ValueError("group_name contains illegal characters")

        self._group_name = value

    @property
    def gid(self) -> int:
        """
        The integer group id of the group.
        """
        return self._gid

    @gid.setter
    def gid(self, value: int) -> None:
        if not isinstance(value, int):
            raise TypeError("gid must be an int")

        if not GID_MIN <= value <= GID_MAX:
            raise ValueError(
                f"gid must be between {GID_MIN} and {GID_MAX}, inclusive: "
                f"{value}")

        self._gid = value

    @property
    def administrators(self) -> Set[str]:
        """
        A set of usernames who can administer the group.
        """
        return set(self._administrators)

    @administrators.setter
    def administrators(self, value: Optional[Union[List[str], Set[str], Tuple[str]]]) -> None:
        if value is None:
            self._administrators = set() # type: Set[str]
            return

        if (not isinstance(value, (list, set, tuple)) or
                not all([isinstance(el, str) for el in value])):
            raise TypeError("administrators must be a list, set, or tuple of strings")

        for username in value:
            if not username:
                raise ValueError("usernames cannot be empty")

            if not NAME_PATTERN.match(username):
                raise ValueError(f"username contains illegal characters: {username}")

        self._administrators = set(value)
        return

    @property
    def members(self) -> Set[str]:
        """
        A set of usernames who are members of the group without requiring a
        password.
        """
        return set(self._members)

    @members.setter
    def members(self, value: Optional[Union[List[str], Set[str], Tuple[str]]]) -> None:
        if value is None:
            self._members = set() # type: Set[str]
            return

        if (not isinstance(value, (list, set, tuple)) or
                not all([isinstance(el, str) for el in value])):
            raise TypeError("members must be a list, set, or tuple of strings")

        for username in value:
            if not username:
                raise ValueError("usernames cannot be empty")

            if not NAME_PATTERN.match(username):
                raise ValueError(f"username contains illegal characters: {username}")

        self._members = set(value)
        return

    @property
    def password(self) -> Optional[str]:
        """
        The hashed password to gain access to the group.
        """
        return self._password

    @password.setter
    def password(self, value: Optional[str]) -> None:
        if value is None:
            self._password = None
            return

        if not isinstance(value, str):
            raise TypeError("password must be a string")

        if not value:
            raise TypeError("password cannot be empty")

        if ":" in value or "\n" in value:
            raise TypeError("password contains illegal characters")

        self._password = value

    @property
    def as_tuple(self) -> GroupTuple:
        """
        The group represented as an immutable tuple object.
        """
        return GroupTuple(
            group_name=self.group_name,
            gid=self.gid,
            administrators=self.administrators,
            members=self.members,
            password=self.password,
            modified=self.modified,
        )

    def __repr__(self):
        return repr(self.as_tuple)

    def update_from_dynamodb_item(self, item: Dict[str, Any]) -> bool:
        """
        user.update_from_dynamodb_item(item: Dict[str, Any]) -> bool
        Update the group from a given DynamoDB item. If an attribute has been
        modified, the modified flag is set to true.

        The group_name field cannot be updated.

        The return value is the value of the modified flag.
        """
        if self.group_name != item["GroupName"]["S"]:
            raise ValueError("Cannot update group_name")

        gid = item["GID"]["N"]
        if self.gid != gid:
            self.gid = gid
            self.modified = True

        administrators = set(item.get("Administrators", {}).get("SS", []))
        if self.administrators != administrators:
            self.administrators = administrators
            self.modified = True

        members = set(item.get("Members", {}).get("SS", []))
        if self.members != members:
            self.members = members
            self.modified = True

        password = item.get("Password", {}).get("S")
        if self.password != password:
            self.password = password
            self.modified = True

        return self.modified
