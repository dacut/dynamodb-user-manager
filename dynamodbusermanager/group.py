"""
Class for manipulating group information.
"""
# pylint: disable=C0103

from functools import total_ordering
from typing import (
    Any, Collection, Dict, List, NamedTuple, Optional, Set, Tuple, Type,
    TypeVar, Union)

from .constants import NAME_PATTERN
from .entity import Entity

class GroupTuple(NamedTuple):
    """
    UserTuple(NamedTuple)
    Holds the data for a Group object in an immutable format.
    """
    name: str
    gid: int
    administrators: Set[str]
    members: Set[str]
    password: Optional[str]
    modified: bool

G = TypeVar("G", bound="Group")

@total_ordering
class Group(Entity):
    """
    Group object for holding data about a single group entry in the /etc/group
    and /etc/gshadow files.
    """
    # pylint: disable=W0201

    def __init__(   # pylint: disable=R0913
            self, name: str, gid: int,
            administrators: Optional[Collection[str]] = None,
            members: Optional[Collection[str]] = None,
            password: Optional[str] = None, modified: bool = False) -> None:
        """
Group(
    name: str, gid: int, administrators: Optional[Collection[str]] = None,
    members: Optional[Collection[str]] = None, password: Optional[str] = None,
    modified: bool = False) -> Group
Create a new Group object.
        """
        super(Group, self).__init__(name=name, gid=gid, password=password, modified=modified)
        self.administrators = administrators
        self.members = members

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Group):
            return False

        return self.as_tuple == other.as_tuple

    def __ne__(self, other: Any) -> bool:
        if not isinstance(other, Group):
            return True

        return self.as_tuple != other.as_tuple

    def __lt__(self, other: "Group") -> bool:
        self._lt_check_other_type(other)
        return self.as_tuple < other.as_tuple

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

    def add_member(self, name: str) -> None:
        """
        Add a user to this group.
        """
        if not isinstance(name, str):
            raise TypeError("name must be a string")

        if not NAME_PATTERN.match(name):
            raise ValueError(f"name contains illegal characters: {name}")

        self._members.add(name)

    def remove_member(self, name: str) -> None:
        """
        Remove a user from this group.
        """
        self._members.remove(name)

    @property
    def as_tuple(self) -> GroupTuple:
        """
        The group represented as an immutable tuple object.
        """
        return GroupTuple(
            name=self.name,
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

        The name field cannot be updated.

        The return value is the value of the modified flag.
        """
        super(Group, self).update_from_dynamodb_item(item)

        administrators = set(item.get("Administrators", {}).get("SS", []))
        if self.administrators != administrators:
            self.administrators = administrators
            self.modified = True

        members = set(item.get("Members", {}).get("SS", []))
        if self.members != members:
            self.members = members
            self.modified = True

        return self.modified

    @classmethod
    def from_dynamodb_item(cls: Type[G], item: Dict[str, Any]) -> G:
        """
        Group.from_dynamodb_item(item: Dict[str, Any]) -> Group
        Create a group from a given DynamoDB item. The modified flag is
        automatically set to true.
        """
        return cls(
            name=item["Name"]["S"],
            gid=int(item["GID"]["N"]),
            password=item.get("Password", {}).get("S"),
            administrators=set(item.get("Administrators", {}).get("SS", [])),
            members=set(item.get("Members", {}).get("SS", [])),
            modified=True)
