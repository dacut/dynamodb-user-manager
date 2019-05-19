"""
Defines the Entity class, a common base class for users and groups on Unix
systems.
"""
from typing import Any, Dict, Optional
from .constants import GID_MIN, GID_MAX, NAME_MAX_LENGTH, NAME_PATTERN

class Entity():
    """
    Common base class for users and groups.
    """
    # pylint: disable=W0201,R0902

    def __init__(
            self, name: str, gid: int, password: Optional[str] = None,
            modified: bool = False) -> None:
        """
Entity(
    name: str, gid: int, password: Optional[str] = None,
    modified: bool = False) -> Entity
Create a new entity with the specified name, group id, and optional
password.

Each entity also holds a modified flag indicating whether it has been
modified in-memory from its database files (/etc/passwd, /etc/group,
etc.)
        """
        super(Entity, self).__init__()
        self.name = name
        self.gid = gid
        self.password = password
        self.modified = modified

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Entity):
            return False

        return (self.name == other.name and
                self.gid == other.gid and
                self.password == other.password and
                self.modified == other.modified)

    def __ne__(self, other: Any) -> bool:
        if not isinstance(other, Entity):
            return True

        return (self.name != other.name or
                self.gid != other.gid or
                self.password != other.password or
                self.modified != other.modified)

    @property
    def name(self) -> str:
        """
        The name of the entity.
        """
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("name must be a string")
        if not value:
            raise ValueError("name cannot be empty")
        if len(value) > NAME_MAX_LENGTH:
            raise ValueError(
                f"name cannot be longer than {NAME_MAX_LENGTH} characters")
        if not NAME_PATTERN.match(value):
            raise ValueError("name contains illegal characters")

        self._name = value

    @property
    def gid(self) -> int:
        """
        The integer group id of the entity.
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
    def password(self) -> Optional[str]:
        """
        The hashed password of the entity.
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
        return

    @property
    def modified(self) -> bool:
        """
        Indicates whether the entity has been modified from the on-disk
        representation.
        """
        return self._modified

    @modified.setter
    def modified(self, value: bool) -> None:
        self._modified = bool(value)

    def _lt_check_other_type(self, other: Any) -> None:
        """
        Verifies that the other type is the same as this type.
        """
        if not isinstance(other, self.__class__):
            raise TypeError(
                f"'<' not supported between instances of "
                f"{type(self).__name__!r} and {type(other).__name__!r}")

    def update_from_dynamodb_item(self, item: Dict[str, Any]) -> bool:
        """
        user.update_from_dynamodb_item(item: Dict[str, Any]) -> bool
        Update the group from a given DynamoDB item. If an attribute has been
        modified, the modified flag is set to true.

        The name field cannot be updated.

        The return value is the value of the modified flag.
        """
        if self.name != item["Name"]["S"]:
            raise ValueError("Cannot update name")

        gid = int(item["GID"]["N"])
        if self.gid != gid:
            self.gid = gid
            self.modified = True

        password = item.get("Password", {}).get("S")
        if self.password != password:
            self.password = password
            self.modified = True

        return self.modified
