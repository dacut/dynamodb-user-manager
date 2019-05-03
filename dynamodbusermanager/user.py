"""
Class for manipulating user information.
"""
from os import geteuid, seteuid
from re import compile as re_compile
from subprocess import run, CalledProcessError
from typing import Collection, Optional, List, Set, Tuple, Union

UID_MIN = 1
UID_MAX = 0xffffffff
GID_MIN = 1
GID_MAX = 0xffffffff

USERADD = b"/usr/sbin/useradd"
USERDEL = b"/usr/sbin/userdel"
USERMOD = b"/usr/sbin/usermod"

# /usr/include/bits/local_lim.h
LOGIN_NAME_MAX = 256

# Usernames are not well-defined, but we limit them to the POSIX 3.437 rules to
# avoid compatibility problems.
# http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_437
# Which limit them to the portable filename character set:
# http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_282
# ASCII letters, digits, period, underscore, hyphen. The hyphen cannot be the
# first character of the username.
USERNAME_PATTERN = re_compile(r"^[a-zA-Z0-9_\.][-a-zA-Z0-9_\.]*$")

# There's no real limit on what can go into real names (GECOS/comment fields)
# except colons (\x3a) and newlines are forbidden. We also disallow vertical
# tabs, form feeds, and NULs, but otherwise allow the entire Unicode character
# set.
REAL_NAME_PATTERN = re_compile(r"^[^:\n\v\f\0]*$")

# There's no defined limit on the GECOS field, but 512 is a common buffer
# size for the entire passwd line. Given that we allow 256 characters for
# the username, we limit the real name to 128 bytes
REAL_NAME_MAX = 128

# Filenames can have anything except colons. We require them to be absolute
# paths and not have redundant or trailing slashes.
FILENAME_PATTERN = re_compile(r"^(/[^:/]+)+|/$")

class User(object):
    def __init__(self, username: str, real_name: str, uid: int,
                 groups: Collection[str], home_dir: str, shell: str,
                 password: Optional[str] = None,
                 ) -> None:
        """
        User(username: str, real_name: str, uid: int, groups: Collection[str],
             home_dir: str, shell: str, password: Optional[str] = None) -> User
        Create a new User object.
        """
        super(User, self).__init__()
        self.username = username
        self.real_name = real_name
        self.uid = uid
        self.groups = groups
        self.home_dir = home_dir
        self.shell = shell
        self.password = password
        return
    
    @property
    def username(self) -> str:
        return self._username
    
    @username.setter
    def username(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("username must be a string")
        elif len(value) == 0:
            raise ValueError("username cannot be empty")
        elif len(value) > LOGIN_NAME_MAX:
            raise ValueError(
                f"username cannot be longer than {LOGIN_NAME_MAX} characters")
        elif not USERNAME_PATTERN.match(value):
            raise ValueError("username contains illegal characters")
        
        self._username = value
    
    @property
    def real_name(self) -> str:
        return self._real_name
    
    @real_name.setter
    def real_name(self, value: Optional[str]) -> None:
        if value is None:
            self._real_name = ""
            return
        
        if not isinstance(value, str):
            raise TypeError("real_name must be a string or None")
        elif not REAL_NAME_PATTERN.match(value):
            raise ValueError("real_name contains illegal characters")
        elif len(value.encode("utf-8")) > REAL_NAME_MAX:
            raise ValueError(
                f"real_name is longer than {REAL_NAME_MAX} bytes (UTF-8 encoded)")
        
        self._real_name = value
        return

    @property
    def uid(self) -> str:
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
    def groups(self) -> Set[str]:
        return set(self._groups)
    
    @groups.setter
    def groups(self, value: Union[List[str],Set[str],Tuple[str]]) -> None:
        if (not isinstance(value, (list, set, tuple)) or
            not all([isinstance(el, str) for el in value])):
            raise TypeError("groups must be a list, set, or tuple of strings")
        
        for group in value:
            if not group:
                raise ValueError("group names cannot be empty")

            if not USERNAME_PATTERN.match(group):
                raise ValueError(f"group contains illegal characters: {group}")
            
        self._groups = set(value)
        return
    
    @property
    def home_dir(self) -> str:
        return self._home_dir
    
    @home_dir.setter
    def home_dir(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("home_dir must be a string")
        
        if not FILENAME_PATTERN.match(value):
            raise ValueError(
                "home_dir is not an absolute path or contains doubled or "
                f"trailing slashes: {value}")
        
        self._home_dir = value
        return

    @property
    def shell(self) -> str:
        return self._shell
    
    @shell.setter
    def shell(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("shell must be a string")
        
        if not FILENAME_PATTERN.match(value):
            raise ValueError(
                "shell is not an absolute path or contains doubled or "
                f"trailing slashes: {value}")
        
        self._shell = value
        return
    
    @property
    def password(self) -> Optional[str]:
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

    def create(self, allow_duplicate_uid: bool = False) -> None:
        """
        user.create(allow_duplicate_uid: bool = False) -> None
        Create the user.
        """
        cmd = [
            USERADD, b"--comment", self.real_name.encode("utf-8"),
            b"--home-dir", self.home_dir.encode("utf-8"),
            b"--create-home", b"--shell", self.shell.encode("utf-8"),
            b"--uid", b"%d" % self.uid, b"--user-group"
        ]

        if allow_duplicate_uid:
            cmd += [b"--non-unique"]

        if self.password:
            cmd += [b"--password", self.password.encode("utf-8")]

        if self.groups:
            cmd += [b"--groups", ",".join(self.groups).encode("utf-8")]
        
        cmd.append(self.username.encode("utf-8"))

        euid = geteuid()
        if euid != 0:
            seteuid(0)
        try:
            cp = run(cmd, capture_output=True, encoding="utf-8")
        finally:
            if euid != 0:
                seteuid(euid)

        if cp.returncode == 1:
            raise RuntimeError("Failed to update passwd file")
        elif cp.returncode == 2 or cp.returncode == 3:
            raise RuntimeError(f"Internal failure: Invalid invocation of useradd: {cp.stderr.strip()}")
        elif cp.returncode == 4:
            raise ValueError(f"Duplicate UID: {self.uid}")
        elif cp.returncode == 5:
            raise ValueError("Group(s) do not exist")
        elif cp.returncode == 9:
            raise ValueError(f"Username already in use: {self.username}")
        elif cp.returncode == 10:
            raise RuntimeError("Failed to update group file")
        elif cp.returncode == 12:
            raise RuntimeError("Failed to create home directory")
        elif cp.returncode != 0:
            raise RuntimeError(f"Unknown useradd failure ({cp.returncode}): {cp.stderr.strip()}")
        
        return
    
    def delete(self) -> None:
        """
        user.delete() -> None
        Delete the user.
        """
        cmd = [USERDEL, self.username.encode("utf-8")]

        euid = geteuid()
        if euid != 0:
            seteuid(0)
        try:
            cp = run(cmd, capture_output=True, encoding="utf-8")
        finally:
            if euid != 0:
                seteuid(euid)
        
        if cp.returncode == 1:
            raise RuntimeError("Failed to update passwd file")
        elif cp.returncode == 2 or cp.returncode == 3:
            raise RuntimeError(f"Internal failure: Invalid invocation of userdel: {cp.stderr.strip()}")
        elif cp.returncode == 6:
            raise ValueError("User does not exist")
        elif cp.returncode == 8:
            raise ValueError("User is currently logged in")
        elif cp.returncode == 10:
            raise RuntimeError("Failed to update group file")
        elif cp.returncode == 12:
            raise RuntimeError("Failed to remove home directory")
        elif cp.returncode != 0:
            raise RuntimeError(f"Unknown userdel failure ({cp.returncode}): {cp.stderr.strip()}")
        
        return

    def update(self) -> None:
        """
        user.update() -> None
        Update the user.
        """
        cmd = [
            USERMOD, b"--comment", self.real_name.encode("utf-8"),
            b"--home", self.home_dir.encode("utf-8"),
            b"--shell", self.shell.encode("utf-8"),
            b"--groups", ",".join(self.groups).encode("utf-8"),
            b"--uid", b"%d" % self.uid, self.username.encode("utf-8")
        ]

        euid = geteuid()
        if euid != 0:
            seteuid(0)
        try:
            cp = run(cmd, capture_output=True, encoding="utf-8")
        finally:
            if euid != 0:
                seteuid(euid)
        
        if cp.returncode == 1:
            raise RuntimeError("Failed to update passwd file")
        elif cp.returncode == 2 or cp.returncode == 3:
            raise RuntimeError(f"Internal failure: Invalid invocation of usermod: {cp.stderr.strip()}")
        elif cp.returncode == 4:
            raise ValueError(f"Duplicate UID: {self.uid}")
        elif cp.returncode == 6:
            raise ValueError("User/group does not exist")
        elif cp.returncode == 8:
            raise ValueError("User is currently logged in")
        elif cp.returncode == 9:
            raise ValueError("Username is already in use")
        elif cp.returncode == 10:
            raise RuntimeError("Failed to update group file")
        elif cp.returncode == 12:
            raise RuntimeError("Failed to move home directory")
        elif cp.returncode != 0:
            raise RuntimeError(f"Unknown usermod failure ({cp.returncode}): {cp.stderr.strip()}")
        
        return
