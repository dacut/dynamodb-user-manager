"""
Routines for manipulating the password, group, and their associated shadow
files.
"""
from ctypes import CDLL, c_int, get_errno
from datetime import timedelta
from errno import EAGAIN, EEXIST, EIO, EINVAL, ESRCH
from fcntl import lockf, LOCK_EX, LOCK_SH, LOCK_UN
from functools import partial
from logging import getLogger
from os import (
    chmod, close as os_close, fsync, getpid, kill, link,
    open as os_open, rename, stat, strerror, umask, unlink,
    O_CLOEXEC, O_CREAT, O_TRUNC, O_WRONLY, O_RDWR)
from os.path import exists
from stat import S_IMODE
from time import sleep, time
from typing import (
    Any, Callable, Dict, List, Optional, Set, TextIO, Tuple, Union)
from .constants import (
    EPOCH, FIELD_FIX, FIELD_PATTERN, GID_MIN, GID_MAX, GROUP_FILE, GSHADOW_FILE,
    LOCK_ALL, LOCK_GROUP, LOCK_GSHADOW, LOCK_PASSWD, LOCK_SHADOW,
    LOGIN_DEFS_FILE, LOGIN_DEFS_PATTERN, NAME_PATTERN, NAME_MAX_LENGTH,
    NUMERIC_FIELD_PATTERN, PASSWD_FILE, SHADOW_FILE, UID_MIN, UID_MAX)
from .group import Group
from .user import User
from .utils import (
    ChangeEffectiveId, ensure_user_owns_dir, ensure_user_owns_file, parse_bool)

# pylint: disable=C0103,C0302,C0325,R0912,R0914,R0915

log = getLogger(__name__)

class ShadowDatabase():
    """
    State manager and rules for manipulating the user and group database files:
    /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow.
    """
    login_defs_converters = {
        "CHFN_AUTH": parse_bool,
        "CHFN_RESTRICT": str,
        "CHSH_AUTH": parse_bool,
        "CONSOLE": str,
        "CONSOLE_GROUPS": str,
        "CREATE_HOME": parse_bool,
        "DEFAULT_HOME": parse_bool,
        "ENCRYPT_METHOD": str,
        "ENV_HZ": str,
        "ENV_PATH": str,
        "ENV_SUPATH": str,
        "ENV_TZ": str,
        "ENVIRON_FILE": str,
        "ERASECHAR": int,
        "FAIL_DELAY": int,
        "FAILLOG_ENAB": parse_bool,
        "FAKE_SHELL": str,
        "FTMP_FILE": str,
        "GID_MAX": int,
        "GID_MIN": int,
        "HUSHLOGIN_FILE": str,
        "ISSUE_FILE": str,
        "KILLCHAR": int,
        "LASTLOG_ENAB": parse_bool,
        "LOG_OK_LOGINS": parse_bool,
        "LOG_UNKFAIL_ENAB": parse_bool,
        "LOGIN_RETRIES": int,
        "LOGIN_STRING": str,
        "LOGIN_TIMEOUT": int,
        "MAIL_CHECK_ENAB": parse_bool,
        "MAIL_DIR": str,
        "MAIL_FILE": str,
        "MAX_MEMBERS_PER_GROUP": int,
        "MD5_CRYPT_ENAB": parse_bool,
        "MOTD_FILE": str,
        "NOLOGINS_FILE": str,
        "OBSCURE_CHECKS_ENAB": parse_bool,
        "PASS_ALWAYS_WARN": parse_bool,
        "PASS_CHANGE_TRIES": int,
        "PASS_MAX_DAYS": int,
        "PASS_MIN_DAYS": int,
        "PASS_WARN_AGE": int,
        "PASS_MAX_LEN": int,
        "PASS_MIN_LEN": int,
        "PORTTIME_CHECKS_ENAB": parse_bool,
        "QUOTAS_ENAB": parse_bool,
        "SHA_CRYPT_MIN_ROUNDS": int,
        "SHA_CRYPT_MAX_ROUNDS": int,
        "SULOG_FILE": str,
        "SU_NAME": str,
        "SU_WHEEL_ONLY": parse_bool,
        "SYS_GID_MAX": int,
        "SYS_GID_MIN": int,
        "SYS_UID_MAX": int,
        "SYS_UID_MIN": int,
        "SYSLOG_SG_ENAB": parse_bool,
        "SYSLOG_SU_ENAB": parse_bool,
        "TTYGROUP": str,
        "TTYPERM": str,
        "TTYTYPE_FILE": str,
        "UID_MAX": int,
        "UID_MIN": int,
        "ULIMIT": int,
        "UMASK": lambda s: int(s, 8),
        "USERDEL_CMD": str,
        "USERGROUPS_ENAB": parse_bool,
    }  # type: Dict[str, Callable[[str], Any]]

    def __init__(self, skip_load: bool = False) -> None:
        """
        ShadowDatabase() -> ShadowDatabase
        Create a new shadow database object, initialized from the shadow
        database files.
        """
        super(ShadowDatabase, self).__init__()
        self.config = {}     # type: Dict[str, Any]
        self.users = {}     # type: Dict[str, User]
        self.groups = {}    # type: Dict[str, Group]
        if not skip_load:
            self.reload()

    def reload(self) -> None:
        """
        shadow_db.reload() -> None
        Reload configuration from /etc/login.defs, and users and groups from
        the shadow database files.
        """
        self.config = {}    # type: Dict[str, Any]
        self.users = {}     # type: Dict[str, User]
        self.groups = {}    # type: Dict[str, Group]

        self.load_login_defs()

        with ShadowDatabaseLock(timeout=15):
            self.load_passwd_file()
            self.load_group_file()
            self.load_gshadow_file()
            self.load_shadow_file()

        self._load_ssh_public_keys()

    def write(self) -> None:
        """
        shadow_db.write() -> None
        Write the users and groups to the shadow database files.
        """
        with ShadowDatabaseLock(timeout=15):
            self._write_user_plus_files()
            self._write_group_plus_files()
            self._rotate_files()

    @property
    def modified(self) -> bool:
        """
        Indicates whether any users or groups have been modified.
        """
        for user in self.users.values():
            if user.modified:
                return True

        for group in self.groups.values():
            if group.modified:
                return True

        return False

    def load_login_defs(self, filename: str = LOGIN_DEFS_FILE) -> None:
        """
        shadow_db.load_login_defs(filename: str = "/etc/login.defs") -> None
        Load the /etc/login.defs file and populate self.config.
        """
        with open(filename, "r") as fd:
            for line in fd:
                line = line.strip()
                m = LOGIN_DEFS_PATTERN.match(line)
                if not m:
                    continue

                key = m.group("key")
                value = m.group("value")

                conv = self.login_defs_converters.get(key)
                if conv:
                    try:
                        value = conv(value)
                    except (TypeError, ValueError) as e:
                        log.error(
                            "Failed to convert login.defs %r=%r: %s", key,
                            value, e)
                self.config[key] = value

    def load_passwd_file(self, filename: str = PASSWD_FILE) -> None:
        """
        shadow_db.load_passwd_file(filename: str = "/etc/passwd") -> None
        Populate users and (some of) their attributes from the /etc/passwd
        file.

        This should be called with the database lock held if PASSWD_FILE is
        being read.
        """
        with open(filename, "r") as fd:
            for line in fd:
                line = line.rstrip()

                # Skip blank lines
                if not line:
                    continue

                parts = line.split(":")
                # Format should be 7 parts:
                # name:password:UID:GID:GECOS:directory:shell
                # password should be 'x' to force use of the shadow file.
                if len(parts) != 7:
                    log.warning("Invalid passwd entry: %s", line)
                    continue

                (name, password, uid_str, gid_str, real_name, home,
                 shell) = parts
                modified = False

                if not NAME_PATTERN.match(name):
                    log.error("Invalid passwd entry (bad name): %r", line)
                    continue

                if len(name) > NAME_MAX_LENGTH:
                    log.error(
                        "Invalid passwd entry (name too long): %r", line)
                    continue

                if password != 'x':
                    log.warning(
                        "Password for user %s is not set to the shadow file; "
                        "this will be forced when passwd is overwritten",
                        name)

                try:
                    uid = int(uid_str)
                    if not (UID_MIN <= uid <= UID_MAX):
                        raise ValueError()
                except ValueError:
                    log.error("Invalid passwd entry (bad UID): %r", line)
                    continue

                try:
                    gid = int(gid_str)
                    if not (GID_MIN <= gid <= GID_MAX):
                        raise ValueError()
                except ValueError:
                    log.error("Invalid passwd entry (bad GID): %r", line)
                    continue

                if not FIELD_PATTERN.match(real_name):
                    log.warning(
                        "Invalid passwd entry (bad real_name/GECOS): %r", line)
                    real_name = FIELD_FIX.sub("-", real_name)

                if not FIELD_PATTERN.match(home):
                    log.warning(
                        "Invalid passwd entry (bad home): %r", line)
                    home = "/"
                    modified = True

                if not FIELD_PATTERN.match(shell):
                    log.warning(
                        "Invalid passwd entry (bad shell): %r", line)
                    shell = "/bin/false"
                    modified = True

                self.users[name] = User(
                    name=name, uid=uid, gid=gid, real_name=real_name,
                    home=home, shell=shell, modified=modified)

    def load_group_file(self, filename: str = GROUP_FILE) -> None:
        """
        shadow_db.load_group_file(filename: str = "/etc/groups") -> None
        Populate groups, user-group-memberships, and (some of) their
        attributes from the /etc/group file.

        This should be called with the database lock held if GROUP_FILE is
        being read.
        """
        with open(filename, "r") as fd:
            for line in fd:
                line = line.rstrip()

                # Skip blank lines
                if not line:
                    continue

                parts = line.split(":")
                # Format should be 4 parts:
                # name:password:GID:members
                # password should be 'x' to force use of the shadow file.
                if len(parts) != 4:
                    log.warning("Invalid group entry: %s", line)
                    continue

                name, password, gid_str, members_str = parts
                modified = False

                if not NAME_PATTERN.match(name):
                    log.error("Invalid group entry (bad name): %r", line)
                    continue

                if len(name) > NAME_MAX_LENGTH:
                    log.error(
                        "Invalid group entry (name too long): %r", line)
                    continue

                if password != 'x':
                    log.warning(
                        "Password for group %s is not set to the shadow file; "
                        "this will be forced when passwd is overwritten",
                        name)

                try:
                    gid = int(gid_str)
                    if not (GID_MIN <= gid <= GID_MAX):
                        raise ValueError()
                except ValueError:
                    log.error("Invalid group entry (bad GID): %r", line)
                    continue

                if not FIELD_PATTERN.match(members_str):
                    log.warning(
                        "Invalid group entry (bad members list): %r", line)
                    members = set() # type: Set[str]
                    modified = True
                elif not members_str.strip():
                    members = set()
                else:
                    members = {
                        member.strip() for member in members_str.split(",")}
                    filtered_members = {
                        m for m in members if NAME_PATTERN.match(m)}
                    if filtered_members != members:
                        log.warning(
                            "Invalid group entry (bad members list): %r", line)
                        members = filtered_members
                        modified = True

                self.groups[name] = Group(
                    name=name, gid=gid, members=members,
                    modified=modified)

    def load_gshadow_file(self, filename: str = GSHADOW_FILE) -> None:
        """
        shadow_db.load_gshadow_file(filename: str = "/etc/gshadow") -> None
        Populate group passwords, administrators, and re-validate members
        from the /etc/gshadow file.

        This should be called with the database lock held if GSHADOW_FILE is
        being read.
        """

        # WARNING: Never log a line from the gshadow file. An errant typo in
        # the file could cause the password to be logged. In the log statements
        # below, we always refer to line numbers instead.
        with open(filename, "r") as fd:
            for line_no, line in enumerate(fd):
                line_no += 1 # Print 1-based line numbers
                line = line.rstrip()

                # Skip blank lines
                if not line:
                    continue

                parts = line.split(":")
                # Format should be 4 parts:
                # name:encrypted_password:administrators:members
                if len(parts) != 4:
                    log.warning("Invalid gshadow entry (line %d)", line_no + 1)
                    continue

                name, password, administrators_str, members_str = parts

                group = self.groups.get(name)
                if group is None:
                    log.error("%s:%d: Unknown group", GSHADOW_FILE, line_no)
                    continue

                if not FIELD_PATTERN.match(password):
                    log.warning(
                        "%s:%d: Bad character in password", GSHADOW_FILE,
                        line_no)
                    group.password = '!'
                    group.modified = True

                if not FIELD_PATTERN.match(administrators_str):
                    log.warning(
                        "%s:%d: Bad character in administrators", GSHADOW_FILE,
                        line_no)
                    group.administrators = set()
                    group.modified = True
                elif not administrators_str:
                    group.administrators = set()
                else:
                    admins = {
                        a.strip() for a in administrators_str.split(",")}
                    filtered_admins = {
                        a for a in admins if NAME_PATTERN.match(a)}
                    group.administrators = filtered_admins
                    if admins != filtered_admins:
                        log.warning(
                            "%s:%d: Bad character in administrators",
                            GSHADOW_FILE, line_no)
                        group.modified = True

                if not FIELD_PATTERN.match(members_str):
                    log.warning(
                        "%s:%d: Bad character in members", GSHADOW_FILE,
                        line_no)
                elif not members_str:
                    group.members = set()
                else:
                    members = {a.strip() for a in members_str.split(",")}
                    filtered_members = {
                        a for a in members if NAME_PATTERN.match(a)}
                    if members != filtered_members:
                        log.warning(
                            "%s:%d: Bad character in members", GSHADOW_FILE,
                            line_no)
                        members = filtered_members

                    if members != group.members:
                        log.warning(
                            "%s:%d: Inconsistent group membership in gshadow "
                            "and group file", GSHADOW_FILE, line_no)

                        group.members.update(members)
                        group.modified = True

    def load_shadow_file(self, filename: str = SHADOW_FILE) -> None:
        """
        shadow_db.load_shadow_file(filename: str = "/etc/shadow") -> None
        Populate user passwords and password policies from the /etc/shadow file.

        This should be called with the database lock held if SHADOW_FILE is
        being read.
        """

        # WARNING: Never log a line from the shadow file. An errant typo in
        # the file could cause the password to be logged. In the log statements
        # below, we always refer to line numbers instead.
        with open(filename, "r") as fd:
            for line_no, line in enumerate(fd):
                line_no += 1 # Print 1-based line numbers
                line = line.rstrip()

                # Skip blank lines
                if not line:
                    continue

                parts = line.split(":")
                # Format should be 9 parts, but we'll tolerate 8.
                # user_name:encrypted_password:last_password_change_date:
                # password_age_min_days:password_age_max_days:
                # password_warn_days:password_disable_days:account_expire_date:
                # flags(unused)
                if not (8 <= len(parts) <= 9):
                    log.warning("Invalid shadow entry (line %d)", line_no)
                    continue

                user_name = parts[0]
                password = parts[1]

                (user_name, password, last_password_change_date,
                 password_age_min_days, password_age_max_days,
                 password_warn_days, password_disable_days,
                 account_expire_date) = parts[:8]

                user = self.users.get(user_name)
                if user is None:
                    log.error("%s:%d: Unknown user", SHADOW_FILE, line_no)
                    continue

                if not FIELD_PATTERN.match(password):
                    log.warning(
                        "%s:%d: Bad character in password", SHADOW_FILE,
                        line_no)
                    user.password = '!'
                    user.modified = True
                else:
                    user.password = password

                self._parse_shadow_date_field(
                    user, last_password_change_date,
                    "last_password_change_date", line_no)
                self._parse_shadow_int_field(
                    user, password_age_min_days, "password_age_min_days",
                    line_no)
                self._parse_shadow_int_field(
                    user, password_age_max_days, "password_age_max_days",
                    line_no)
                self._parse_shadow_int_field(
                    user, password_warn_days, "password_warn_days",
                    line_no)
                self._parse_shadow_int_field(
                    user, password_disable_days, "password_disable_days",
                    line_no)
                self._parse_shadow_date_field(
                    user, account_expire_date, "account_expire_date", line_no)

    def _load_ssh_public_keys(self) -> None:
        """
        shadowdb._load_ssh_public_keys() -> None
        Load the SSH public keys for each user.
        """
        for user in self.users.values():
            # By default, the user does not have an ssh_public_key.
            auth_keys = user.authorized_keys
            if user.ssh_public_keys != auth_keys:
                user.ssh_public_keys = auth_keys # type: ignore
                user.modified = True

    @staticmethod
    def _parse_shadow_date_field(user: User, value: str, name: str, line_no: int) -> None:
        """
        ShadowDatabase._parse_shadow_date_field(value: str, name: str, line_no: int) -> None
        Parse an optional date field (in integer form, number of days since
        Jan 1, 1970) from the shadow file.

        If it is invalid, log an error without logging its content for security
        purposes (in case the shadow file is malformed and the hashed password
        has overflown into this field); set the field to None and indicate the
        user has been modified from the shadow contents.

        If it is empty, set the field to None.

        Otherwise, set the field to the date this value represents.
        """
        if not NUMERIC_FIELD_PATTERN.match(value):
            log.warning("%s:%d Bad character in %s", SHADOW_FILE, line_no, name)
            setattr(user, name, None)
            user.modified = True
        elif not value:
            setattr(user, name, None)
        else:
            date_value = EPOCH + timedelta(days=int(value))
            setattr(user, name, date_value)

    @staticmethod
    def _parse_shadow_int_field(user: User, value: str, name: str, line_no: int) -> None:
        """
        ShadowDatabase._parse_shadow_int_field(value: str, name: str, line_no: int) -> None
        Parse an optional integer field from the shadow file.

        If it is invalid, log an error without logging its content for security
        purposes (in case the shadow file is malformed and the hashed password
        has overflown into this field); set the field to None and indicate the
        user has been modified from the shadow contents.

        If it is empty, set the field to None.

        Otherwise, set the field to the integer value this value represents.
        """
        if not NUMERIC_FIELD_PATTERN.match(value):
            log.warning("%s:%d Bad character in %s", SHADOW_FILE, line_no, name)
            setattr(user, name, None)
            user.modified = True
        elif not value:
            setattr(user, name, None)
        else:
            setattr(user, name, int(value))

    def _write_user_plus_files(self) -> None:
        """
        shadow_db.write_user_plus_files() -> None
        Write users out to the /etc/passwd+ and /etc/shadow+ files. These are
        written to instead of modifying /etc/passwd and /etc/shadow directly
        to avoid race conditions.

        This should be called with the database lock held.
        """
        with ShadowWriter(PASSWD_FILE + "+", SHADOW_FILE + "+") as (pfd, sfd):
            for user in sorted(self.users.values(), key=lambda u: u.uid):
                self._write_user(user, pfd, sfd)
                user.modified = False

    def _write_group_plus_files(self) -> None:
        """
        shadow_db.write_group_plus_files() -> None
        Write groups out to the /etc/group+ and /etc/gshadow+ files. These are
        written to instead of modifying /etc/group and /etc/gshadow directly
        to avoid race conditions.

        This should be called with the database lock held.
        """
        with ShadowWriter(GROUP_FILE + "+", GSHADOW_FILE + "+") as (gfd, gsfd):
            for group in sorted(self.groups.values(), key=lambda g: g.gid):
                self._write_group(group, gfd, gsfd)
                group.modified = False

    @staticmethod
    def _write_user(user: User, passwd: TextIO, shadow: TextIO) -> None:
        """
        ShadowDatabase.write_user(
            user: User, passwd: TextIO, shadow: TextIO) -> None
        Write the specified user out to the passwd+ and shadow+ files, and
        to the user's ~/.ssh/authorized_keys file.
        """
        name = user.name
        # passwd format is 7 parts:
        # name:password:UID:GID:GECOS:directory:shell
        # password is 'x' to force use of the shadow file.
        passwd.write(
            f"{name}:x:{user.uid}:{user.gid}:"
            f"{user.real_name}:{user.home}:{user.shell}\n")

        # shadow format is 9 parts:
        # user_name:encrypted_password:last_password_change_date:
        # password_age_min_days:password_age_max_days:
        # password_warn_days:password_disable_days:account_expire_date:
        # flags(unused)
        password = (user.password if user.password is not None else "!!")
        change_days_str = (
            str((user.last_password_change_date - EPOCH).days)
            if user.last_password_change_date is not None else "")
        age_min_str = (
            str(user.password_age_min_days)
            if user.password_age_min_days is not None else "")
        age_max_str = (
            str(user.password_age_max_days)
            if user.password_age_max_days is not None else "")
        warn_days_str = (
            str(user.password_warn_days)
            if user.password_warn_days is not None else "")
        disable_days_str = (
            str(user.password_disable_days)
            if user.password_disable_days is not None else "")
        expire_days_str = (
            str((user.account_expire_date - EPOCH).days)
            if user.account_expire_date is not None else "")

        shadow.write(
            f"{name}:{password}:{change_days_str}:{age_min_str}:"
            f"{age_max_str}:{warn_days_str}:{disable_days_str}:"
            f"{expire_days_str}:\n")

    def create_user_home(self, user: User) -> None:
        """
        shadowdb.create_user_home(user: User) -> None
        Create the home directory for the user if it does not already exist.
        """
        home = user.home
        home_mask = self.config.get("UMASK")
        if home_mask is None:
            log.debug("UMASK is not configured in /etc/login.defs; assuming 0o022")
            home_mask = 0o022
        else:
            log.debug("UMASK set to %03o", home_mask)

        home_mode = 0o777 & ~home_mask
        log.debug("home_mode set to %03o", home_mode)

        if not home:
            log.warning(
                "User %s does not have a home directory set", user.name)
        else:
            ensure_user_owns_dir(user.uid, user.gid, home, home_mode)

    def write_user_ssh_keys(self, user: User) -> None:
        """
        shadowdb.write_user_ssh_keys(user: User) -> None
        Write the user's ssh public keys to their ~/.ssh/authorized_keys file,
        ensuring that ~/.ssh and ~/.ssh/authorized_keys exist, are owned by
        the user, and are only writable by the user.

        This does not re-write the file if it already has the correct contents.
        """
        mask = self.config.get("UMASK", 0o022)
        dir_mode = 0o777 & ~mask
        file_mode = 0o666 & ~mask

        if not user.home:
            log.warning(
                "User %s does not have a home directory -- unable to write "
                "public keys.", user.name)
            return

        if not exists(user.home):
            log.warning(
                "User %s home directory %s does not exist", user.name,
                user.home)
            return

        ssh_dir = user.home + "/.ssh"
        auth_keys_file = ssh_dir + "/authorized_keys"
        auth_keys = "\n".join(sorted(user.ssh_public_keys)) + "\n"
        ensure_user_owns_dir(user.uid, user.gid, ssh_dir, dir_mode, 0o722)
        ensure_user_owns_file(user.uid, auth_keys_file, file_mode, 0o722)

        with ChangeEffectiveId(user.uid, user.gid):
            orig_umask = umask(0)
            try:
                osfd = os_open(
                    auth_keys_file, O_RDWR | O_CREAT | O_CLOEXEC, file_mode)
            finally:
                umask(orig_umask)

            with open(osfd, "r+") as fd:
                lockf(fd.fileno(), LOCK_SH)
                try:
                    existing = fd.read()
                    if existing != auth_keys:
                        # Need to rewrite.
                        fd.seek(0)
                        lockf(osfd, LOCK_EX)
                        fd.write(auth_keys)
                        fd.flush()
                        fsync(fd.fileno())
                finally:
                    lockf(fd.fileno(), LOCK_UN)

    @staticmethod
    def _write_group(group: Group, gfile: TextIO, gshadow: TextIO) -> None:
        """
        ShadowDatabase.write_group(
            group: Group, gfile: TextIO, gshadow: TextIO) -> None
        Write the specified group out to the group+ and gshadow+ files.
        """
        name = group.name
        administrators = ",".join(sorted(group.administrators))
        members = ",".join(sorted(group.members))

        # group format is 4 parts:
        # name:password:GID:members
        # password is 'x' to force use of the shadow file.
        gfile.write(f"{name}:x:{group.gid}:{members}\n")

        # gshadow format is 4 parts:
        # name:encrypted_password:administrators:members
        password_str = (
            group.password if group.password is not None else "!")

        gshadow.write(f"{name}:{password_str}:{administrators}:{members}\n")

    @staticmethod
    def _rotate_files() -> None:
        """
        ShadowDatabase._rotate_files() -> None
        Remove any database backup files (with a '-' suffix). Rename the
        current files to the backup names. Rename the new files (with a '+'
        suffix) to the current names.

        This should be called with the database lock held.
        """
        for filename in (PASSWD_FILE, SHADOW_FILE, GROUP_FILE, GSHADOW_FILE):
            backup_filename = filename + "-"
            new_filename = filename + "+"

            assert exists(new_filename)

            if exists(backup_filename):
                unlink(backup_filename)

            rename(filename, backup_filename)
            rename(new_filename, filename)

    @staticmethod
    def _deny_access(filename: str, expected_uid: int, actual_uid: int) -> None:
        """
        ShadowDatabase._deny_access(
            filename: str, expected_uid: int, actual_uid: int) -> None
        Deny access to the specified file or directory by resetting permissions
        to 000.
        """
        log.warning(
            "Expected %s to be owned by uid %d but is owned by uid %d; "
            "setting permissions to 000", filename, expected_uid, actual_uid)
        try:
            chmod(filename, 0)
        except OSError as e:
            log.error("Failed to chmod(%s, 0): %s", filename, e)

    @staticmethod
    def _check_reset_group_other_writable(filename: str, mode: int) -> None:
        """
        ShadowDatabase._check_reset_group_other_writable(
            filename: str, mode: int) -> None
        If filename is writable by group or other, log this information and
        reset those bits.
        """
        group_writable = (mode & 0o020 != 0)
        other_writable = (mode & 0o002 != 0)

        who = []
        if group_writable:
            who.append("group")

        if other_writable:
            who.append("other")

        if not who:
            return

        log.warning(
            "%s is writable by %s; resetting these bits.",
            filename, " and ".join(who))
        chmod(filename, S_IMODE(mode) & 0o755)

class ShadowDatabaseLock():
    """
    Lock manager for the shadow database files.

    Typical usage is as a context manager:
        with ShadowDatabaseLock():
            # Operations on shadow files...
    """

    # libc.so is not an ELF file on most Linux systems; we need to hard-=code
    # libc.so.6 here.
    try:
        _libc = CDLL("libc.so.6")

        # On most systems, libc includes the lckpwdf() and ulckpwdf() functions
        # to lock /etc/shadow.
        _libc.lckpwdf.argtypes = _libc.ulckpwdf.argtypes = ()
        _libc.lckpwdf.restype = _libc.ulckpwdf.restype = c_int
        _os_lckpwdf = _libc.lckpwdf
        _os_ulckpwdf = _libc.ulckpwdf
    except (OSError, AttributeError):
        _os_lckpwdf = None
        _os_ulckpwdf = None

    _shadow_lock_file = "/etc/.pwd.lock"

    # This is a programmatic listing of the lock order and the bits that
    # determine whether to lock the file.
    _lock_order = [
        (LOCK_PASSWD, PASSWD_FILE),
        (LOCK_GROUP, GROUP_FILE),
        (LOCK_GSHADOW, GSHADOW_FILE),
        (LOCK_SHADOW, SHADOW_FILE),
    ]

    def __init__(
            self,
            items: int = LOCK_ALL,
            timeout: Optional[Union[int, float]] = None) -> None:
        """
        ShadowDatabaseLock(
            items: int = LOCK_ALL,
            timeout: Optional[Union[int, float]] = None) -> ShadowDatabaseLock
        Create a lock object but don't acquire the lock (yet).
        The items parameter is a bitwise OR of one or more of the following:
        LOCK_PASSWD, LOCK_GROUP, LOCK_SHADOW, LOCK_GSHADOW. LOCK_ALL includes
        all items.

        The timeout parameter specifies how long (in seconds) to wait for
        each lock. If 0, this tries exactly once. If negative or None, this
        waits forever.
        """
        super(ShadowDatabaseLock, self).__init__()
        self.items = items
        self.timeout = timeout
        self._lckpwdf_fd = None # type: Optional[int]
        self.lock_count = 0

    def _lckpwdf(self) -> None:
        """
        sdlock._lckpwdf() -> None
        Acquire an exclusive lock on the /etc/shadow file, using the
        OS-provided function if possible; otherwise, this opens /etc/.pwd.lock
        and locks it for exclusive access.
        """
        assert self._lckpwdf_fd is None

        if self._os_lckpwdf is not None:
            if self._os_lckpwdf() != 0:
                errno = get_errno()
                raise OSError(errno, strerror(errno))
            self._lckpwdf_fd = -1
        else:
            self._lckpwdf_fd = os_open(
                self._shadow_lock_file, O_WRONLY | O_CREAT | O_CLOEXEC, 0o600)
            lockf(self._lckpwdf_fd, LOCK_EX)

    def _ulckpwdf(self) -> None:
        """
        sdlock._ulckpwdf() -> None
        Relinquish the exclusive lock on the /etc/shadow file, using the
        OS-provided function is possible; otherwise, this unlocks
        /etc/.pwd.lock and closes the handle.
        """
        assert self._lckpwdf_fd is not None
        try:
            if self._lckpwdf_fd == -1:
                assert self._os_ulckpwdf is not None
                if self._os_ulckpwdf() != 0:
                    errno = get_errno()
                    raise OSError(errno, strerror(errno))
            else:
                os_close(self._lckpwdf_fd)
        finally:
            self._lckpwdf_fd = None

    def _lock_file_immediate(self, filename: str) -> None:
        """
        sdlock._lock_file_immediate(filename: str) -> None
        Acquire a shadow-utility lock on the specified shadow database file.

        This follows the pattern used by the shadow utility (which works on
        NFS mounted volumes):
            1. Create a file named $filename.$pid
            2. Write our pid to it.
            3. Hard link a file named $filename.lock to $filename.$pid
            4. Make sure the link count is 2 (directory entry, $filename.lock).
            4. Unlink $filename.$pid.

        If step 3 fails, then it checks to see if $filename.lock exists and
        holds a potentially valid pid. If it does, and no process id with that
        pid exists, it unlinks $filename.lock and attempts steps 3-5 again.

        Otherwise, if any step fails, the lock fails.
        """
        if self.lock_count > 0:
            self.lock_count += 1
            return

        pid = getpid()
        pid_filename = f"{filename}.{pid}"
        lock_filename = f"{filename}.lock"

        # Step 1 -- we use os_open here to control permissions.
        log.debug("Creating pidlock file %s", pid_filename)
        try:
            pid_fd = os_open(pid_filename, O_CREAT | O_TRUNC | O_WRONLY, 0o600)
        except OSError as e:
            log.error("Failed to create pidlock file %s: %s", pid_filename, e)
            raise

        # Step 2 -- write our pid.
        pid_file = open(pid_fd, "w")
        pid_file.write(str(pid))
        pid_file.flush()
        pid_file.close()

        try:
            for retry in range(2):
                # Step 3 -- link $filename.lock to $filename.$pid
                log.debug("Linking lock file %s to pidlock file %s",
                          lock_filename, pid_filename)
                try:
                    link(pid_filename, lock_filename)
                except OSError as e:
                    log.error("Failed to lock: %s", e)
                    if retry > 0 or e.errno != EEXIST:
                        # Already tried this or got a strange error; give up.
                        raise

                    # Can we read the pid from the lock file?
                    log.debug("Getting pid of process holding existing lock")
                    with open(lock_filename, "r+") as lock_file:
                        lock_pid_str = lock_file.read()

                    try:
                        lock_pid = int(lock_pid_str)
                        if lock_pid <= 0:
                            raise ValueError(f"Invalid lock pid {lock_pid}")
                    except ValueError as e:
                        raise OSError(EIO, strerror(EIO)) from e

                    # Does this process exist?
                    try:
                        log.debug(
                            "Checking to see if pid %d is still alive",
                            lock_pid)
                        kill(lock_pid, 0)
                    except OSError as e:
                        if e.errno != ESRCH:
                            log.error(
                                "Failed to kill pid %d with signal 0: %s",
                                lock_pid, e)
                            raise
                    else:
                        log.info("Lock process %d is still alive", lock_pid)
                        if lock_pid == pid:
                            log.error("Lock process %d is our pid!", lock_pid)
                            raise OSError(EIO, strerror(EIO)) from e
                        raise OSError(EAGAIN, strerror(EAGAIN)) from e

                    # Nope; wipe the lock file and try again.
                    log.debug("Removing stale lock file %s", lock_filename)
                    unlink(lock_filename)

                # Step 4 -- verify link count.
                st = stat(pid_filename)
                if st.st_nlink != 2:
                    log.error(
                        "Incorrect link count for %s: expected 2, got %d",
                        pid_filename, st.st_nlink)
                    raise OSError(EIO, strerror(EIO))

                self.lock_count = 1
                return
        finally:
            # Step 5: (Successful or not) -- unlink $filename.$pid
            log.debug("Unlinking pidlock file %s", pid_filename)
            try:
                unlink(pid_filename)
            except OSError as e:
                log.error("Failed to unlink pidlock file %s (ignored): %s",
                          pid_filename, e)

    def _lock_file(
            self,
            filename: str,
            timeout: Optional[Union[int, float]] = None,
            initial_sleep_time: float = 0.1,
            max_sleep_time: float = 2.0) -> None:
        """
        sdlock._lock_file(
            filename: str,
            timeout: Optional[Union[int, float]] = None,
            initial_sleep_time: float = 0.1,
            max_sleep_time: float = 2.0) -> None
        Acquire a shadow-utility lock on the specified shadow database file.
        If the lock is not available, keep trying until the specified timeout
        expires.

        If timeout is 0, this tries exactly once. If timeout is None or
        negative, this tries forever.

        For details on the lock algorithm, see the documentation for
        _lock_file_immediate.
        """
        sleep_time = initial_sleep_time
        if timeout is not None and timeout > 0:
            end_time = time() + timeout      # type: Optional[float]
        else:
            end_time = None

        while True:
            try:
                return self._lock_file_immediate(filename)
            except OSError as e:
                log.debug("Got OSError %s", e, exc_info=True)
                # If we failed for a reason other than waiting for the lock,
                # or we were told to just try once, exit here.
                if e.errno != EAGAIN or timeout == 0:
                    raise

                # If we have an upper limit on the time, make sure we haven't
                # exceeded it.
                if end_time is not None:
                    now = time()
                    if now > end_time:
                        raise

                # Don't re-poll too quickly; do an exponential backoff to
                # avoid DoSing the filesystem.
                sleep(sleep_time)
                sleep_time = min(1.5 * sleep_time, max_sleep_time)

    def _unlock_file(self, filename: str) -> None:
        """
        sdlock._unlock_file(filename: str) -> None
        Release the shadow-utility lock on the specified shadow database file.
        """
        if self.lock_count > 1:
            self.lock_count -= 1
            return

        pid = getpid()
        lock_file = f"{filename}.lock"

        try:
            log.debug("Validating that we own lock file %s", lock_file)
            fd = open(lock_file, "r+")
        except OSError as e:
            log.error("Unable to open lock file %s: %s", lock_file, e)
            raise

        lock_pid_str = fd.read()
        try:
            lock_pid = int(lock_pid_str)
        except ValueError as e:
            log.error("Lock file does not contain valid pid data: %r", lock_pid_str)
            raise OSError(EINVAL, strerror(EINVAL))

        if lock_pid != pid:
            log.error("Lock file is for pid %d; our pid is %d", lock_pid, pid)
            raise OSError(EINVAL, strerror(EINVAL))

        fd.close()
        log.debug("Unlinking %s", lock_file)
        unlink(lock_file)
        self.lock_count = 0

    def lock(self) -> None:
        """
        sdlock.lock() -> None
        Lock the shadow database files. This locks files in the same order
        that the shadow utilites do to prevent deadlocks: passwd, group,
        gshadow, and shadow.

        This method is not reentrant. Calling it a second time will deadlock.
        """
        rollback = []   # type: List[Callable]

        try:
            self._lckpwdf()
            rollback.append(self._ulckpwdf)

            for item, filename in self._lock_order:
                if self.items & item:
                    self._lock_file(filename, self.timeout)
                    rollback.append(partial(self._unlock_file, filename))
        except Exception as e: # pylint: disable=W0703
            log.error("Error while attempting database lock: %s", e)

            if rollback:
                log.info("Attempting rollback of existing locks")
            rollback.reverse()
            for func in rollback:
                log.debug("Rolling back: %s", func)

                try:
                    func()
                except Exception as e2: # pylint: disable=W0703
                    log.error(
                        "Rollback of %s failed (ignored): %s", func, e2,
                        exc_info=True)

            raise

    def unlock(self) -> None:
        """
        sdlock.unlock() -> None
        Unlock the shadow database files. This unlocks files in the same order
        that the shadow utilites do to prevent deadlocks: shadow, gshadow,
        group, and password.
        """
        for item, filename in reversed(self._lock_order):
            if self.items & item:
                try:
                    self._unlock_file(filename)
                except Exception as e: # pylint: disable=W0703
                    log.error("Failed to unlock %s (ignored): %s", filename, e)

        self._ulckpwdf()

    def __enter__(self) -> "ShadowDatabaseLock":
        self.lock()
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        self.unlock()


class ShadowWriter():
    """
    Context manager for writing new shadow files.
    """
    def __init__(self, filename: str, shadow_filename: str) -> None:
        """
        ShadowWriter(filename: str, shadow_filename: str) -> ShadowWriter
        Create a new ShadowWriter object to write to the specified filenames.
        """
        super(ShadowWriter, self).__init__()
        self.filename = filename
        self.shadow_filename = shadow_filename
        self.fd = None  # type: Optional[TextIO]
        self.sfd = None # type: Optional[TextIO]

    def __enter__(self) -> Tuple[TextIO, TextIO]:
        fd_fileno = sfd_fileno = -1
        try:
            # Follow our permission bits exactly -- don't use process permission
            # bits.
            orig_umask = umask(0)
            try:
                fd_fileno = os_open(
                    self.filename, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
                sfd_fileno = os_open(
                    self.shadow_filename, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
            finally:
                umask(orig_umask)
            lockf(fd_fileno, LOCK_EX)
            lockf(sfd_fileno, LOCK_EX)

            self.fd = open(fd_fileno, "w")
            self.sfd = open(sfd_fileno, "w")

            return (self.fd, self.sfd)
        except OSError:
            if sfd_fileno != -1:
                try:
                    os_close(sfd_fileno)
                except OSError:
                    pass

                try:
                    unlink(self.shadow_filename)
                except OSError:
                    pass

            if fd_fileno != -1:
                try:
                    os_close(fd_fileno)
                except OSError:
                    pass

                try:
                    unlink(self.filename)
                except OSError:
                    pass

            raise

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        try:
            if self.sfd is not None:
                self.sfd.flush()
                fsync(self.sfd.fileno())
                self.sfd.close()
        except OSError:
            pass

        try:
            if self.fd is not None:
                self.fd.flush()
                fsync(self.fd.fileno())
                self.fd.close()
        except OSError:
            pass

        if exc_type is not None:
            try:
                unlink(self.shadow_filename)
            except OSError:
                pass

            try:
                unlink(self.filename)
            except OSError:
                pass
