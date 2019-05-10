"""
Routines for manipulating the password, group, and their associated shadow
files.
"""
from ctypes import CDLL, c_int, get_errno
from datetime import timedelta
from errno import EAGAIN, EEXIST, EIO, EINVAL, ESRCH
from fcntl import lockf, LOCK_EX
from functools import partial
from logging import getLogger
from os import (
    close as os_close, fsync, getpid, kill, link, open as os_open, rename,
    stat, strerror, unlink,
    O_CLOEXEC, O_CREAT, O_TRUNC, O_WRONLY
)
from os.path import exists
from time import sleep, time
from typing import Callable, Dict, List, Optional, TextIO, Tuple, Union
from .constants import (
    EPOCH, FIELD_FIX, FIELD_PATTERN, GID_MIN, GID_MAX, GROUP_FILE, GSHADOW_FILE,
    LOCK_ALL, LOCK_GROUP, LOCK_GSHADOW, LOCK_PASSWD, LOCK_SHADOW, NAME_PATTERN,
    NAME_MAX_LENGTH, NUMERIC_FIELD_PATTERN, PASSWD_FILE, SHADOW_FILE,
    UID_MIN, UID_MAX)
from .group import Group
from .user import User

# pylint: disable=C0103,C0325

log = getLogger(__name__)

class ShadowDatabase():
    """
    State manager and rules for manipulating the user and group database files:
    /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow.
    """

    def __init__(self) -> None:
        """
        ShadowDatabase() -> ShadowDatabase
        Create a new shadow database object, initialized from the shadow
        database files.
        """
        super(ShadowDatabase, self).__init__()
        self.users = {}     # type: Dict[str, User]
        self.groups = {}    # type: Dict[str, Group]
        self.reload()

    def reload(self) -> None:
        """
        shadow_db.reload() -> None
        Reload users and groups from the shadow database files.
        """
        self.users = {}     # type: Dict[str, User]
        self.groups = {}    # type: Dict[str, Group]

        with ShadowDatabaseLock():
            self._load_passwd_file()
            self._load_group_file()
            self._load_gshadow_file()
            self._load_shadow_file()

    def write(self) -> None:
        """
        shadow_db.write() -> None
        Write the users and groups to the shadow database files.
        """
        with ShadowDatabaseLock():
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

    def _load_passwd_file(self) -> None:
        """
        shadow_db._load_passwd_file() -> None
        Populate users and (some of) their attributes from the /etc/passwd
        file.

        This should be called with the database lock held.
        """
        with open(PASSWD_FILE, "r") as fd:
            for line in fd:
                line = line.rstrip()

                # Skip blank lines
                if not line:
                    continue

                parts = line.split(":")
                # Format should be 7 parts:
                # user_name:password:UID:GID:GECOS:directory:shell
                # password should be 'x' to force use of the shadow file.
                if len(parts) != 7:
                    log.warning("Invalid passwd entry: %s", line)
                    continue

                (user_name, password, uid_str, gid_str, real_name, home,
                 shell) = parts
                modified = False

                if not NAME_PATTERN.match(user_name):
                    log.error("Invalid passwd entry (bad user_name): %r", line)
                    continue

                if len(user_name) > NAME_MAX_LENGTH:
                    log.error(
                        "Invalid passwd entry (user_name too long): %r", line)
                    continue

                if password != 'x':
                    log.warning(
                        "Password for user %s is not set to the shadow file; "
                        "this will be forced when passwd is overwritten",
                        user_name)

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

                self.users[user_name] = User(
                    user_name=user_name, uid=uid, gid=gid, real_name=real_name,
                    home=home, shell=shell, modified=modified)

    def _load_group_file(self) -> None:
        """
        shadow_db._load_group_file() -> None
        Populate groups, user-group-memberships, and (some of) their
        attributes from the /etc/group file.

        This should be called with the database lock held.
        """
        with open(GROUP_FILE, "r") as fd:
            for line in fd:
                line = line.rstrip()

                # Skip blank lines
                if not line:
                    continue

                parts = line.split(":")
                # Format should be 4 parts:
                # group_name:password:GID:members
                # password should be 'x' to force use of the shadow file.
                if len(parts) != 4:
                    log.warning("Invalid group entry: %s", line)
                    continue

                group_name, password, gid_str, members_str = parts
                modified = False

                if not NAME_PATTERN.match(group_name):
                    log.error("Invalid group entry (bad group_name): %r", line)
                    continue

                if len(group_name) > NAME_MAX_LENGTH:
                    log.error(
                        "Invalid group entry (group_name too long): %r", line)
                    continue

                if password != 'x':
                    log.warning(
                        "Password for group %s is not set to the shadow file; "
                        "this will be forced when passwd is overwritten",
                        group_name)

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
                    members = []    # type: List[str]
                    modified = True
                else:
                    members = [
                        member.strip() for member in members_str.split(",")]
                    filtered_members = [
                        m for m in members if NAME_PATTERN.match(m)]
                    if filtered_members != members:
                        log.warning(
                            "Invalid group entry (bad members list): %r", line)
                        members = filtered_members

                self.groups[group_name] = Group(
                    group_name=group_name, gid=gid, members=members,
                    modified=modified)

    def _load_gshadow_file(self) -> None:
        """
        shadow_db._load_gshadow_file() -> None
        Populate group passwords, administrators, and re-validate members
        from the /etc/gshadow file.

        This should be called with the database lock held.
        """

        # WARNING: Never log a line from the gshadow file. An errant typo in
        # the file could cause the password to be logged. In the log statements
        # below, we always refer to line numbers instead.
        with open(GSHADOW_FILE, "r") as fd:
            for line_no, line in enumerate(fd):
                line_no += 1 # Print 1-based line numbers
                line = line.rstrip()

                # Skip blank lines
                if not line:
                    continue

                parts = line.split(":")
                # Format should be 4 parts:
                # group_name:encrypted_password:administrators:members
                if len(parts) != 4:
                    log.warning("Invalid gshadow entry (line %d)", line_no + 1)
                    continue

                group_name, password, administrators_str, members_str = parts

                group = self.groups.get(group_name)
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

    def _load_shadow_file(self) -> None:
        """
        shadow_db._load_shadow_file() -> None
        Populate user passwords and password policies from the /etc/shadow file.

        This should be called with the database lock held.
        """

        # WARNING: Never log a line from the shadow file. An errant typo in
        # the file could cause the password to be logged. In the log statements
        # below, we always refer to line numbers instead.
        with open(SHADOW_FILE, "r") as fd:
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
                    log.warning("Invalid shadow entry (line %d)", line_no + 1)
                    continue

                (user_name, password, last_password_change_date_str,
                 password_age_min_days_str, password_age_max_days_str,
                 password_warn_days_str, password_disable_days_str,
                 account_expire_date_str) = parts[:8]

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

                if not NUMERIC_FIELD_PATTERN.match(
                        last_password_change_date_str):
                    log.warning(
                        "%s:%d Bad character in last_password_change_date",
                        SHADOW_FILE, line_no)
                    user.last_password_change_date = None
                    user.modified = True
                else:
                    user.last_password_change_date = EPOCH + timedelta(
                        days=int(last_password_change_date_str))

                if not NUMERIC_FIELD_PATTERN.match(password_age_min_days_str):
                    log.warning(
                        "%s:%d Bad character in password_age_min_days",
                        SHADOW_FILE, line_no)
                    user.password_age_min_days = None
                    user.modified = True
                else:
                    user.password_age_min_days = int(password_age_min_days_str)

                if not NUMERIC_FIELD_PATTERN.match(password_age_max_days_str):
                    log.warning(
                        "%s:%d Bad character in password_age_max_days",
                        SHADOW_FILE, line_no)
                    user.password_age_max_days = None
                    user.modified = True
                else:
                    user.password_age_max_days = int(password_age_max_days_str)

                if not NUMERIC_FIELD_PATTERN.match(password_warn_days_str):
                    log.warning(
                        "%s:%d Bad character in password_warn_days",
                        SHADOW_FILE, line_no)
                    user.password_warn_days = None
                    user.modified = True
                else:
                    user.password_warn_days = int(password_warn_days_str)

                if not NUMERIC_FIELD_PATTERN.match(password_disable_days_str):
                    log.warning(
                        "%s:%d Bad character in password_disable_days",
                        SHADOW_FILE, line_no)
                    user.password_disable_days = None
                    user.modified = True
                else:
                    user.password_disable_days = int(password_disable_days_str)

                if not NUMERIC_FIELD_PATTERN.match(account_expire_date_str):
                    log.warning(
                        "%s:%d Bad character in account_expire_date",
                        SHADOW_FILE, line_no)
                    user.account_expire_date = None
                    user.modified = True
                else:
                    user.account_expire_date = EPOCH + timedelta(
                        days=int(account_expire_date_str))

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
        Write the specified user out to the passwd+ and shadow+ files.
        """
        user_name = user.user_name
        # passwd format is 7 parts:
        # user_name:password:UID:GID:GECOS:directory:shell
        # password is 'x' to force use of the shadow file.
        passwd.write(
            f"{user_name}:x:{user.uid}:{user.gid}:"
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
        expire_days_str = (
            str((user.account_expire_date - EPOCH).days)
            if user.account_expire_date is not None else "")

        shadow.write(
            f"{user.user_name}:{password}:{change_days_str}:{age_min_str}:"
            f"{age_max_str}:{warn_days_str}:{expire_days_str}:\n")

    @staticmethod
    def _write_group(group: Group, gfile: TextIO, gshadow: TextIO) -> None:
        """
        ShadowDatabase.write_group(
            group: Group, gfile: TextIO, gshadow: TextIO) -> None
        Write the specified group out to the group+ and gshadow+ files.
        """
        group_name = group.group_name
        administrators = ",".join(sorted(group.administrators))
        members = ",".join(sorted(group.members))

        # group format is 4 parts:
        # group_name:password:GID:members
        # password is 'x' to force use of the shadow file.
        gfile.write(f"{group_name}:x:{group.gid}:{members}\n")

        # gshadow format is 4 parts:
        # group_name:encrypted_password:administrators:members
        password_str = (
            group.password if group.password is not None else "!")

        gshadow.write(f"{group_name}:{password_str}:{administrators}:{members}\n")

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
            rename(new_filename, backup_filename)


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
                        raise OSError(EIO, strerror(EIO))

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
                        raise OSError(EAGAIN, strerror(EAGAIN))

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
            fd = open(filename, "r+")
        except OSError as e:
            log.error("Unable to open lock file %s: %s", lock_file, e)
            raise

        lock_pid_str = fd.read()
        try:
            lock_pid = int(lock_pid_str)
        except ValueError as e:
            log.error("Lock file does not contain valid pid data: %r", lock_pid)
            raise OSError(EINVAL, strerror(EINVAL))

        if lock_pid != pid:
            log.error("Lock file is for pid %d; our pid is %d", lock_pid, pid)
            raise OSError(EINVAL, strerror(EINVAL))

        fd.close()
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
            fd_fileno = os_open(
                self.filename, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
            sfd_fileno = os_open(
                self.shadow_filename, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
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
