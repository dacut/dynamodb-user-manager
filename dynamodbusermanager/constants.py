"""
Constants and patterns used elsewhere.
"""
from datetime import date
from re import compile as re_compile

EPOCH = date(year=1970, month=1, day=1)

UID_MIN = 0
UID_MAX = 0xffffffff
GID_MIN = 0
GID_MAX = 0xffffffff

# Maximum length of a user/group name. /usr/include/bits/local_lim.h
NAME_MAX_LENGTH = 256

# User/group names are not well-defined, but we limit them to the POSIX 3.437
# rules to avoid compatibility problems.
# http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_437
# Which limit them to the portable filename character set:
# http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_282
# ASCII letters, digits, period, underscore, hyphen. The hyphen cannot be the
# first character of the username.
NAME_PATTERN = re_compile(r"^[a-zA-Z0-9_\.][-a-zA-Z0-9_\.]*$")

# There's no real limit on what can go into other fields except colons
# and newlines are forbidden. We also disallow vertical tabs, form feeds, and
# NULs for sanity, but otherwise allow the entire Unicode character set.
FIELD_PATTERN = re_compile(r"^[^:\n\v\f\0]*$")
FIELD_FIX = re_compile(r"[:\n\v\f\0]+")

NUMERIC_FIELD_PATTERN = re_compile("r[+-]?[0-9]*$")

# There's no defined limit on the GECOS field, but 512 is a common buffer
# size for the entire passwd line. Given that we allow 256 characters for
# the username, we limit the real name to 256 bytes.
REAL_NAME_MAX_LENGTH = 256

LOCK_PASSWD = 1
LOCK_GROUP = 2
LOCK_GSHADOW = 4
LOCK_SHADOW = 8
LOCK_ALL = (LOCK_PASSWD | LOCK_GROUP | LOCK_GSHADOW | LOCK_SHADOW)

PASSWD_FILE = "/etc/passwd"
GROUP_FILE = "/etc/group"
GSHADOW_FILE = "/etc/gshadow"
SHADOW_FILE = "/etc/shadow"
