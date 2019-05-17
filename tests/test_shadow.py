#!/usr/bin/env python3
from datetime import date
from logging import getLogger, Formatter, DEBUG
from os import getpid
from os.path import exists
from subprocess import run
from unittest import skip, TestCase
from dynamodbusermanager.shadow import ShadowDatabase, ShadowDatabaseLock
from dynamodbusermanager.group import Group
from dynamodbusermanager.user import User

EPOCH = date(1970, 1, 1)

class ShadowTest(TestCase):
    def setUp(self):
        rootLogger = getLogger()
        fmt = Formatter(fmt="%(levelname)-8s %(name)s %(filename)s %(lineno)d: %(message)s")
        rootLogger.handlers[0].setFormatter(fmt)
        rootLogger.setLevel(DEBUG)

    def test_locking(self):
        pid = getpid()
        with ShadowDatabaseLock():
            pass

        self.assertFalse(exists("/etc/passwd.lock"), "/etc/passwd.lock exists")
        self.assertFalse(exists("/etc/group.lock"), "/etc/group.lock exists")
        self.assertFalse(exists("/etc/gshadow.lock"), "/etc/gshadow.lock exists")
        self.assertFalse(exists("/etc/shadow.lock"), "/etc/shadow.lock exists")
        self.assertFalse(exists(f"/etc/passwd.{pid}"), "/etc/passwd.pid exists")
        self.assertFalse(exists(f"/etc/group.{pid}"), "/etc/group.pid exists")
        self.assertFalse(exists(f"/etc/gshadow.{pid}"), "/etc/gshadow.pid exists")
        self.assertFalse(exists(f"/etc/shadow.{pid}"), "/etc/shadow.pid exists")

    def test_load(self):
        sdb = ShadowDatabase()
        tluser = sdb.users["testload"]  # type: User

        self.assertEqual(tluser.name, "testload")
        self.assertEqual(tluser.real_name, "Test Load User")
        self.assertEqual(tluser.uid, 5000)
        self.assertEqual(tluser.gid, 5000)
        self.assertEqual(tluser.home, "/home/testload")
        self.assertEqual(tluser.shell, "/bin/true")
        self.assertEqual(tluser.last_password_change_date, date(2001, 1, 1))
        self.assertEqual(tluser.password_age_min_days, 10)
        self.assertEqual(tluser.password_age_max_days, 2000)
        self.assertEqual(tluser.password_disable_days, 50)
        self.assertEqual(tluser.account_expire_date, date(2100, 1, 1))

    def test_save(self):
        sdb = ShadowDatabase()

        # Preconditions -- testsave1 doesn't exist; testsave2 exists.
        tsuser1 = sdb.users.get("testsave1") # type: User
        tsuser2 = sdb.users.get("testsave2") # type: User
        tsgroup1 = sdb.groups.get("testsave1") # type: Group
        tsgroup2 = sdb.groups.get("testsave2") # type: Group
        self.assertIsNone(tsuser1)
        self.assertIsNotNone(tsuser2)
        self.assertIsNone(tsgroup1)
        self.assertIsNotNone(tsgroup2)

        # Make sure our values agree with the test setup for testsave2
        self.assertEqual(tsuser2.uid, 5002)
        self.assertEqual(tsuser2.gid, 5002)
        self.assertEqual(tsuser2.home, "/home/testsave2")
        self.assertEqual(tsuser2.shell, "/bin/true")
        self.assertEqual(tsuser2.last_password_change_date, date(2001, 1, 1))
        self.assertEqual(tsuser2.password_age_min_days, 10)
        self.assertEqual(tsuser2.password_age_max_days, 2000)
        self.assertEqual(tsuser2.password_warn_days, 14)
        self.assertEqual(tsuser2.password_disable_days, 50)
        self.assertEqual(tsuser2.account_expire_date, date(2100, 1, 1))

        # Create testsave1
        tsgroup1 = Group(name="testsave1", gid=5001, members={"testsave1"}, modified=True)
        tsuser1 = User(name="testsave1", uid=5001, gid=5001,
                      real_name="Test User 5001", home="/home/testsave1",
                      shell="/bin/false")
        sdb.groups[tsgroup1.name] = tsgroup1
        sdb.users[tsuser1.name] = tsuser1
        sdb.groups["cdrom"].add_member("testsave1")
        sdb.write()

        # Forace a reload and make sure both users exists now.
        sdb.reload()
        tsuser1 = sdb.users.get("testsave1") # type: User
        tsuser2 = sdb.users.get("testsave2") # type: User
        tsgroup1 = sdb.groups.get("testsave1") # type: Group
        tsgroup2 = sdb.groups.get("testsave2") # type: Group
        self.assertIsNotNone(tsuser1)
        self.assertIsNotNone(tsuser2)
        self.assertIsNotNone(tsgroup1)
        self.assertIsNotNone(tsgroup2)

        # Make sure testsave1 agrees with the values we saved.
        self.assertEqual(tsuser1.uid, 5001)
        self.assertEqual(tsuser1.gid, 5001)
        self.assertEqual(tsuser1.home, "/home/testsave1")
        self.assertEqual(tsuser1.shell, "/bin/false")
        self.assertIsNone(tsuser1.last_password_change_date)
        self.assertIsNone(tsuser1.password_age_min_days)
        self.assertIsNone(tsuser1.password_age_max_days)
        self.assertIsNone(tsuser1.password_warn_days)
        self.assertIsNone(tsuser1.password_disable_days)
        self.assertIsNone(tsuser1.account_expire_date)

        # Make testsave2 hasn't changed from our view.
        self.assertEqual(tsuser2.uid, 5002)
        self.assertEqual(tsuser2.gid, 5002)
        self.assertEqual(tsuser2.home, "/home/testsave2")
        self.assertEqual(tsuser2.shell, "/bin/true")
        self.assertEqual(tsuser2.last_password_change_date, date(2001, 1, 1))
        self.assertEqual(tsuser2.password_age_min_days, 10)
        self.assertEqual(tsuser2.password_age_max_days, 2000)
        self.assertEqual(tsuser2.password_warn_days, 14)
        self.assertEqual(tsuser2.password_disable_days, 50)
        self.assertEqual(tsuser2.account_expire_date, date(2100, 1, 1))

        # Make sure we can see testsave1 outside of our database
        id = run(["/bin/id", "testsave1"], capture_output=True,
                 encoding="utf-8")
        self.assertEqual(id.returncode, 0, "/bin/id testsave1 failed")
        out = id.stdout.strip()
        uid_info, gid_info, groups_info = out.split()
        self.assertEqual(uid_info, "uid=5001(testsave1)")
        self.assertEqual(gid_info, "gid=5001(testsave1)")
        self.assertTrue(groups_info.startswith("groups="))
        groups_info = groups_info[7:]
        groups_info = set(groups_info.split(","))
        self.assertEqual(groups_info, {"5001(testsave1)", "11(cdrom)"})
