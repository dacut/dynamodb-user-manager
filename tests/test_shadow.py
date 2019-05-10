#!/usr/bin/env python3
from datetime import date
from os import getpid
from os.path import exists
from subprocess import run
from unittest import skip, TestCase
from dynamodbusermanager.shadow import ShadowDatabase, ShadowDatabaseLock
from dynamodbusermanager.group import Group
from dynamodbusermanager.user import User

EPOCH = date(1970, 1, 1)

class ShadowTest(TestCase):
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
        tu5000 = sdb.users["testuser5000"]  # type: User

        self.assertEqual(tu5000.name, "testuser5000")
        self.assertEqual(tu5000.real_name, "Test User 5000")
        self.assertEqual(tu5000.uid, 5000)
        self.assertEqual(tu5000.gid, 5000)
        self.assertEqual(tu5000.home, "/home/testuser5000")
        self.assertEqual(tu5000.shell, "/bin/true")
        self.assertEqual(tu5000.last_password_change_date, date(2001, 1, 1))
        self.assertEqual(tu5000.password_age_min_days, 10)
        self.assertEqual(tu5000.password_age_max_days, 2000)
        self.assertEqual(tu5000.password_disable_days, 50)
        self.assertEqual(tu5000.account_expire_date, date(2100, 1, 1))

    def test_save(self):
        sdb = ShadowDatabase()
        tg5001 = Group(name="testuser5001", gid=5001, members={"testuser5001"}, modified=True)
        tu5001 = User(name="testuser5001", uid=5001, gid=5001,
                      real_name="Test User 5001", home="/home/testuser5001",
                      shell="/bin/false")
        sdb.groups[tg5001.name] = tg5001
        sdb.users[tu5001.name] = tu5001
        sdb.groups["cdrom"].add_member("testuser5001")
        sdb.write()

        id = run(["/bin/id", "testuser5001"], capture_output=True,
                 encoding="utf-8")
        self.assertEqual(id.returncode, 0, "/bin/id testuser5001 failed")
        out = id.stdout.strip()
        uid_info, gid_info, groups_info = out.split()
        self.assertEqual(uid_info, "uid=5001(testuser5001)")
        self.assertEqual(gid_info, "gid=5001(testuser5001)")
        self.assertTrue(groups_info.startswith("groups="))
        groups_info = groups_info[7:]
        groups_info = set(groups_info.split(","))
        self.assertEqual(groups_info, {"5001(testuser5001)", "11(cdrom)"})