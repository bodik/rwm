#!/usr/bin/env python3
"""rwm postgresql backup helper"""

import os
import shutil
import subprocess
import sys
from argparse import ArgumentParser


BASE = "/var/lib/rwm"
BACKUPDIR = f"{BASE}/postgresql"
ARCHIVE = f"{BASE}/postgresql.tar.gz"
USERNAME = os.environ.get("PGUSER", "postgres")


def list_databases():
    """list postgresql databases"""

    cmd = [
        "su",
        "-c",
        'psql -q -A -t -c "SELECT datname FROM pg_database WHERE datistemplate = false;"',
        USERNAME,
    ]
    proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True)
    return proc.stdout.splitlines()


def backup_database(database):
    """backup single database"""

    cmd = ["su", "-c", f"pg_dump --clean --create {database}", USERNAME]
    try:
        with open(f"{BACKUPDIR}/{database}.sql", "wb") as fd:
            subprocess.run(cmd, stdout=fd, check=True)
    except subprocess.CalledProcessError:
        print(f"ERROR: cannot dump {database}", file=sys.stderr)
        return 1

    return 0


def backup_global_data():
    """backup global data"""

    try:
        cmd = ["su", "-c", "pg_dumpall --clean --globals-only", USERNAME]
        with open(f"{BACKUPDIR}/_globals.sql", "wb") as fd:
            subprocess.run(cmd, stdout=fd, check=True)
    except subprocess.CalledProcessError:
        print("ERROR: cannot dump database global data", file=sys.stderr)
        return 1

    return 0


def create():
    """dump database to archive"""

    databases = 0
    errors = 0

    shutil.rmtree(BACKUPDIR, ignore_errors=True)
    os.makedirs(BACKUPDIR, exist_ok=True)

    for db in list_databases():
        databases += 1
        errors += backup_database(db)

    errors += backup_global_data()

    subprocess.run(["tar", "czf", ARCHIVE, BACKUPDIR], check=True)
    shutil.rmtree(BACKUPDIR)
    print("archive created:")
    subprocess.run(["ls", "-l", ARCHIVE], check=True)

    if databases == 0:
        print("ERROR: no databases dumped", file=sys.stderr)
        errors += 1

    print(f"RESULT: errors={errors} databases={databases}")
    return errors


def cleanup():
    """cleanup backup process"""

    return os.unlink(ARCHIVE)


# pylint: disable=duplicate-code
def main():
    """main"""

    parser = ArgumentParser()
    parser.add_argument("command", choices=["create", "cleanup"])
    args = parser.parse_args()
    os.umask(0o077)

    if args.command == "create":
        return create()
    if args.command == "cleanup":
        return cleanup()
    return 1


if __name__ == "__main__":
    sys.exit(main())
