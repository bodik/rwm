#!/usr/bin/env python3
"""rwm mysql backup  helper"""

import os
import shutil
import subprocess
import sys
from argparse import ArgumentParser


BASE = "/var/lib/rwm"
BACKUPDIR = f"{BASE}/mysql"
ARCHIVE = f"{BASE}/mysql.tar.gz"

SKIP_DATABASES = [
    "information_schema",
    "performance_schema",
]

DUMP_EXTRAS = {
    "mysql.general_log": ["--skip-lock-tables"],
    "mysql.slow_log": ["--skip-lock-tables"],
    "mysql.transaction_registry": ["--skip-lock-tables"],
}


def list_databases():
    """list mysql databases"""

    proc = subprocess.run(["mysql", "-NBe", "show databases"], check=True, stdout=subprocess.PIPE, text=True)
    return proc.stdout.splitlines()


def list_tables(database):
    """list mysql database tables"""

    proc = subprocess.run(["mysql", "-NBe", "show tables", database], check=True, stdout=subprocess.PIPE, text=True)
    return proc.stdout.splitlines()


def backup_table(database, table):
    """backup single table"""

    cmd = (
        ["mysqldump", "--triggers", "--events", "--single-transaction"]
        + DUMP_EXTRAS.get(f"{database}.{table}", [])
        + [database, table]
    )
    try:
        with open(f"{BACKUPDIR}/{database},{table}.sql", "wb") as fd:
            subprocess.run(cmd, stdout=fd, check=True)
    except subprocess.CalledProcessError:
        print(f"ERROR: cannot dump {database}.{table}", file=sys.stderr)
        return 1

    return 0


def create():
    """dump database to archive"""

    databases = 0
    tables = 0
    errors = 0

    shutil.rmtree(BACKUPDIR, ignore_errors=True)
    os.makedirs(BACKUPDIR, exist_ok=True)

    for db in list_databases():
        if db in SKIP_DATABASES:
            continue
        databases += 1

        for table in list_tables(db):
            tables += 1
            errors += backup_table(db, table)

    subprocess.run(["tar", "czf", ARCHIVE, BACKUPDIR], check=True)
    shutil.rmtree(BACKUPDIR)
    print("archive created:")
    subprocess.run(["ls", "-l", ARCHIVE], check=True)

    if databases == 0:
        print("ERROR: no databases dumped", file=sys.stderr)
        errors += 1

    print(f"RESULT: errors={errors} databases={databases} tables={tables}")
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
