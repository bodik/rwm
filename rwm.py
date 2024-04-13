#!/usr/bin/env python3
"""rwm, restic/s3 worm manager"""

import dataclasses
import gzip
import json
import logging
import os
import shlex
import subprocess
import sys
from argparse import ArgumentParser
from datetime import datetime
from io import BytesIO
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import BotoCoreError, ClientError
from tabulate import tabulate


__version__ = "1.0"
logger = logging.getLogger("rwm")
logger.setLevel(logging.INFO)


def is_sublist(needle, haystack):
    """Check if needle is a sublist of haystack using list slicing and equality comparison"""

    # If needle is empty, it's considered a sublist of any list
    if not needle:
        return True
    return any(haystack[i:i+len(needle)] == needle for i in range(len(haystack)))


def get_config(path):
    """load config"""

    if Path(path).exists():
        return yaml.safe_load(Path(path).read_text(encoding='utf-8')) or {}
    return {}


def run_command(*args, **kwargs):
    """output capturing command executor"""

    kwargs.update({
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
    })
    logger.debug("run_command: %s", shlex.join(args[0]))
    return subprocess.run(*args, **kwargs, check=False)


def wrap_output(process):
    """wraps command output and prints results"""

    if process.stdout:
        print(process.stdout)
    if process.stderr:
        print(process.stderr, file=sys.stderr)
    return process.returncode


def size_fmt(num):
    """print value formated with human readable units"""

    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB']:
        if abs(num) < 1024.0:
            return f'{num:0.1f} {unit}'
        num /= 1024.0
    return f'{num:0.1f} YiB'


@dataclasses.dataclass
class BackupResult:
    """backup results data container"""

    name: str
    returncode: int
    time_start: datetime
    time_end: datetime

    def to_dict(self):
        """dict serializer"""

        return {
            "ident": "RESULT",
            "name": self.name,
            "status": "OK" if self.returncode == 0 else "ERROR",
            "returncode": self.returncode,
            "backup_start": self.time_start.isoformat(),
            "backup_time": str(self.time_end-self.time_start),
        }


class RwmJSONEncoder(json.JSONEncoder):
    """json encoder"""

    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)  # pragma: nocover  ; no other type in processeda data


class StorageManager:
    """s3 policed bucket manager"""

    USER_BUCKET_POLICY_ACTIONS = [
        # backups
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        # policies
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:ListBucketVersions",
        "s3:GetBucketVersioning"
    ]

    def __init__(self, url, access_key, secret_key):
        self.url = url
        self.access_key = access_key
        self.secret_key = secret_key
        self.s3 = boto3.resource('s3', endpoint_url=url, aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key)

    def bucket_create(self, name):
        """aws s3 resource api stub"""
        # boto3 client and resource api are not completely aligned
        # s3.Bucket("xyz").create() returns dict instead of s3.Bucket object
        return self.s3.create_bucket(Bucket=name)

    def bucket_exist(self, name):
        """check if bucket exist"""
        return name in [x.name for x in self.list_buckets()]

    def bucket_owner(self, name):
        """aws s3 resource api stub"""
        return self.s3.Bucket(name).Acl().owner["ID"]

    def bucket_policy(self, name):
        """aws s3 resource api stub"""

        try:
            return json.loads(self.s3.Bucket(name).Policy().policy)
        except (ClientError, BotoCoreError) as exc:
            if "NoSuchBucketPolicy" not in str(exc):
                logger.error("rwm bucket_policy error, %s", (exc))
            return None

    def bucket_acl(self, name):
        """api stub"""
        acl = self.s3.Bucket(name).Acl()
        return {"owner": acl.owner, "grants": acl.grants}

    def list_buckets(self):
        """aws s3 resource api stub"""
        return list(self.s3.buckets.all())

    def list_objects(self, bucket_name):
        """aws s3 resource api stub"""
        return list(self.s3.Bucket(bucket_name).objects.all())

    def storage_create(self, bucket_name, target_username):
        """create policed bucket"""

        if not target_username:
            raise ValueError("must specify value for bucket user")

        bucket = self.bucket_create(bucket_name)
        tenant, admin_username = bucket.Acl().owner["ID"].split("$")

        # grants basic RW access to user in same tenant
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                # full access to admin
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": [f"arn:aws:iam::{tenant}:user/{admin_username}"]},
                    "Action": ["*"],
                    "Resource": [f"arn:aws:s3:::{bucket.name}", f"arn:aws:s3:::{bucket.name}/*"]
                },
                # limited access to user
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": [f"arn:aws:iam::{tenant}:user/{target_username}"]},
                    "Action": self.USER_BUCKET_POLICY_ACTIONS,
                    "Resource": [f"arn:aws:s3:::{bucket.name}", f"arn:aws:s3:::{bucket.name}/*"]
                }
            ]
        }
        bucket.Policy().put(Policy=json.dumps(bucket_policy))

        # enforces versioning
        bucket.Versioning().enable()

        return bucket

    def storage_delete(self, bucket_name):
        """storage delete"""

        bucket = self.s3.Bucket(bucket_name)
        bucket.objects.all().delete()
        bucket.object_versions.all().delete()
        bucket.delete()
        return 0

    @staticmethod
    def _policy_statements_admin(policy):
        """policy helper"""
        return list(filter(lambda stmt: stmt["Action"] == ["*"], policy["Statement"]))

    @staticmethod
    def _policy_statements_user(policy):
        """policy helper"""
        return list(filter(lambda stmt: stmt["Action"] != ["*"], policy["Statement"]))

    def storage_check_policy(self, name):
        """storage check bucket policy"""

        if not (policy := self.bucket_policy(name)):
            return False

        admin_statements = self._policy_statements_admin(policy)
        user_statements = self._policy_statements_user(policy)

        if (  # pylint: disable=too-many-boolean-expressions
            # only two expected statements should be present on a bucket
            len(policy["Statement"]) == 2
            and len(admin_statements) == 1
            and len(user_statements) == 1
            # with distinct identities for admin and user
            and admin_statements[0]["Principal"] != user_statements[0]["Principal"]
            # user should have only limited access
            and sorted(self.USER_BUCKET_POLICY_ACTIONS) == sorted(user_statements[0]["Action"])
            # the bucket should be versioned
            and self.s3.Bucket(name).Versioning().status == "Enabled"
        ):
            return True

        return False

    def storage_list(self):
        """storage list"""

        output = []
        for bucket in self.list_buckets():
            result = {}
            result["name"] = bucket.name
            result["policy"] = "OK" if self.storage_check_policy(bucket.name) else "FAILED"
            result["short_owner"] = self.bucket_owner(bucket.name).split("$")[-1]

            if result["policy"] == "OK":
                user_statement = self._policy_statements_user(self.bucket_policy(bucket.name))[0]
                result["target_user"] = user_statement["Principal"]["AWS"][0].split("/")[-1]
            else:
                result["target_user"] = None

            output.append(result)

        return output

    def storage_info(self, bucket_name):
        """grabs storage bucket detailed info"""

        result = {}
        result["name"] = bucket_name
        result["check_policy"] = "OK" if self.storage_check_policy(bucket_name) else "FAILED"
        result["owner"] = self.bucket_owner(bucket_name)
        result["acl"] = self.bucket_acl(bucket_name)
        result["policy"] = self.bucket_policy(bucket_name)
        result["objects"] = 0
        result["delete_markers"] = 0
        result["old_versions"] = 0
        result["size"] = 0
        result["old_size"] = 0
        result["saved_states"] = []

        paginator = self.s3.meta.client.get_paginator('list_object_versions')
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Versions", []):
                if obj["IsLatest"]:
                    result["objects"] += 1
                    result["size"] += obj["Size"]
                else:
                    result["old_versions"] += 1
                    result["old_size"] += obj["Size"]
            result["delete_markers"] += len(page.get("DeleteMarkers", []))

        for page in paginator.paginate(Bucket=bucket_name, Prefix="rwm"):
            result["saved_states"] += [x["Key"] for x in page.get("Versions", [])]

        return result

    def storage_drop_versions(self, bucket_name):
        """deletes all old versions and delete markers from storage to reclaim space"""

        # ? lock repo
        paginator = self.s3.meta.client.get_paginator('list_object_versions')

        # drop all active object versions
        objects = []
        for page in paginator.paginate(Bucket=bucket_name):
            for item in page.get("Versions", []):
                if not item["IsLatest"]:
                    objects.append([bucket_name, item["Key"], item["VersionId"]])
        for item in objects:
            self.s3.ObjectVersion(*item).delete()

        # drop all delete markers
        objects = []
        for page in paginator.paginate(Bucket=bucket_name):
            for item in page.get("DeleteMarkers", []):
                objects.append([bucket_name, item["Key"], item["VersionId"]])
        for item in objects:
            self.s3.ObjectVersion(*item).delete()

        return 0

    def _bucket_state(self, bucket_name):
        """dumps current bucket state into dict"""

        state = {
            "bucket_name": bucket_name,
            "bucket_acl": self.bucket_acl(bucket_name),
            "bucket_policy": self.bucket_policy(bucket_name),
            "time_start": datetime.now(),
            "time_end": None,
            "versions": [],
            "delete_markers": []
        }

        paginator = self.s3.meta.client.get_paginator('list_object_versions')
        for page in paginator.paginate(Bucket=bucket_name):
            state["versions"] += page.get("Versions", [])
            state["delete_markers"] += page.get("DeleteMarkers", [])
        state["time_end"] = datetime.now()

        return state

    def storage_save_state(self, bucket_name):
        """save storage state into itself"""

        # explicit error handling here, it's used during backup process
        try:
            bucket_state = self._bucket_state(bucket_name)
            now = datetime.now().astimezone().isoformat()
            self.s3.Bucket(bucket_name).upload_fileobj(
                BytesIO(gzip.compress(json.dumps(bucket_state, cls=RwmJSONEncoder).encode())),
                f"rwm/state_{now}.json.gz"
            )
        except (BotoCoreError, ClientError, TypeError) as exc:
            logger.exception(exc)
            return 1

        return 0

    def storage_restore_state(self, source_bucket_name, target_bucket_name, state_object_key):
        """create new bucket, copy data by selected state_file"""

        target_bucket = self.storage_create(target_bucket_name, "dummy")
        resp = self.s3.Bucket(source_bucket_name).Object(state_object_key).get()
        state = json.loads(gzip.decompress(resp['Body'].read()))

        for obj in state["versions"]:
            if obj["IsLatest"]:
                target_bucket.Object(obj["Key"]).copy({"Bucket": source_bucket_name, "Key": obj["Key"], "VersionId": obj["VersionId"]})

        return 0


class RWM:
    """rwm impl"""

    def __init__(self, config):
        self.config = config
        self.storage_manager = StorageManager(
            config.get("rwm_s3_endpoint_url"),
            config.get("rwm_s3_access_key"),
            config.get("rwm_s3_secret_key")
        )

    def aws_cmd(self, args) -> subprocess.CompletedProcess:
        """aws cli wrapper"""

        env = {
            "PATH": os.environ["PATH"],
            "AWS_METADATA_SERVICE_NUM_ATTEMPTS": "0",
            "AWS_ACCESS_KEY_ID": self.config["rwm_s3_access_key"],
            "AWS_SECRET_ACCESS_KEY": self.config["rwm_s3_secret_key"]
        }
        if is_sublist(["s3", "mb"], args):
            # region must be set and empty for awscil >=2.x and ?du? ceph s3
            env.update({"AWS_DEFAULT_REGION": ""})

        # aws cli does not have endpoint-url as env config option
        return run_command(["aws", "--endpoint-url", self.config["rwm_s3_endpoint_url"]] + args, env=env)

    def restic_cmd(self, args) -> subprocess.CompletedProcess:
        """restic command wrapper"""

        env = {
            "HOME": os.environ["HOME"],
            "PATH": os.environ["PATH"],
            "AWS_ACCESS_KEY_ID": self.config["rwm_s3_access_key"],
            "AWS_SECRET_ACCESS_KEY": self.config["rwm_s3_secret_key"],
            "RESTIC_PASSWORD": self.config["rwm_restic_password"],
            "RESTIC_REPOSITORY": f"s3:{self.config['rwm_s3_endpoint_url']}/{self.config['rwm_restic_bucket']}",
        }
        return run_command(["restic"] + args, env=env)

    def _restic_backup(self, name) -> subprocess.CompletedProcess:
        """runs restic backup by name"""

        logger.info(f"run restic_backup {name}")
        conf = self.config["rwm_backups"][name]
        excludes = []
        for item in conf.get("excludes", []):
            excludes += ["--exclude", item]
        extras = conf.get("extras", [])
        cmd_args = ["backup"] + extras + excludes + conf["filesdirs"]

        return self.restic_cmd(cmd_args)

    def _restic_forget_prune(self) -> subprocess.CompletedProcess:
        """runs forget prune"""

        logger.info("run restic_forget_prune")
        keeps = []
        for key, val in self.config.get("rwm_retention", {}).items():
            keeps += [f"--{key}", val]
        cmd_args = ["forget", "--prune"] + keeps

        return self.restic_cmd(cmd_args)

    def _runparts(self, parts_name, parts: list) -> int:
        """run all commands in parts in shell"""

        for part in parts:
            logger.info("rwm _runparts %s shell command, %s", parts_name, json.dumps(part))
            wrap_output(part_proc := run_command(part, shell=True))
            if part_proc.returncode != 0:
                logger.error("rwm _runparts failed")
                return part_proc.returncode

        return 0

    def _prerun(self, name) -> int:
        """prerun runparts stub"""
        return self._runparts("prerun", self.config["rwm_backups"][name].get("prerun", []))

    def _postrun(self, name) -> int:
        """postrun runparts stub"""
        return self._runparts("postrun", self.config["rwm_backups"][name].get("postrun", []))

    def backup(self, name) -> int:
        """backup command"""

        bucket_name = self.config["rwm_restic_bucket"]

        if not self.storage_manager.storage_check_policy(bucket_name):
            logger.warning("used bucket does not have expected policy")

        if self._prerun(name) != 0:
            logger.error("rwm _prerun failed")
            return 1

        wrap_output(backup_proc := self._restic_backup(name))
        if backup_proc.returncode != 0:
            logger.error("rwm _restic_backup failed")
            return 1

        if self._postrun(name) != 0:
            logger.error("rwm _postrun failed")
            return 1

        wrap_output(forget_proc := self._restic_forget_prune())
        if forget_proc.returncode != 0:
            logger.error("rwm _restic_forget_prune failed")
            return 1

        if self.storage_manager.storage_save_state(bucket_name) != 0:
            logger.error("rwm storage_save_state failed")
            return 1

        return 0

    def backup_all(self) -> int:
        """backup all command"""

        stats = []
        ret = 0

        for name in self.config["rwm_backups"].keys():
            time_start = datetime.now()
            wrap_output(backup_proc := self._restic_backup(name))
            time_end = datetime.now()
            ret |= backup_proc.returncode
            stats.append(BackupResult(name, backup_proc.returncode, time_start, time_end))

        if ret == 0:
            time_start = datetime.now()
            wrap_output(forget_proc := self._restic_forget_prune())
            time_end = datetime.now()
            ret |= forget_proc.returncode
            stats.append(BackupResult("_forget_prune", forget_proc.returncode, time_start, time_end))

        time_start = datetime.now()
        save_state_ret = self.storage_manager.storage_save_state(self.config["rwm_restic_bucket"])
        time_end = datetime.now()
        ret |= save_state_ret
        stats.append(BackupResult("_storage_save_state", save_state_ret, time_start, time_end))

        logger.info("rwm backup_all results")
        print(tabulate([item.to_dict() for item in stats], headers="keys", numalign="left"))
        return ret

    def storage_create(self, bucket_name, target_username) -> int:
        """storage create command"""

        self.storage_manager.storage_create(bucket_name, target_username)
        return 0

    def storage_delete(self, bucket_name) -> int:
        """storage delete command"""

        return self.storage_manager.storage_delete(bucket_name)

    def storage_list(self) -> int:
        """storage_list command"""

        print(tabulate(self.storage_manager.storage_list(), headers="keys", numalign="left"))
        return 0

    def storage_info(self, bucket_name) -> int:
        """storage_list command"""

        sinfo = self.storage_manager.storage_info(bucket_name)
        total_size = sinfo["size"] + sinfo["old_size"]

        print(f'Storage bucket:   {sinfo["name"]}')
        print("----------------------------------------")
        print(f'RWM policy check: {sinfo["check_policy"]}')
        print(f'Owner:            {sinfo["owner"]}')
        print(f'Objects:          {sinfo["objects"]}')
        print(f'Delete markers:   {sinfo["delete_markers"]}')
        print(f'Old versions:     {sinfo["old_versions"]}')
        print(f'Size:             {size_fmt(sinfo["size"])}')
        print(f'Old size:         {size_fmt(sinfo["old_size"])}')
        print(f'Total size:       {size_fmt(total_size)}')
        print("----------------------------------------")
        print("Bucket ACL:")
        print(json.dumps(sinfo["acl"], indent=2))
        print("----------------------------------------")
        print("Bucket policy:")
        print(json.dumps(sinfo["policy"], indent=2))
        print("----------------------------------------")
        print("RWM saved states:")
        print("\n".join(sorted(sinfo["saved_states"])))

        return 0

    def storage_drop_versions(self, bucket_name) -> int:
        """storage_drop_versions command"""

        return self.storage_manager.storage_drop_versions(bucket_name)

    def storage_restore_state(self, source_bucket, target_bucket, state_object_key) -> int:
        """storage restore state"""

        return self.storage_manager.storage_restore_state(source_bucket, target_bucket, state_object_key)


def configure_logging(debug):
    """configure logger"""

    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(name)s[%(process)d]: %(levelname)s %(message)s"
        )
    )
    logger.addHandler(log_handler)
    if debug:  # pragma: no cover  ; would reconfigure pylint environment
        logger.setLevel(logging.DEBUG)


def parse_arguments(argv):
    """parse arguments"""

    parser = ArgumentParser(description="restics3 worm manager")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--config", default="rwm.conf")

    subparsers = parser.add_subparsers(title="commands", dest="command", required=False)

    subparsers.add_parser("version", help="show version")

    aws_cmd_parser = subparsers.add_parser("aws", help="run aws cli")
    aws_cmd_parser.add_argument("cmd_args", nargs="*")
    restic_cmd_parser = subparsers.add_parser("restic", help="run restic")
    restic_cmd_parser.add_argument("cmd_args", nargs="*")

    backup_cmd_parser = subparsers.add_parser("backup", help="perform backup")
    backup_cmd_parser.add_argument("name", help="backup name")

    _ = subparsers.add_parser("backup_all", help="run all backups in config")

    storage_create_cmd_parser = subparsers.add_parser("storage_create", help="create policed storage bucked")
    storage_create_cmd_parser.add_argument("bucket_name", help="bucket name")
    storage_create_cmd_parser.add_argument("target_username", help="user to be granted limited RW access")

    storage_delete_cmd_parser = subparsers.add_parser("storage_delete", help="delete storage")
    storage_delete_cmd_parser.add_argument("bucket_name", help="bucket name")

    _ = subparsers.add_parser("storage_list", help="list storages")

    storage_info_cmd_parser = subparsers.add_parser("storage_info", help="show detailed storage info")
    storage_info_cmd_parser.add_argument("bucket_name", help="bucket name")

    storage_drop_versions_cmd_parser = subparsers.add_parser(
        "storage_drop_versions",
        help="reclaim storage space; drop any old object versions from bucket"
    )
    storage_drop_versions_cmd_parser.add_argument("bucket_name", help="bucket name")

    storage_restore_state_cmd_parser = subparsers.add_parser("storage_restore_state", help="restore bucketX stateX1 to bucketY")
    storage_restore_state_cmd_parser.add_argument("source_bucket", help="source_bucket")
    storage_restore_state_cmd_parser.add_argument("target_bucket", help="target_bucket; should not exist")
    storage_restore_state_cmd_parser.add_argument("state", help="state object key in source bucket")

    return parser.parse_args(argv)


def main(argv=None):  # pylint: disable=too-many-branches
    """main"""

    args = parse_arguments(argv)
    configure_logging(args.debug)

    config = {}
    if args.config:
        config.update(get_config(args.config))
    logger.debug("config, %s", config)
    # assert config ?
    rwmi = RWM(config)
    ret = -1

    if args.command == "version":
        print(__version__)
        ret = 0

    if args.command == "aws":
        ret = wrap_output(rwmi.aws_cmd(args.cmd_args))
    if args.command == "restic":
        ret = wrap_output(rwmi.restic_cmd(args.cmd_args))

    if args.command == "backup":
        ret = rwmi.backup(args.name)
        logger.info("rwm backup finished with %s (ret %d)", "success" if ret == 0 else "errors", ret)
    if args.command == "backup_all":
        ret = rwmi.backup_all()
        logger.info("rwm backup_all finished with %s (ret %d)", "success" if ret == 0 else "errors", ret)

    if args.command == "storage_create":
        ret = rwmi.storage_create(args.bucket_name, args.target_username)
    if args.command == "storage_delete":
        ret = rwmi.storage_delete(args.bucket_name)
    if args.command == "storage_list":
        ret = rwmi.storage_list()
    if args.command == "storage_info":
        ret = rwmi.storage_info(args.bucket_name)
    if args.command == "storage_drop_versions":
        ret = rwmi.storage_drop_versions(args.bucket_name)
    if args.command == "storage_restore_state":
        ret = rwmi.storage_restore_state(args.source_bucket, args.target_bucket, args.state)

    logger.debug("rwm finished with %s (ret %d)", "success" if ret == 0 else "errors", ret)
    return ret


if __name__ == "__main__":  # pragma: nocover
    sys.exit(main())
