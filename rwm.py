#!/usr/bin/env python3
"""rwm, restic/s3 worm manager"""

import base64
import logging
import os
import subprocess
import sys
from argparse import ArgumentParser
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


__version__ = "0.1"
logger = logging.getLogger("rwm")
logger.setLevel(logging.DEBUG)


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
    logger.debug("run_command, %s", (args, kwargs))
    return subprocess.run(*args, **kwargs, check=False)


def wrap_output(process):
    """wraps command output and prints results"""

    if process.stdout:
        print(process.stdout)
    if process.stderr:
        print(process.stderr, file=sys.stderr)
    return process.returncode


def rclone_obscure_password(plaintext, iv=None):
    """rclone obscure password algorithm"""

    # https://github.com/rclone/rclone/blob/master/fs/config/obscure/obscure.go
    # https://github.com/maaaaz/rclonedeobscure
    # GTP translate to python cryptography

    secret_key = b"\x9c\x93\x5b\x48\x73\x0a\x55\x4d\x6b\xfd\x7c\x63\xc8\x86\xa9\x2b\xd3\x90\x19\x8e\xb8\x12\x8a\xfb\xf4\xde\x16\x2b\x8b\x95\xf6\x38"
    if not iv:
        iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(secret_key), modes.CTR(iv), backend=default_backend()).encryptor()
    data = iv + encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class RWM:
    """rwm impl"""

    def __init__(self, config):
        self.config = config

    def aws_cmd(self, args):
        """aws cli wrapper"""

        env = {
            "PATH": os.environ["PATH"],
            "AWS_METADATA_SERVICE_NUM_ATTEMPTS": "0",
            "AWS_ACCESS_KEY_ID": self.config["RWM_S3_ACCESS_KEY"],
            "AWS_SECRET_ACCESS_KEY": self.config["RWM_S3_SECRET_KEY"]
        }
        if is_sublist(["s3", "mb"], args):
            # region must be set and empty for awscil >=2.x and ?du? ceph s3
            env.update({"AWS_DEFAULT_REGION": ""})

        # aws cli does not have endpoint-url as env config option
        return run_command(["aws", "--endpoint-url", self.config["RWM_S3_ENDPOINT_URL"]] + args, env=env)

    def rclone_cmd(self, args):
        """rclone wrapper"""

        env = {
            "RCLONE_CONFIG": "",
            "RCLONE_CONFIG_RWMBE_TYPE": "s3",
            "RCLONE_CONFIG_RWMBE_ENDPOINT": self.config["RWM_S3_ENDPOINT_URL"],
            "RCLONE_CONFIG_RWMBE_ACCESS_KEY_ID": self.config["RWM_S3_ACCESS_KEY"],
            "RCLONE_CONFIG_RWMBE_SECRET_ACCESS_KEY": self.config["RWM_S3_SECRET_KEY"],
            "RCLONE_CONFIG_RWMBE_PROVIDER": "Ceph",
            "RCLONE_CONFIG_RWMBE_ENV_AUTH": "false",
            "RCLONE_CONFIG_RWMBE_REGION": "",
        }
        return run_command(["rclone"] + args, env=env)

    def rclone_crypt_cmd(self, args):
        """
        rclone crypt wrapper
        * https://rclone.org/docs/#config-file
        * https://rclone.org/crypt/
        """

        env = {
            "RCLONE_CONFIG": "",
            "RCLONE_CONFIG_RWMBE_TYPE": "crypt",
            "RCLONE_CONFIG_RWMBE_REMOTE": f"rwmbes3:/{self.config['RWM_RCLONE_CRYPT_BUCKET']}",
            "RCLONE_CONFIG_RWMBE_PASSWORD": rclone_obscure_password(self.config["RWM_RCLONE_CRYPT_PASSWORD"]),
            "RCLONE_CONFIG_RWMBE_PASSWORD2": rclone_obscure_password(self.config["RWM_RCLONE_CRYPT_PASSWORD"]),

            "RCLONE_CONFIG_RWMBES3_TYPE": "s3",
            "RCLONE_CONFIG_RWMBES3_ENDPOINT": self.config["RWM_S3_ENDPOINT_URL"],
            "RCLONE_CONFIG_RWMBES3_ACCESS_KEY_ID": self.config["RWM_S3_ACCESS_KEY"],
            "RCLONE_CONFIG_RWMBES3_SECRET_ACCESS_KEY": self.config["RWM_S3_SECRET_KEY"],
            "RCLONE_CONFIG_RWMBES3_PROVIDER": "Ceph",
            "RCLONE_CONFIG_RWMBES3_ENV_AUTH": "false",
            "RCLONE_CONFIG_RWMBES3_REGION": "",
        }
        return run_command(["rclone"] + args, env=env)

    def restic_cmd(self, args):
        """restic command wrapper"""

        env = {
            "HOME": os.environ["HOME"],
            "PATH": os.environ["PATH"],
            "AWS_ACCESS_KEY_ID": self.config["RWM_S3_ACCESS_KEY"],
            "AWS_SECRET_ACCESS_KEY": self.config["RWM_S3_SECRET_KEY"],
            "RESTIC_PASSWORD": self.config["RWM_RESTIC_PASSWORD"],
            "RESTIC_REPOSITORY": f"s3:{self.config['RWM_S3_ENDPOINT_URL']}/{self.config['RWM_RESTIC_BUCKET']}",
        }
        return run_command(["restic"] + args, env=env)


def main(argv=None):
    """main"""

    parser = ArgumentParser(description="restics3 worm manager")
    parser.add_argument("--config", default="rwm.conf")

    subparsers = parser.add_subparsers(title="commands", dest="command", required=False)
    aws_cmd_parser = subparsers.add_parser("aws", help="aws command")
    aws_cmd_parser.add_argument("cmd_args", nargs="*")
    rc_cmd_parser = subparsers.add_parser("rclone", help="rclone command")
    rc_cmd_parser.add_argument("cmd_args", nargs="*")
    rcc_cmd_parser = subparsers.add_parser("rclone_crypt", help="rclone command with crypt overlay")
    rcc_cmd_parser.add_argument("cmd_args", nargs="*")
    res_cmd_parser = subparsers.add_parser("restic", help="restic command")
    res_cmd_parser.add_argument("cmd_args", nargs="*")

    args = parser.parse_args(argv)

    config = {}
    if args.config:
        config.update(get_config(args.config))
    # assert config ?
    rwm = RWM(config)

    if args.command == "aws":
        return wrap_output(rwm.aws_cmd(args.cmd_args))
    if args.command == "rclone":
        return wrap_output(rwm.rclone_cmd(args.cmd_args))
    if args.command == "rclone_crypt":
        return wrap_output(rwm.rclone_crypt_cmd(args.cmd_args))
    if args.command == "restic":
        return wrap_output(rwm.restic_cmd(args.cmd_args))

    return 0


if __name__ == "__main__":  # pragma: nocover
    sys.exit(main())
