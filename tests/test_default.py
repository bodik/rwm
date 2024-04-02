"""default tests"""

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock, patch

import boto3
import rwm
from rwm import is_sublist, main as rwm_main, rclone_obscure_password, RWM, wrap_output


def buckets_plain_list(full_response):
    """boto3 helper"""

    return [x["Name"] for x in full_response["Buckets"]]


def objects_plain_list(full_response):
    """boto3 helper"""

    return [x["Key"] for x in full_response["Contents"]]


def test_sublist():
    """test sublist"""

    assert is_sublist([], [])
    assert is_sublist([1, 2, 3], [5, 4, 1, 2, 3, 6, 7])
    assert not is_sublist([1, 3], [5, 4, 1, 2, 3, 6, 7])


def test_wrap_output():
    """test wrap_output"""

    assert wrap_output(CompletedProcess(args='dummy', returncode=11, stdout="dummy", stderr="dummy")) == 11


def test_main(tmpworkdir: str):  # pylint: disable=unused-argument
    """test main"""

    # optional and default config handling
    assert rwm_main(["version"]) == 0
    Path("rwm.conf").touch()
    assert rwm_main(["version"]) == 0

    # command branches
    mock = Mock(return_value=CompletedProcess(args='dummy', returncode=0))
    for item in ["aws", "rclone", "rclone_crypt", "restic", "backup"]:
        with patch.object(rwm.RWM, f"{item}_cmd", mock):
            assert rwm_main([item, "dummy"]) == 0

    mock = Mock(return_value=0)

    with patch.object(rwm.RWM, "backup_all_cmd", mock):
        assert rwm_main(["backup_all"]) == 0

    with patch.object(rwm.RWM, "storage_create_cmd", mock):
        assert rwm_main(["storage_create", "bucket", "user"]) == 0

    for item in ["storage_delete", "storage_check_policy"]:
        with patch.object(rwm.RWM, f"{item}_cmd", mock):
            assert rwm_main([item, "bucket"]) == 0


def test_aws_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test aws command"""

    trwm = RWM({
        "rwm_s3_endpoint_url": motoserver,
        "rwm_s3_access_key": "dummy",
        "rwm_s3_secret_key": "dummy",
    })
    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")
    test_bucket = "testbucket"

    assert test_bucket not in buckets_plain_list(s3.list_buckets())

    trwm.aws_cmd(["s3", "mb", f"s3://{test_bucket}"])
    assert test_bucket in buckets_plain_list(s3.list_buckets())

    trwm.aws_cmd(["s3", "rb", f"s3://{test_bucket}"])
    assert test_bucket not in buckets_plain_list(s3.list_buckets())


def test_rclone_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test rclone command"""

    trwm = RWM({
        "rwm_s3_endpoint_url": motoserver,
        "rwm_s3_access_key": "dummy",
        "rwm_s3_secret_key": "dummy",
    })
    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")

    test_bucket = "testbucket"
    test_file = "testfile.txt"
    Path(test_file).write_text('1234', encoding='utf-8')

    trwm.rclone_cmd(["mkdir", f"rwmbe:/{test_bucket}/"])
    trwm.rclone_cmd(["copy", test_file, f"rwmbe:/{test_bucket}/"])
    assert test_bucket in buckets_plain_list(s3.list_buckets())
    assert test_file in objects_plain_list(s3.list_objects_v2(Bucket=test_bucket))


def test_rclone_crypt_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test rclone with crypt overlay"""

    trwm = RWM({
        "rwm_s3_endpoint_url": motoserver,
        "rwm_s3_access_key": "dummy",
        "rwm_s3_secret_key": "dummy",
        "rwm_rclone_crypt_bucket": "cryptdata_test",
        "rwm_rclone_crypt_password": rclone_obscure_password("dummydummydummydummy"),
    })
    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")

    test_bucket = "testbucket"
    test_file = "testfile.txt"
    Path(test_file).write_text('1234', encoding='utf-8')

    trwm.rclone_crypt_cmd(["copy", test_file, f"rwmbe:/{test_bucket}/"])
    assert len(objects_plain_list(s3.list_objects_v2(Bucket=trwm.config["rwm_rclone_crypt_bucket"]))) == 1

    trwm.rclone_crypt_cmd(["delete", f"rwmbe:/{test_bucket}/{test_file}"])
    assert s3.list_objects_v2(Bucket=trwm.config["rwm_rclone_crypt_bucket"])["KeyCount"] == 0

    test_file1 = "testfile1.txt"
    Path(test_file1).write_text('4321', encoding='utf-8')
    trwm.rclone_crypt_cmd(["sync", ".", f"rwmbe:/{test_bucket}/"])
    assert s3.list_objects_v2(Bucket=trwm.config["rwm_rclone_crypt_bucket"])["KeyCount"] == 2

    Path(test_file1).unlink()
    trwm.rclone_crypt_cmd(["sync", ".", f"rwmbe:/{test_bucket}/"])
    assert s3.list_objects_v2(Bucket=trwm.config["rwm_rclone_crypt_bucket"])["KeyCount"] == 1


def test_restic_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test restic command"""

    trwm = RWM({
        "rwm_s3_endpoint_url": motoserver,
        "rwm_s3_access_key": "dummy",
        "rwm_s3_secret_key": "dummy",
        "rwm_restic_bucket": "restictest",
        "rwm_restic_password": "dummydummydummydummy",
    })

    assert trwm.restic_cmd(["init"]).returncode == 0
    proc = trwm.restic_cmd(["cat", "config"])
    assert "id" in json.loads(proc.stdout)


def _list_snapshots(trwm):
    """test helper"""

    return json.loads(trwm.restic_cmd(["snapshots", "--json"]).stdout)


def _list_files(trwm, snapshot_id):
    """test helper"""

    snapshot_ls = [
        json.loads(x)
        for x in
        trwm.restic_cmd(["ls", snapshot_id, "--json"]).stdout.splitlines()
    ]
    return [
        x["path"] for x in snapshot_ls
        if (x["struct_type"] == "node" and x["type"] == "file")
    ]


def test_backup_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test backup_cmd command"""

    trwm = RWM({
        "rwm_s3_endpoint_url": motoserver,
        "rwm_s3_access_key": "dummy",
        "rwm_s3_secret_key": "dummy",
        "rwm_restic_bucket": "restictest",
        "rwm_restic_password": "dummydummydummydummy",
        "rwm_backups": {
            "testcfg": {
                "filesdirs": ["testdatadir/"],
                "excludes": ["testfile_to_be_ignored"],
                "extras": ["--tag", "dummytag"],
            }
        },
        "rwm_retention": {
            "keep-daily": "1"
        }
    })

    Path("testdatadir").mkdir()
    Path("testdatadir/testdata1.txt").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/testfile_to_be_ignored").write_text("dummydata", encoding="utf-8")

    assert trwm.backup_cmd("testcfg").returncode == 0

    snapshots = _list_snapshots(trwm)
    assert len(snapshots) == 1
    snapshot_files = _list_files(trwm, snapshots[0]["id"])
    assert "/testdatadir/testdata1.txt" in snapshot_files


def test_backup_cmd_excludes(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test backup command"""

    trwm = RWM({
        "rwm_s3_endpoint_url": motoserver,
        "rwm_s3_access_key": "dummy",
        "rwm_s3_secret_key": "dummy",
        "rwm_restic_bucket": "restictest",
        "rwm_restic_password": "dummydummydummydummy",
        "rwm_backups": {
            "testcfg": {
                "filesdirs": ["testdatadir"],
                "excludes": ["proc/*", "*.ignored"],
                "extras": ["--tag", "dummytag"],
            }
        }
    })

    Path("testdatadir").mkdir()
    Path("testdatadir/etc").mkdir()
    Path("testdatadir/etc/config").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/etc/config2").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/etc/config3.ignored").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/etc/proc").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/etc/processor").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/proc").mkdir()
    Path("testdatadir/proc/to_be_also_excluded").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/processor").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/some_other_proc_essor").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/var").mkdir()
    Path("testdatadir/var/proc").mkdir()
    Path("testdatadir/var/proc/data").write_text("dummydata", encoding="utf-8")

    assert trwm.backup_cmd("testcfg").returncode == 0

    snapshots = _list_snapshots(trwm)
    assert len(snapshots) == 1
    snapshot_files = _list_files(trwm, snapshots[0]["id"])
    assert "/testdatadir/etc/config" in snapshot_files
    assert "/testdatadir/etc/config2" in snapshot_files
    assert "/testdatadir/etc/config3.ignored" not in snapshot_files
    assert "/testdatadir/etc/proc" in snapshot_files
    assert "/testdatadir/etc/processor" in snapshot_files
    assert "/testdatadir/proc" not in snapshot_files
    assert "/testdatadir/proc/to_be_also_excluded" not in snapshot_files
    assert "/testdatadir/processor" in snapshot_files
    assert "/testdatadir/some_other_proc_essor" in snapshot_files
    # following expected result does not work, because test config uses root-unanchored exclude path "proc/*"
    # assert "/testdatadir/var/proc/data" in snapshot_files


def test_backup_cmd_error_handling(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test backup command err cases"""

    rwm_conf = {
        "rwm_backups": {
            "dummycfg": {"filesdirs": ["dummydir"]}
        }
    }
    mock_ok = Mock(return_value=CompletedProcess(args='dummy', returncode=0))
    mock_fail = Mock(return_value=CompletedProcess(args='dummy', returncode=11))

    with patch.object(rwm.RWM, "restic_autoinit", mock_fail):
        assert RWM(rwm_conf).backup_cmd("dummycfg").returncode == 11

    with (
        patch.object(rwm.RWM, "restic_autoinit", mock_ok),
        patch.object(rwm.RWM, "restic_backup", mock_fail)
    ):
        assert RWM(rwm_conf).backup_cmd("dummycfg").returncode == 11

    with (
        patch.object(rwm.RWM, "restic_autoinit", mock_ok),
        patch.object(rwm.RWM, "restic_backup", mock_ok),
        patch.object(rwm.RWM, "restic_forget_prune", mock_fail)
    ):
        assert RWM(rwm_conf).backup_cmd("dummycfg").returncode == 11


def test_backup_all_cmd(tmpworkdir: str):  # pylint: disable=unused-argument
    """test backup command err cases"""

    rwm_conf = {
        "rwm_backups": {
            "dummycfg": {"filesdirs": ["dummydir"]}
        }
    }
    mock = Mock(return_value=CompletedProcess(args='dummy', returncode=0))

    with (
        patch.object(rwm.RWM, "restic_autoinit", mock),
        patch.object(rwm.RWM, "restic_backup", mock),
        patch.object(rwm.RWM, "restic_forget_prune", mock)
    ):
        assert RWM(rwm_conf).backup_all_cmd() == 0


def test_backup_all_cmd_error_handling(tmpworkdir: str):  # pylint: disable=unused-argument
    """test backup command err cases"""

    rwm_conf = {
        "rwm_backups": {
            "dummycfg": {"filesdirs": ["dummydir"]}
        }
    }
    mock_fail = Mock(return_value=CompletedProcess(args='dummy', returncode=11))

    with patch.object(rwm.RWM, "restic_autoinit", mock_fail):
        assert RWM(rwm_conf).backup_all_cmd() == 11


def test_storage_create_cmd(tmpworkdir: str, microceph: str, radosuser_admin: rwm.StorageManager):  # pylint: disable=unused-argument
    """test_storage_create_cmd"""

    trwm = rwm.RWM({
        "rwm_s3_endpoint_url": radosuser_admin.url,
        "rwm_s3_access_key": radosuser_admin.access_key,
        "rwm_s3_secret_key": radosuser_admin.secret_key,
    })

    bucket_name = "testbuck"
    assert trwm.storage_create_cmd(bucket_name, "testnx") == 0
    assert trwm.storage_create_cmd("!invalid", "testnx") == 1
    assert trwm.storage_create_cmd("", "testnx") == 1


def test_storage_delete_cmd(tmpworkdir: str, microceph: str, radosuser_admin: rwm.StorageManager):  # pylint: disable=unused-argument
    """test_storage_create_cmd"""

    trwm = rwm.RWM({
        "rwm_s3_endpoint_url": radosuser_admin.url,
        "rwm_s3_access_key": radosuser_admin.access_key,
        "rwm_s3_secret_key": radosuser_admin.secret_key,

        "rwm_restic_bucket": "testbuck",
        "rwm_restic_password": "dummydummydummydummy",
        "rwm_backups": {
            "testcfg": {"filesdirs": ["testdatadir/"]}
        }
    })

    bucket_name = trwm.config["rwm_restic_bucket"]
    Path("testdatadir").mkdir()
    Path("testdatadir/testdata1.txt").write_text("dummydata", encoding="utf-8")

    bucket = trwm.storage_manager.storage_create(bucket_name, "admin")
    assert trwm.storage_manager.bucket_exist(bucket_name)
    assert len(trwm.storage_manager.list_objects(bucket_name)) == 0

    assert trwm.backup_cmd("testcfg").returncode == 0
    assert len(trwm.storage_manager.list_objects(bucket_name)) != 0

    object_versions = radosuser_admin.s3.meta.client.list_object_versions(Bucket=bucket.name)
    assert len(object_versions["Versions"]) > 0
    assert len(object_versions["DeleteMarkers"]) > 0

    assert trwm.storage_delete_cmd(bucket_name) == 0
    assert not trwm.storage_manager.bucket_exist(bucket_name)
    assert trwm.storage_delete_cmd(bucket_name) == 1


def test_storage_check_policy_cmd(tmpworkdir: str, microceph: str, radosuser_admin: rwm.StorageManager):  # pylint: disable=unused-argument
    """test storage check policy command"""

    trwm = rwm.RWM({
        "rwm_s3_endpoint_url": radosuser_admin.url,
        "rwm_s3_access_key": radosuser_admin.access_key,
        "rwm_s3_secret_key": radosuser_admin.secret_key,
    })

    mock = Mock(return_value=False)
    with patch.object(rwm.StorageManager, "storage_check_policy", mock):
        assert trwm.storage_check_policy_cmd("dummy") == 1
