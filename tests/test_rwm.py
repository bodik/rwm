"""rwm tests"""

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock, patch

import rwm


def test_aws_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test aws command"""

    trwm = rwm.RWM({
        "rwm_s3_endpoint_url": motoserver,
        "rwm_s3_access_key": "dummy",
        "rwm_s3_secret_key": "dummy",
    })
    test_bucket = "testbucket"

    assert not trwm.storage_manager.bucket_exist(test_bucket)

    trwm.aws_cmd(["s3", "mb", f"s3://{test_bucket}"])
    assert trwm.storage_manager.bucket_exist(test_bucket)

    trwm.aws_cmd(["s3", "rb", f"s3://{test_bucket}"])
    assert not trwm.storage_manager.bucket_exist(test_bucket)


def test_restic_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test restic command"""

    trwm = rwm.RWM({
        "rwm_s3_endpoint_url": motoserver,
        "rwm_s3_access_key": "dummy",
        "rwm_s3_secret_key": "dummy",
        "rwm_restic_bucket": "restictest",
        "rwm_restic_password": "dummydummydummydummy",
    })

    assert trwm.restic_cmd(["init"]).returncode == 0
    proc = trwm.restic_cmd(["cat", "config"])
    assert "id" in json.loads(proc.stdout)


def _restic_list_snapshots(trwm):
    """test helper"""
    return json.loads(trwm.restic_cmd(["snapshots", "--json"]).stdout)


def _restic_list_snapshot_files(trwm, snapshot_id):
    """test helper"""
    snapshot_ls = [json.loads(x) for x in trwm.restic_cmd(["ls", snapshot_id, "--json"]).stdout.splitlines()]
    return [x["path"] for x in snapshot_ls if (x["struct_type"] == "node") and (x["type"] == "file")]


def test_backup(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test backup"""

    trwm = rwm.RWM({
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

    assert trwm.restic_cmd(["init"]).returncode == 0
    assert trwm.backup("testcfg") == 0

    snapshots = _restic_list_snapshots(trwm)
    assert len(snapshots) == 1
    snapshot_files = _restic_list_snapshot_files(trwm, snapshots[0]["id"])
    assert "/testdatadir/testdata1.txt" in snapshot_files


def test_backup_excludes(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test backu"""

    trwm = rwm.RWM({
        "rwm_s3_endpoint_url": motoserver,
        "rwm_s3_access_key": "dummy",
        "rwm_s3_secret_key": "dummy",
        "rwm_restic_bucket": "restictest",
        "rwm_restic_password": "dummydummydummydummy",
        "rwm_backups": {
            "testcfg": {
                "filesdirs": ["testdatadir/"],
                "excludes": ["testdatadir/proc/*", "*.ignored"],
                "extras": ["--tag", "dummytag"],
            }
        }
    })

    Path("testdatadir").mkdir()
    Path("testdatadir/etc").mkdir()
    Path("testdatadir/etc/config").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/etc/config3.ignored").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/etc/proc").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/proc").mkdir()
    Path("testdatadir/proc/to_be_also_excluded").write_text("dummydata", encoding="utf-8")
    Path("testdatadir/var").mkdir()
    Path("testdatadir/var/proc").mkdir()
    Path("testdatadir/var/proc/data").write_text("dummydata", encoding="utf-8")

    assert trwm.restic_cmd(["init"]).returncode == 0
    assert trwm.backup("testcfg") == 0

    snapshots = _restic_list_snapshots(trwm)
    assert len(snapshots) == 1
    snapshot_files = _restic_list_snapshot_files(trwm, snapshots[0]["id"])
    assert "/testdatadir/etc/config" in snapshot_files
    assert "/testdatadir/etc/config3.ignored" not in snapshot_files
    assert "/testdatadir/etc/proc" in snapshot_files
    assert "/testdatadir/proc" not in snapshot_files
    assert "/testdatadir/proc/to_be_also_excluded" not in snapshot_files
    assert "/testdatadir/var/proc/data" in snapshot_files


def test_backup_error_handling(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test backup command err cases"""

    rwm_conf = {
        "rwm_restic_bucket": "restictest",
        "rwm_backups": {
            "dummycfg": {"filesdirs": ["dummydir"]}
        }
    }
    mock_proc_ok = Mock(return_value=CompletedProcess(args='dummy', returncode=0))
    mock_proc_fail = Mock(return_value=CompletedProcess(args='dummy', returncode=2))
    mock_fail = Mock(return_value=11)

    with (
        patch.object(rwm.RWM, "_restic_backup", mock_proc_fail)
    ):
        assert rwm.RWM(rwm_conf).backup("dummycfg") == 1

    with (
        patch.object(rwm.RWM, "_restic_backup", mock_proc_ok),
        patch.object(rwm.RWM, "_restic_forget_prune", mock_proc_fail)
    ):
        assert rwm.RWM(rwm_conf).backup("dummycfg") == 1

    with (
        patch.object(rwm.RWM, "_restic_backup", mock_proc_ok),
        patch.object(rwm.RWM, "_restic_forget_prune", mock_proc_ok),
        patch.object(rwm.StorageManager, "storage_save_state", mock_fail)
    ):
        assert rwm.RWM(rwm_conf).backup("dummycfg") == 1


def test_backup_all(tmpworkdir: str):  # pylint: disable=unused-argument
    """test backup_all"""

    rwm_conf = {
        "rwm_restic_bucket": "restictest",
        "rwm_backups": {
            "dummycfg": {"filesdirs": ["dummydir"]}
        }
    }
    mock_proc_ok = Mock(return_value=CompletedProcess(args='dummy', returncode=0))
    mock_ok = Mock(return_value=0)

    with (
        patch.object(rwm.RWM, "_restic_backup", mock_proc_ok),
        patch.object(rwm.RWM, "_restic_forget_prune", mock_proc_ok),
        patch.object(rwm.StorageManager, "storage_save_state", mock_ok)
    ):
        assert rwm.RWM(rwm_conf).backup_all() == 0


def test_storage_create(tmpworkdir: str, microceph: str, radosuser_admin: rwm.StorageManager):  # pylint: disable=unused-argument
    """test_storage_create"""

    trwm = rwm.RWM({
        "rwm_s3_endpoint_url": radosuser_admin.url,
        "rwm_s3_access_key": radosuser_admin.access_key,
        "rwm_s3_secret_key": radosuser_admin.secret_key,
    })

    bucket_name = "testbuck"
    assert trwm.storage_create(bucket_name, "testnx") == 0
    assert trwm.storage_create("!invalid", "testnx") == 1
    assert trwm.storage_create(bucket_name, "") == 1


def test_storage_delete(tmpworkdir: str, microceph: str, radosuser_admin: rwm.StorageManager):  # pylint: disable=unused-argument
    """test_storage_delete"""

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
    assert len(trwm.storage_manager.list_objects(bucket_name)) == 0
    assert trwm.restic_cmd(["init"]).returncode == 0
    assert trwm.backup("testcfg") == 0
    assert len(trwm.storage_manager.list_objects(bucket_name)) != 0

    object_versions = radosuser_admin.s3.meta.client.list_object_versions(Bucket=bucket.name)
    assert len(object_versions["Versions"]) > 0
    assert len(object_versions["DeleteMarkers"]) > 0

    assert trwm.storage_delete(bucket_name) == 0
    assert not trwm.storage_manager.bucket_exist(bucket_name)

    assert trwm.storage_delete(bucket_name) == 1


def test_storage_check_policy(tmpworkdir: str):  # pylint: disable=unused-argument
    """test storage check policy"""

    trwm = rwm.RWM({})

    mock = Mock(return_value=False)
    with patch.object(rwm.StorageManager, "storage_check_policy", mock):
        assert trwm.storage_check_policy("dummy") == 1


def test_storage_list(tmpworkdir: str):  # pylint: disable=unused-argument
    """test storage_list"""

    trwm = rwm.RWM({})

    mock = Mock(return_value=[])
    with patch.object(rwm.StorageManager, "storage_list", mock):
        assert trwm.storage_list() == 0


def test_storage_drop_versions(tmpworkdir: str):  # pylint: disable=unused-argument
    """test storage drop versions"""

    trwm = rwm.RWM({})

    mock = Mock(return_value=0)
    with patch.object(rwm.StorageManager, "storage_drop_versions", mock):
        assert trwm.storage_drop_versions("dummy") == 0
