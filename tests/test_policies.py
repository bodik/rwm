"""rwm bucket policies tests"""

import json
from io import BytesIO
from pathlib import Path

import pytest

import rwm


def test_microceph_defaults(
        tmpworkdir: str,
        microceph: str,
        radosuser_test1: rwm.StorageManager,
        radosuser_test2: rwm.StorageManager
):  # pylint: disable=unused-argument
    """test microceph defaults"""

    bucket_name = "testbuckx"

    # create bucket, check owner and default policy
    assert bucket_name not in [x.name for x in radosuser_test1.list_buckets()]
    radosuser_test1.create_bucket(bucket_name)

    assert bucket_name in [x.name for x in radosuser_test1.list_buckets()]
    assert radosuser_test1.bucket_owner(bucket_name).endswith("$test1")
    assert not radosuser_test1.bucket_policy(bucket_name)

    # bucket must exist, but not be not visible nor accessible to others
    with pytest.raises(radosuser_test2.s3.meta.client.exceptions.BucketAlreadyExists):
        radosuser_test2.create_bucket(bucket_name)
    assert bucket_name not in [x.name for x in radosuser_test2.list_buckets()]
    with pytest.raises(radosuser_test2.s3.meta.client.exceptions.ClientError, match=r"AccessDenied"):
        assert radosuser_test2.list_objects(bucket_name)


def test_storage_policy(
        tmpworkdir: str,
        microceph: str,
        radosuser_admin: rwm.StorageManager,
        radosuser_test1: rwm.StorageManager,
        radosuser_test2: rwm.StorageManager
):  # pylint: disable=unused-argument
    """test manager created bucket policy"""

    bucket = radosuser_admin.storage_create("testbuckx", "test1")

    assert radosuser_admin.list_objects(bucket.name) == []
    assert radosuser_test1.list_objects(bucket.name) == []
    assert radosuser_admin.bucket_policy(bucket.name)
    assert radosuser_test1.bucket_policy(bucket.name)

    with pytest.raises(radosuser_test2.s3.meta.client.exceptions.ClientError, match=r"AccessDenied"):
        radosuser_test2.list_objects(bucket.name)

    assert bucket.Versioning().status == "Enabled"


def test_storage_versioning(
        tmpworkdir: str,
        microceph: str,
        radosuser_admin: rwm.StorageManager,
        radosuser_test1: rwm.StorageManager,
):  # pylint: disable=unused-argument
    """test manager created bucket policy"""

    bucket_name = "testbuckx"
    target_username = "test1"

    bucket = radosuser_admin.storage_create(bucket_name, target_username)
    assert bucket.Versioning().status == "Enabled"

    bucket = radosuser_test1.s3.Bucket(bucket_name)
    bucket.upload_fileobj(BytesIO(b"dummydata"), "dummykey")
    assert len(radosuser_test1.list_objects(bucket_name)) == 1
    bucket.Object("dummykey").delete()
    assert len(radosuser_test1.list_objects(bucket_name)) == 0

    # there should be object and it's delete marker
    object_versions = list(bucket.object_versions.all())
    assert len(object_versions) == 2

    # boto3 resource api does not have working marker attribute
    # https://github.com/boto/botocore/issues/674
    # https://github.com/boto/boto3/issues/1769
    # print(radosuser_test1.s3.meta.client.list_object_versions(Bucket=bucket_name))
    object_versions = radosuser_test1.s3.meta.client.list_object_versions(Bucket=bucket.name)
    assert len(object_versions["Versions"]) == 1
    assert len(object_versions["DeleteMarkers"]) == 1


def test_storage_backup(
    tmpworkdir: str,
    microceph: str,
    radosuser_admin: rwm.StorageManager,
    radosuser_test1: rwm.StorageManager,
):  # pylint: disable=unused-argument
    """test backup to manager created bucket with policy"""

    bucket_name = "rwmbackup-test1"
    target_username = "test1"

    radosuser_admin.storage_create(bucket_name, target_username)
    Path("testdir").mkdir()
    Path("testdir/testdata").write_text('dummy', encoding="utf-8")

    trwm = rwm.RWM({
        "rwm_s3_endpoint_url": radosuser_test1.url,
        "rwm_s3_access_key": radosuser_test1.access_key,
        "rwm_s3_secret_key": radosuser_test1.secret_key,
        "rwm_restic_bucket": bucket_name,
        "rwm_restic_password": "dummydummydummydummy",
        "rwm_backups": {
            "dummy": {"filesdirs": ["testdir"]}
        }
    })
    assert trwm.backup_cmd("dummy").returncode == 0

    assert radosuser_test1.list_objects(bucket_name)
    assert len(json.loads(trwm.restic_cmd(["snapshots", "--json"]).stdout)) == 1


def test_storage_check_policy(
    tmpworkdir: str,
    microceph: str,
    radosuser_admin: rwm.StorageManager,
    radosuser_test1: rwm.StorageManager
):  # pylint: disable=unused-argument
    """test backup to manager created bucket with policy"""

    bucket_name = "rwmbackup-test1"
    target_username = "test1"
    
    assert radosuser_admin.create_bucket(bucket_name)
    assert not radosuser_admin.storage_check_policy(bucket_name)
    radosuser_admin.storage_delete(bucket_name)

    radosuser_admin.storage_create(bucket_name, "test1")
    assert radosuser_test1.storage_check_policy(bucket_name)

    radosuser_admin.s3.Bucket(bucket_name).Versioning().suspend()
    assert not radosuser_test1.storage_check_policy(bucket_name)
