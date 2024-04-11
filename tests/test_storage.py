"""rwm storagemanager and bucket policing tests"""

import json
import os
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

    # create bucket
    assert not radosuser_test1.bucket_exist(bucket_name)
    radosuser_test1.bucket_create(bucket_name)
    assert len(radosuser_test1.list_buckets()) == 1
    assert radosuser_test1.list_objects(bucket_name) == []

    # assert basic raw bucket behavior
    assert radosuser_test1.bucket_exist(bucket_name)
    assert radosuser_test1.bucket_owner(bucket_name).endswith("$test1")
    assert not radosuser_test1.bucket_policy(bucket_name)

    # bucket must exist, but not be accessible to others
    with pytest.raises(radosuser_test2.s3.meta.client.exceptions.BucketAlreadyExists):
        radosuser_test2.bucket_create(bucket_name)
    with pytest.raises(radosuser_test2.s3.meta.client.exceptions.ClientError, match=r"AccessDenied"):
        assert radosuser_test2.list_objects(bucket_name)


def test_storage_create(
    tmpworkdir: str,
    microceph: str,
    radosuser_admin: rwm.StorageManager,
    radosuser_test1: rwm.StorageManager,
    radosuser_test2: rwm.StorageManager
):  # pylint: disable=unused-argument
    """test manager storage_create"""

    bucket = radosuser_admin.storage_create("testbuckx", "test1")

    assert radosuser_admin.list_objects(bucket.name) == []
    assert radosuser_admin.storage_check_policy(bucket.name)

    assert radosuser_test1.storage_check_policy(bucket.name)

    # storage must exist, but not be accessible to others
    with pytest.raises(radosuser_test2.s3.meta.client.exceptions.ClientError, match=r"AccessDenied"):
        radosuser_test2.list_objects(bucket.name)


def test_storage_delete(
        tmpworkdir: str,
        microceph: str,
        radosuser_admin: rwm.StorageManager,
        radosuser_test1: rwm.StorageManager,
):  # pylint: disable=unused-argument
    """test manager storage_delete"""

    bucket_name = "testbuckx"
    target_username = "test1"
    bucket = radosuser_admin.storage_create(bucket_name, target_username)

    bucket = radosuser_test1.s3.Bucket(bucket.name)
    bucket.upload_fileobj(BytesIO(b"dummydata"), "dummykey")
    assert len(radosuser_test1.list_objects(bucket.name)) == 1
    bucket.Object("dummykey").delete()
    assert len(radosuser_test1.list_objects(bucket.name)) == 0

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


def test_storage_check_policy(
    tmpworkdir: str,
    microceph: str,
    radosuser_admin: rwm.StorageManager,
    radosuser_test1: rwm.StorageManager
):  # pylint: disable=unused-argument
    """test manager storage_check_policy"""

    bucket_name = "rwmbackup-test1"
    target_username = "test1"

    assert radosuser_admin.bucket_create(bucket_name)
    assert not radosuser_admin.storage_check_policy(bucket_name)
    radosuser_admin.storage_delete(bucket_name)

    radosuser_admin.storage_create(bucket_name, target_username)
    assert radosuser_test1.storage_check_policy(bucket_name)

    radosuser_admin.s3.Bucket(bucket_name).Versioning().suspend()
    assert not radosuser_test1.storage_check_policy(bucket_name)


def test_storage_backup_usage(
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
    assert trwm.restic_cmd(["init"]).returncode == 0
    assert trwm.backup("dummy") == 0

    assert radosuser_test1.list_objects(bucket_name)
    assert len(json.loads(trwm.restic_cmd(["snapshots", "--json"]).stdout)) == 1

    with pytest.raises(radosuser_test1.s3.meta.client.exceptions.ClientError, match=r"AccessDenied"):
        assert radosuser_test1.storage_delete(bucket_name)


def test_storage_list(
    tmpworkdir: str,
    microceph: str,
    radosuser_admin: rwm.StorageManager,
):  # pylint: disable=unused-argument
    """test managet list storage"""

    bucket_name = "rwmbackup-test1"
    target_username = "test1"

    radosuser_admin.bucket_create("no-acl-dummy")
    bucket = radosuser_admin.storage_create(bucket_name, target_username)
    bucket.upload_fileobj(BytesIO(b"dummydata1"), "dummykey")
    assert len(radosuser_admin.storage_list(show_full=True, name_filter="a")) == 2


def test_storage_drop_versions(tmpworkdir: str, microceph: str, radosuser_admin: rwm.StorageManager):  # pylint: disable=unused-argument
    """test manager storage_drop_versions"""

    bucket_name = "testbuckx"
    target_username = "test1"
    bucket = radosuser_admin.storage_create(bucket_name, target_username)

    bucket.upload_fileobj(BytesIO(b"dummydata1"), "dummykey")
    bucket.upload_fileobj(BytesIO(b"dummydata2"), "dummykey")
    bucket.Object("dummykey").delete()
    bucket.upload_fileobj(BytesIO(b"dummydata3"), "dummykey")

    # boto3 resource api
    object_versions = list(bucket.object_versions.all())
    assert len(object_versions) == 4
    # boto3 client api
    object_versions = radosuser_admin.s3.meta.client.list_object_versions(Bucket=bucket.name)
    assert len(object_versions["Versions"]) == 3
    assert len(object_versions["DeleteMarkers"]) == 1

    assert radosuser_admin.storage_drop_versions(bucket.name) == 0

    object_versions = list(bucket.object_versions.all())
    assert len(object_versions) == 1


@pytest.mark.skipif('PYTEST_SLOW' not in os.environ, reason='slow on devnode, runs in CI')
def test_storage_drop_versions_many(tmpworkdir: str, microceph: str, radosuser_admin: rwm.StorageManager):  # pylint: disable=unused-argument
    """test manager storage_drop_versions"""

    bucket_name = "testbuckx"
    target_username = "test1"
    bucket = radosuser_admin.storage_create(bucket_name, target_username)

    bucket.upload_fileobj(BytesIO(b"dummydata0"), "dummykey")
    for idx in range(801):
        bucket.Object("dummykey").delete()
        bucket.upload_fileobj(BytesIO(f"dummydata{idx}".encode()), "dummykey")

    assert radosuser_admin.storage_drop_versions(bucket.name) == 0

    object_versions = list(bucket.object_versions.all())
    assert len(object_versions) == 1
