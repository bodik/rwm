"""default tests"""

from pathlib import Path

import boto3
from rwm import is_sublist, main as rwm_main, rclone_obscure_password


def test_sublist():
    """test sublist"""

    assert is_sublist([], [])
    assert is_sublist([1, 2, 3], [5, 4, 1, 2, 3, 6, 7])
    assert not is_sublist([1, 3], [5, 4, 1, 2, 3, 6, 7])


def test_config(tmpworkdir: str):  # pylint: disable=unused-argument
    """test config handling"""

    Path("rwm.conf").touch()
    rwm_main([])


def buckets_plain_list(full_response):
    """boto3 helper"""

    return [x["Name"] for x in full_response["Buckets"]]


def objects_plain_list(full_response):
    """boto3 helper"""

    return [x["Key"] for x in full_response["Contents"]]


def test_aws(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test aws command"""

    rwm_conf = {
        "S3_ENDPOINT_URL": motoserver,
        "S3_ACCESS_KEY": "dummy",
        "S3_SECRET_KEY": "dummy",
    }
    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")
    test_bucket = "testbucket"

    assert test_bucket not in buckets_plain_list(s3.list_buckets())

    rwm_main(["aws", "s3", "mb", f"s3://{test_bucket}"], rwm_conf)
    assert test_bucket in buckets_plain_list(s3.list_buckets())

    rwm_main(["aws", "s3", "rb", f"s3://{test_bucket}"], rwm_conf)
    assert test_bucket not in buckets_plain_list(s3.list_buckets())


def test_rclone(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test rclone command"""

    rwm_conf = {
        "S3_ENDPOINT_URL": motoserver,
        "S3_ACCESS_KEY": "dummy",
        "S3_SECRET_KEY": "dummy",
    }
    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")

    test_bucket = "testbucket"
    test_file = "testfile.txt"
    Path(test_file).write_text('1234', encoding='utf-8')

    rwm_main(["rc", "mkdir", f"rwmbe:/{test_bucket}/"], rwm_conf)
    rwm_main(["rc", "copy", test_file, f"rwmbe:/{test_bucket}/"], rwm_conf)
    assert test_bucket in buckets_plain_list(s3.list_buckets())
    assert test_file in objects_plain_list(s3.list_objects_v2(Bucket=test_bucket))


def test_rclone_argscheck():
    """test rclone args checking"""

    assert rwm_main(["rc", "dummy"]) == 1


def test_rclone_crypt(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test rclone with crypt overlay"""

    rwm_conf = {
        "S3_ENDPOINT_URL": motoserver,
        "S3_ACCESS_KEY": "dummy",
        "S3_SECRET_KEY": "dummy",
        "RCC_CRYPT_BUCKET": "cryptdata_test",
        "RCC_CRYPT_PASSWORD": rclone_obscure_password("dummydummydummydummydummydummydummydummy"),
    }
    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")

    test_bucket = "testbucket"
    test_file = "testfile.txt"
    Path(test_file).write_text('1234', encoding='utf-8')

    rwm_main(["rcc", "copy", test_file, f"rwmbe:/{test_bucket}/"], rwm_conf)
    assert len(objects_plain_list(s3.list_objects_v2(Bucket=rwm_conf["RCC_CRYPT_BUCKET"]))) == 1

    rwm_main(["rcc", "delete", f"rwmbe:/{test_bucket}/{test_file}"], rwm_conf)
    assert s3.list_objects_v2(Bucket=rwm_conf["RCC_CRYPT_BUCKET"])["KeyCount"] == 0

    test_file1 = "testfile1.txt"
    Path(test_file1).write_text('4321', encoding='utf-8')
    rwm_main(["rcc", "sync", ".", f"rwmbe:/{test_bucket}/"], rwm_conf)
    assert s3.list_objects_v2(Bucket=rwm_conf["RCC_CRYPT_BUCKET"])["KeyCount"] == 2

    Path(test_file1).unlink()
    rwm_main(["rcc", "sync", ".", f"rwmbe:/{test_bucket}/"], rwm_conf)
    assert s3.list_objects_v2(Bucket=rwm_conf["RCC_CRYPT_BUCKET"])["KeyCount"] == 1


def test_rclone_crypt_argscheck():
    """test rclone crypt args checking"""

    assert rwm_main(["rcc", "dummy"]) == 1
