"""default tests"""

from pathlib import Path
from textwrap import dedent

import boto3
from rwm import is_sublist, main as rwm_main, rclone_obscure_password, RWM


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


def test_main(tmpworkdir: str):  # pylint: disable=unused-argument
    """test main"""

    assert rwm_main([]) == 0

    Path("rwm.conf").write_text(
        dedent("""
            S3_ENDPOINT_URL: "dummy"
            S3_ACCESS_KEY: "dummy"
            S3_SECRET_KEY: "dummy"

            RCC_CRYPT_BUCKET: "dummy-nasbackup-test1"
            RCC_CRYPT_PASSWORD: "dummy"

            RES_BUCKET: "dummy"
            RES_PASSWORD: "dummy"
        """),
        encoding="utf-8"
    )

    assert rwm_main([]) == 0

    assert rwm_main(["aws", "--", "--version"]) == 0
    assert rwm_main(["aws", "notexist"]) != 0

    assert rwm_main(["rclone", "version"]) == 0
    assert rwm_main(["rclone_crypt", "version"]) == 0

    assert rwm_main(["restic", "version"]) == 0


def test_aws_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test aws command"""

    rwm = RWM({
        "S3_ENDPOINT_URL": motoserver,
        "S3_ACCESS_KEY": "dummy",
        "S3_SECRET_KEY": "dummy",
    })
    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")
    test_bucket = "testbucket"

    assert test_bucket not in buckets_plain_list(s3.list_buckets())

    rwm.aws_cmd(["s3", "mb", f"s3://{test_bucket}"])
    assert test_bucket in buckets_plain_list(s3.list_buckets())

    rwm.aws_cmd(["s3", "rb", f"s3://{test_bucket}"])
    assert test_bucket not in buckets_plain_list(s3.list_buckets())


def test_rclone_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test rclone command"""

    rwm = RWM({
        "S3_ENDPOINT_URL": motoserver,
        "S3_ACCESS_KEY": "dummy",
        "S3_SECRET_KEY": "dummy",
    })
    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")

    test_bucket = "testbucket"
    test_file = "testfile.txt"
    Path(test_file).write_text('1234', encoding='utf-8')

    rwm.rclone_cmd(["mkdir", f"rwmbe:/{test_bucket}/"])
    rwm.rclone_cmd(["copy", test_file, f"rwmbe:/{test_bucket}/"])
    assert test_bucket in buckets_plain_list(s3.list_buckets())
    assert test_file in objects_plain_list(s3.list_objects_v2(Bucket=test_bucket))


def test_rclone_crypt_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
    """test rclone with crypt overlay"""

    rwm = RWM({
        "S3_ENDPOINT_URL": motoserver,
        "S3_ACCESS_KEY": "dummy",
        "S3_SECRET_KEY": "dummy",
        "RCC_CRYPT_BUCKET": "cryptdata_test",
        "RCC_CRYPT_PASSWORD": rclone_obscure_password("dummydummydummydummydummydummydummydummy"),
    })
    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")

    test_bucket = "testbucket"
    test_file = "testfile.txt"
    Path(test_file).write_text('1234', encoding='utf-8')

    rwm.rclone_crypt_cmd(["copy", test_file, f"rwmbe:/{test_bucket}/"])
    assert len(objects_plain_list(s3.list_objects_v2(Bucket=rwm.config["RCC_CRYPT_BUCKET"]))) == 1

    rwm.rclone_crypt_cmd(["delete", f"rwmbe:/{test_bucket}/{test_file}"])
    assert s3.list_objects_v2(Bucket=rwm.config["RCC_CRYPT_BUCKET"])["KeyCount"] == 0

    test_file1 = "testfile1.txt"
    Path(test_file1).write_text('4321', encoding='utf-8')
    rwm.rclone_crypt_cmd(["sync", ".", f"rwmbe:/{test_bucket}/"])
    assert s3.list_objects_v2(Bucket=rwm.config["RCC_CRYPT_BUCKET"])["KeyCount"] == 2

    Path(test_file1).unlink()
    rwm.rclone_crypt_cmd(["sync", ".", f"rwmbe:/{test_bucket}/"])
    assert s3.list_objects_v2(Bucket=rwm.config["RCC_CRYPT_BUCKET"])["KeyCount"] == 1


# def test_restic_cmd(tmpworkdir: str, motoserver: str):  # pylint: disable=unused-argument
#    """test rclone with crypt overlay"""
#
#    rwm_conf = {
#        "S3_ENDPOINT_URL": motoserver,
#        "S3_ACCESS_KEY": "dummy",
#        "S3_SECRET_KEY": "dummy",
#        "RES_BUCKET": "restic_test",
#        "RES_PASSWORD": "dummydummydummydummydummydummydummydummy",
#    }
#    s3 = boto3.client('s3', endpoint_url=motoserver, aws_access_key_id="dummy", aws_secret_access_key="dummy")
#
#    test_bucket = "testbucket"
#    test_file = "testfile.txt"
#    Path(test_file).write_text('1234', encoding='utf-8')
#
#    rwm_main(["res", "init"], rwm_conf)
#    assert len(objects_plain_list(s3.list_objects_v2(Bucket=rwm_conf["RES_BUCKET"]))) == 1


#
#    rwm_main(["rcc", "delete", f"rwmbe:/{test_bucket}/{test_file}"], rwm_conf)
#    assert s3.list_objects_v2(Bucket=rwm_conf["RCC_CRYPT_BUCKET"])["KeyCount"] == 0
#
#    test_file1 = "testfile1.txt"
#    Path(test_file1).write_text('4321', encoding='utf-8')
#    rwm_main(["rcc", "sync", ".", f"rwmbe:/{test_bucket}/"], rwm_conf)
#    assert s3.list_objects_v2(Bucket=rwm_conf["RCC_CRYPT_BUCKET"])["KeyCount"] == 2
#
#    Path(test_file1).unlink()
#    rwm_main(["rcc", "sync", ".", f"rwmbe:/{test_bucket}/"], rwm_conf)
#    assert s3.list_objects_v2(Bucket=rwm_conf["RCC_CRYPT_BUCKET"])["KeyCount"] == 1
