"""rwm bucket policies tests"""

import boto3
import pytest


def test_microceph_defaults(
        tmpworkdir: str,
        microceph: str,
        rgwuser_test1: boto3.resource,
        rgwuser_test2: boto3.resource
):  # pylint: disable=unused-argument
    """test microceph defaults"""

    # bucket should not be present
    test_bucket = "testbuckx"
    assert test_bucket not in [x.name for x in rgwuser_test1.buckets.all()]

    # create bucket
    rgwuser_test1.create_bucket(Bucket=test_bucket)
    assert test_bucket in [x.name for x in rgwuser_test1.buckets.all()]

    # list from other identity, check it is not visible
    assert test_bucket not in [x.name for x in rgwuser_test2.buckets.all()]
    # but already exist
    with pytest.raises(rgwuser_test2.meta.client.exceptions.BucketAlreadyExists):
        rgwuser_test2.create_bucket(Bucket=test_bucket)

    # belongs to expected user
    assert rgwuser_test1.Bucket(test_bucket).Acl().owner["ID"] == "test1"
    # but unaccessible by other user
    with pytest.raises(rgwuser_test2.meta.client.exceptions.ClientError, match=r"AccessDenied"):
        assert rgwuser_test2.Bucket(test_bucket).Acl().owner["ID"] == "test1"
