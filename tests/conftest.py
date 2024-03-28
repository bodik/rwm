"""pytest conftest"""

import json
import os
import shutil
import socket
import subprocess
from tempfile import mkdtemp

import boto3
import pytest
from xprocess import ProcessStarter


@pytest.fixture
def tmpworkdir():
    """
    self cleaning temporary workdir
    pytest tmpdir fixture has issues https://github.com/pytest-dev/pytest/issues/1120
    """

    cwd = os.getcwd()
    tmpdir = mkdtemp(prefix='rwmtest_')
    os.chdir(tmpdir)
    yield tmpdir
    os.chdir(cwd)
    shutil.rmtree(tmpdir)


@pytest.fixture
def motoserver(xprocess):
    """mocking s3 server fixture"""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    sock.close()

    class Starter(ProcessStarter):
        """xprocess stub"""
        pattern = "This is a development server"
        args = ["moto_server", "--port", str(port)]
        terminate_on_interrupt = True

    xprocess.ensure("motoserver", Starter)
    yield f"http://localhost:{port}"
    xprocess.getinfo("motoserver").terminate()


@pytest.fixture
def microceph():
    """microceph s3 server fixture"""

    yield "http://localhost:80"


def rgwuser(microceph_url, name):
    """rgwuser fixture"""

    subprocess.run(
        ["/snap/bin/radosgw-admin", "user", "rm", f"--uid={name}", "--purge-data"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False
    )
    proc = subprocess.run(
        ["/snap/bin/radosgw-admin", "user", "create", f"--uid={name}", f"--display-name=rwguser_{name}"],
        check=True,
        capture_output=True,
        text=True,
    )

    user = json.loads(proc.stdout)
    yield boto3.resource(
        's3',
        endpoint_url=microceph_url,
        aws_access_key_id=user["keys"][0]["access_key"],
        aws_secret_access_key=user["keys"][0]["secret_key"]
    )

    subprocess.run(["/snap/bin/radosgw-admin", "user", "rm", f"--uid={name}", "--purge-data"], check=True)


@pytest.fixture
def rgwuser_test1(microceph):  # pylint: disable=redefined-outer-name, unused-argument
    """rgwuser test1 stub"""

    yield from rgwuser(microceph, "test1")


@pytest.fixture
def rgwuser_test2(microceph):  # pylint: disable=redefined-outer-name, unused-argument
    """rgwuser test2 stub"""

    yield from rgwuser(microceph, "test2")
