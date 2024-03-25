"""pytest conftest"""

import os
import shutil
import socket
from tempfile import mkdtemp

import pytest
from xprocess import ProcessStarter


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
def tmpworkdir():
    """
    self cleaning temporary workdir
    pytest tmpdir fixture has issues https://github.com/pytest-dev/pytest/issues/1120
    """

    cwd = os.getcwd()
    tmpdir = mkdtemp(prefix='rwm_test-')
    os.chdir(tmpdir)
    yield tmpdir
    os.chdir(cwd)
    shutil.rmtree(tmpdir)
