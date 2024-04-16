"""default tests"""

from subprocess import CompletedProcess
from unittest.mock import Mock, patch

import rwm
from rwm import is_sublist, main as rwm_main, size_fmt, wrap_output


def test_sublist():
    """test sublist"""

    assert is_sublist([], [])
    assert is_sublist([1, 2, 3], [5, 4, 1, 2, 3, 6, 7])
    assert not is_sublist([1, 3], [5, 4, 1, 2, 3, 6, 7])


def test_wrap_output():
    """test wrap_output"""

    assert wrap_output(CompletedProcess(args='dummy', returncode=11, stdout="dummy", stderr="dummy")) == 11


def test_size_fmt():
    """test sizefmt"""

    assert size_fmt(1024) == "1.0 KiB"
    assert size_fmt(10**25) == "8.3 YiB"


def _rwm_minconfig(args):
    return rwm_main(["--config", "tests/rwmtest.conf"] + args)


def test_main():
    """test main"""

    assert _rwm_minconfig(["version"]) == 0

    # command branches
    mock_proc = Mock(return_value=CompletedProcess(args='dummy', returncode=0))
    mock_ok = Mock(return_value=0)

    with patch.object(rwm.RWM, "aws_cmd", mock_proc):
        assert _rwm_minconfig(["aws", "dummy"]) == 0

    with patch.object(rwm.RWM, "restic_cmd", mock_proc):
        assert _rwm_minconfig(["restic", "dummy"]) == 0

    with patch.object(rwm.RWM, "backup", mock_ok):
        assert _rwm_minconfig(["backup", "dummy"]) == 0

    with patch.object(rwm.RWM, "backup", mock_ok):
        assert _rwm_minconfig(["backup-all"]) == 0

    with patch.object(rwm.RWM, "storage_create", mock_ok):
        assert _rwm_minconfig(["storage-create", "bucket", "user"]) == 0

    with patch.object(rwm.RWM, "storage_delete", mock_ok):
        assert _rwm_minconfig(["storage-delete", "bucket"]) == 0

    with patch.object(rwm.RWM, "storage_list", mock_ok):
        assert _rwm_minconfig(["storage-list"]) == 0

    with patch.object(rwm.RWM, "storage_info", mock_ok):
        assert _rwm_minconfig(["storage-info", "dummy"]) == 0

    with patch.object(rwm.RWM, "storage_drop_versions", mock_ok):
        assert _rwm_minconfig(["storage-drop-versions", "bucket"]) == 0

    with patch.object(rwm.RWM, "storage_restore_state", mock_ok):
        assert _rwm_minconfig(["storage-restore-state", "bucket", "bucket", "state"]) == 0

    # error handling
    assert rwm_main(["--config", "notexist", "version"]) == 1
