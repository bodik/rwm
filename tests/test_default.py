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


def test_main():
    """test main"""

    def rwm_main_minconfig(args):
        return rwm_main(["--config", "tests/rwmtest.conf"] + args)

    assert rwm_main_minconfig(["version"]) == 0

    # command branches
    mock_proc = Mock(return_value=CompletedProcess(args='dummy', returncode=0))
    mock_ok = Mock(return_value=0)

    with patch.object(rwm.RWM, "aws_cmd", mock_proc):
        assert rwm_main_minconfig(["aws", "dummy"]) == 0
    with patch.object(rwm.RWM, "restic_cmd", mock_proc):
        assert rwm_main_minconfig(["restic", "dummy"]) == 0

    with patch.object(rwm.RWM, "backup", mock_ok):
        assert rwm_main_minconfig(["backup", "dummy"]) == 0
    with patch.object(rwm.RWM, "backup_all", mock_ok):
        assert rwm_main_minconfig(["backup_all"]) == 0

    with patch.object(rwm.RWM, "storage_create", mock_ok):
        assert rwm_main_minconfig(["storage_create", "bucket", "user"]) == 0
    with patch.object(rwm.RWM, "storage_delete", mock_ok):
        assert rwm_main_minconfig(["storage_delete", "bucket"]) == 0
    with patch.object(rwm.RWM, "storage_list", mock_ok):
        assert rwm_main_minconfig(["storage_list"]) == 0
    with patch.object(rwm.RWM, "storage_info", mock_ok):
        assert rwm_main_minconfig(["storage_info", "dummy"]) == 0
    with patch.object(rwm.RWM, "storage_drop_versions", mock_ok):
        assert rwm_main_minconfig(["storage_drop_versions", "bucket"]) == 0
    with patch.object(rwm.RWM, "storage_restore_state", mock_ok):
        assert rwm_main_minconfig(["storage_restore_state", "bucket", "bucket", "state"]) == 0
