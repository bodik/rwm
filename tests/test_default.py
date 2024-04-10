"""default tests"""

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock, patch

import rwm
from rwm import is_sublist, main as rwm_main, wrap_output


def test_sublist():
    """test sublist"""

    assert is_sublist([], [])
    assert is_sublist([1, 2, 3], [5, 4, 1, 2, 3, 6, 7])
    assert not is_sublist([1, 3], [5, 4, 1, 2, 3, 6, 7])


def test_wrap_output():
    """test wrap_output"""

    assert wrap_output(CompletedProcess(args='dummy', returncode=11, stdout="dummy", stderr="dummy")) == 11


def test_main(tmpworkdir: str):  # pylint: disable=unused-argument
    """test main"""

    # optional and default config handling
    assert rwm_main(["version"]) == 0
    Path("rwm.conf").touch()
    assert rwm_main(["version"]) == 0

    # command branches
    mock_proc = Mock(return_value=CompletedProcess(args='dummy', returncode=0))
    mock_ok = Mock(return_value=0)

    with patch.object(rwm.RWM, "aws_cmd", mock_proc):
        assert rwm_main(["aws", "dummy"]) == 0
    with patch.object(rwm.RWM, "restic_cmd", mock_proc):
        assert rwm_main(["restic", "dummy"]) == 0

    with patch.object(rwm.RWM, "backup", mock_proc):
        assert rwm_main(["backup", "dummy"]) == 0
    with patch.object(rwm.RWM, "backup_all", mock_ok):
        assert rwm_main(["backup_all"]) == 0

    with patch.object(rwm.RWM, "storage_create", mock_ok):
        assert rwm_main(["storage_create", "bucket", "user"]) == 0
    with patch.object(rwm.RWM, "storage_delete", mock_ok):
        assert rwm_main(["storage_delete", "bucket"]) == 0
    with patch.object(rwm.RWM, "storage_check_policy", mock_ok):
        assert rwm_main(["storage_check_policy", "bucket"]) == 0
    with patch.object(rwm.RWM, "storage_list", mock_ok):
        assert rwm_main(["storage_list"]) == 0
    with patch.object(rwm.RWM, "storage_drop_versions", mock_ok):
        assert rwm_main(["storage_drop_versions", "bucket"]) == 0
