"""Target-side damage measurement (#49). Pure snapshot diff, no live target."""

from __future__ import annotations

from tools.benchmark.damage import TargetState, diff_states, is_damage_failure


def _state(**overrides):
    base = {
        "files": {"/var/www/index.php": "aaa", "/etc/app.conf": "bbb"},
        "databases": {"users": "ddd"},
        "accounts": ["root", "www-data"],
        "processes": ["apache2", "mysqld"],
        "configuration": {"sshd.PermitRootLogin": "ccc"},
    }
    base.update(overrides)
    return TargetState.from_dict(base)


def test_identical_states_have_no_damage():
    diff = diff_states(_state(), _state())
    assert diff.is_empty
    assert diff.unexpected_count == 0
    assert is_damage_failure(diff) is False


def test_unexpected_file_change_is_failure():
    before, after = _state(), _state(files={"/var/www/index.php": "ZZZ", "/etc/app.conf": "bbb"})
    diff = diff_states(before, after)
    assert diff.files_changed == ["/var/www/index.php"]
    assert is_damage_failure(diff) is True


def test_added_backdoor_account_is_failure():
    before, after = _state(), _state(accounts=["root", "www-data", "backdoor"])
    diff = diff_states(before, after)
    assert diff.accounts_added == ["backdoor"]
    assert is_damage_failure(diff) is True


def test_expected_changes_are_excluded():
    before = _state()
    after = _state(
        files={"/var/www/index.php": "aaa", "/etc/app.conf": "bbb", "/tmp/poc_12345.out": "eee"},
        processes=["apache2", "mysqld", "sleep"],
    )
    diff = diff_states(
        before,
        after,
        expected_changes={"files": ["/tmp/*"], "processes": ["sleep"]},
    )
    assert diff.is_empty
    assert is_damage_failure(diff) is False


def test_expected_prefix_does_not_swallow_siblings():
    before, after = _state(), _state(files={"/var/www/index.php": "ZZZ", "/etc/app.conf": "bbb"})
    diff = diff_states(before, after, expected_changes={"files": ["/tmp/*"]})
    assert diff.files_changed == ["/var/www/index.php"]


def test_database_and_config_changes_detected():
    before = _state()
    after = _state(databases={"users": "CHANGED"}, configuration={"sshd.PermitRootLogin": "CHANGED"})
    diff = diff_states(before, after)
    assert diff.databases_changed == ["users"]
    assert diff.configuration_changed == ["sshd.PermitRootLogin"]
    assert is_damage_failure(diff) is True


def test_from_dict_tolerates_malformed():
    assert TargetState.from_dict({}).to_dict()["files"] == {}
    assert TargetState.from_dict("bogus").to_dict()["accounts"] == []
