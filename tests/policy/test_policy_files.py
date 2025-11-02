# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

from pathlib import Path

import pytest

from d2.exceptions import ConfigurationError


def test_locate_policy_file_prefers_explicit(tmp_path):
    policy_path = tmp_path / "custom-policy.yaml"
    policy_path.write_text("metadata: {}\npolicies: []\n")

    module = __import__("d2.policy.files", fromlist=["locate_policy_file"])
    locate_policy_file = module.locate_policy_file

    assert locate_policy_file(policy_path=policy_path) == policy_path


def test_locate_policy_file_uses_default_candidates(tmp_path, monkeypatch):
    config_root = tmp_path / "config"
    policy_dir = config_root / "d2"
    policy_dir.mkdir(parents=True)
    default_file = policy_dir / "policy.yaml"
    default_file.write_text("metadata: {}\npolicies: []\n")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_root))

    module = __import__("d2.policy.files", fromlist=["locate_policy_file"])
    locate_policy_file = module.locate_policy_file

    assert locate_policy_file() == default_file


def test_locate_policy_file_rejects_multiple_files(tmp_path, monkeypatch):
    config_root = tmp_path / "config"
    policy_dir = config_root / "d2"
    policy_dir.mkdir(parents=True)
    (policy_dir / "policy.yaml").write_text("metadata: {}\npolicies: []\n")
    (policy_dir / "policy.json").write_text("{\"metadata\": {}, \"policies\": []}")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_root))

    module = __import__("d2.policy.files", fromlist=["locate_policy_file"])
    locate_policy_file = module.locate_policy_file

    with pytest.raises(ConfigurationError):
        locate_policy_file()


def test_iter_policy_candidates_respects_env_override(tmp_path, monkeypatch):
    override = tmp_path / "override.yml"
    override.write_text("metadata: {}\npolicies: []\n")
    monkeypatch.setenv("D2_POLICY_FILE", str(override))

    module = __import__("d2.policy.files", fromlist=["iter_policy_candidates"])
    iter_policy_candidates = module.iter_policy_candidates

    candidates = list(iter_policy_candidates(Path.cwd()))
    assert candidates[0] == override

