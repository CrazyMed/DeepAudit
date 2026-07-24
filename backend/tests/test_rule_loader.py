"""本地规则加载器的单元测试。

验证 load_local_rules 能从 rules/ 目录加载 Semgrep YAML 规则，
返回 Semgrep 可用的 --config 参数。

这是 Phase 1.5 的核心：让规则可本地化，不依赖在线规则集。
"""

import pytest
import os
import tempfile
from pathlib import Path

from app.services.rule_loader import (
    load_local_rules,
    validate_semgrep_rule,
    get_rule_config_argument,
)


class TestLoadLocalRules:
    """从目录加载本地 YAML 规则。"""

    def test_loads_yaml_files(self, tmp_path):
        """应加载目录下的 .yml 文件。"""
        (tmp_path / "sql-injection.yml").write_text(
            "rules:\n- id: test-sql\n  pattern: $X\n  message: test\n  languages: [python]",
            encoding="utf-8",
        )
        rules = load_local_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0]["file_name"] == "sql-injection.yml"

    def test_loads_yaml_and_yml_extensions(self, tmp_path):
        """同时支持 .yml 和 .yaml。"""
        (tmp_path / "a.yml").write_text("rules: []", encoding="utf-8")
        (tmp_path / "b.yaml").write_text("rules: []", encoding="utf-8")
        rules = load_local_rules(str(tmp_path))
        assert len(rules) == 2

    def test_ignores_non_yaml_files(self, tmp_path):
        """非 YAML 文件应被忽略。"""
        (tmp_path / "a.yml").write_text("rules: []", encoding="utf-8")
        (tmp_path / "readme.md").write_text("# Rules", encoding="utf-8")
        (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        rules = load_local_rules(str(tmp_path))
        assert len(rules) == 1

    def test_empty_directory(self, tmp_path):
        """空目录返回空列表。"""
        assert load_local_rules(str(tmp_path)) == []

    def test_nonexistent_directory(self, tmp_path):
        """不存在的目录返回空列表，不报错。"""
        assert load_local_rules(str(tmp_path / "nonexistent")) == []

    def test_returns_rule_content(self, tmp_path):
        """加载的规则应包含文件内容（供后续校验/合并）。"""
        content = "rules:\n- id: test\n  pattern: $X\n  message: test\n  languages: [python]"
        (tmp_path / "rule.yml").write_text(content, encoding="utf-8")
        rules = load_local_rules(str(tmp_path))
        assert rules[0]["content"] == content
        assert rules[0]["file_name"] == "rule.yml"


class TestValidateSemgrepRule:
    """校验 YAML 是否是合法的 Semgrep 规则。"""

    def test_valid_rule(self):
        yaml = """
rules:
  - id: test-sql-injection
    pattern: $DB.execute(...)
    message: Possible SQL injection
    languages: [python]
    severity: ERROR
"""
        assert validate_semgrep_rule(yaml) is True

    def test_invalid_no_rules_key(self):
        yaml = "something_else: value"
        assert validate_semgrep_rule(yaml) is False

    def test_invalid_empty(self):
        assert validate_semgrep_rule("") is False

    def test_invalid_not_yaml(self):
        assert validate_semgrep_rule("this is not yaml {{{") is False

    def test_invalid_no_id(self):
        yaml = """
rules:
  - pattern: $X
    message: test
    languages: [python]
"""
        assert validate_semgrep_rule(yaml) is False


class TestGetRuleConfigArgument:
    """根据本地规则情况，返回 Semgrep 的 --config 参数。"""

    def test_local_rules_exist_returns_path(self, tmp_path):
        """有本地规则时，返回目录路径（本地扫描，不联网）。"""
        (tmp_path / "rule.yml").write_text(
            "rules:\n- id: test\n  pattern: $X\n  message: t\n  languages: [python]",
            encoding="utf-8",
        )
        config = get_rule_config_argument(str(tmp_path))
        # 应返回本地路径，不是 p/xxx 在线规则
        assert config == str(tmp_path)
        assert "p/" not in config

    def test_no_local_rules_falls_back_to_online(self, tmp_path):
        """无本地规则时，回退到在线规则集（p/security-audit）。"""
        config = get_rule_config_argument(str(tmp_path))
        assert config == "p/security-audit"

    def test_no_local_rules_custom_fallback(self, tmp_path):
        """可指定回退的在线规则集。"""
        config = get_rule_config_argument(str(tmp_path), fallback="p/owasp-top-ten")
        assert config == "p/owasp-top-ten"
