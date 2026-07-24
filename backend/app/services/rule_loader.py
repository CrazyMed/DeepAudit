"""本地 Semgrep 规则加载器。

从 rules/ 目录加载 YAML 规则文件，供 Semgrep 本地扫描使用（不联网）。
这是 Phase 1.5 的核心：让规则可本地化、可控、可自定义行内规范。
"""

import os
import logging
from pathlib import Path
from typing import List, Dict

import yaml

logger = logging.getLogger(__name__)

# 默认回退的在线规则集（无本地规则时使用）
DEFAULT_ONLINE_RULESET = "p/security-audit"


def load_local_rules(rules_dir: str) -> List[Dict]:
    """从目录加载本地 YAML 规则文件。

    Args:
        rules_dir: 规则目录路径

    Returns:
        规则列表，每项含 file_name 和 content。
        目录不存在或为空时返回空列表（不报错）。
    """
    dir_path = Path(rules_dir)
    if not dir_path.is_dir():
        return []

    # 支持 .yml 和 .yaml
    yaml_files = sorted(list(dir_path.glob("*.yml")) + list(dir_path.glob("*.yaml")))
    if not yaml_files:
        return []

    rules = []
    for yf in yaml_files:
        try:
            content = yf.read_text(encoding="utf-8")
            rules.append({
                "file_name": yf.name,
                "file_path": str(yf),
                "content": content,
            })
        except Exception as e:
            logger.warning(f"读取规则文件 {yf.name} 失败: {e}")
    return rules


def validate_semgrep_rule(yaml_content: str) -> bool:
    """校验 YAML 是否是合法的 Semgrep 规则。

    合法 Semgrep 规则必须：
    - 是有效 YAML
    - 顶层有 rules 键（列表）
    - 每条规则有 id

    Args:
        yaml_content: YAML 字符串

    Returns:
        合法返回 True，否则 False
    """
    if not yaml_content or not yaml_content.strip():
        return False

    try:
        data = yaml.safe_load(yaml_content)
    except yaml.YAMLError:
        return False

    if not isinstance(data, dict):
        return False

    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        return False

    # 每条规则必须有 id
    for rule in rules:
        if not isinstance(rule, dict):
            return False
        if not rule.get("id"):
            return False

    return True


def get_rule_config_argument(
    rules_dir: str,
    fallback: str = DEFAULT_ONLINE_RULESET,
) -> str:
    """根据本地规则情况，返回 Semgrep 的 --config 参数。

    优先用本地规则（不联网），无本地规则时回退到在线规则集。

    Args:
        rules_dir: 本地规则目录
        fallback: 无本地规则时的回退在线规则集

    Returns:
        传给 semgrep --config 的参数值
    """
    local_rules = load_local_rules(rules_dir)
    valid_rules = [r for r in local_rules if validate_semgrep_rule(r["content"])]

    if valid_rules:
        logger.info(f"使用本地规则: {len(valid_rules)} 个有效文件（{rules_dir}）")
        return rules_dir

    logger.info(f"无有效本地规则，回退到在线规则集: {fallback}")
    return fallback
