"""安全的 ZIP 解压工具。

从 agent_tasks.py 提取，修复了"无公共目录前缀时全部文件被跳过"的 bug。
"""

import os
import zipfile
import logging

logger = logging.getLogger(__name__)


def is_path_safe(base_dir: str, target_path: str) -> bool:
    """检查解压路径是否在目标目录内（防 Zip Slip）。"""
    base = os.path.abspath(base_dir)
    target = os.path.abspath(os.path.join(base_dir, target_path))
    return target.startswith(base + os.sep) or target == base


def _detect_common_prefix(file_list: list) -> str:
    """检测 zip 是否有公共目录前缀。

    只有当所有文件都共享同一个顶层目录时才返回该前缀（含尾部 /）。
    否则返回空串（无前缀）。

    例如：
    - ["myproject/app.py", "myproject/lib.py"] → "myproject/"
    - ["app.py", "lib.py"] → ""（无公共目录）
    - ["app.py"] → ""（单文件不算）
    """
    if not file_list or len(file_list) < 1:
        return ""

    # 取第一个文件的顶层路径
    parts = file_list[0].split("/", 1)
    if len(parts) < 2:
        # 第一个文件没有目录层级，说明无公共前缀
        return ""

    candidate = parts[0] + "/"

    # 所有文件都必须以这个前缀开头
    for f in file_list:
        if not f.startswith(candidate):
            return ""

    return candidate


def safe_extract_zip(zip_ref: zipfile.ZipFile, extract_dir: str) -> None:
    """安全解压 ZIP，防 Zip Slip，自动去公共目录前缀。

    修复：当 zip 无外层目录时，原代码误把第一个文件名当目录前缀，
    导致所有文件 startswith 检查失败，全部被跳过（解压出空目录）。

    Args:
        zip_ref: 打开的 ZipFile 对象
        extract_dir: 解压目标目录
    """
    file_list = zip_ref.namelist()
    if not file_list:
        return

    common_prefix = _detect_common_prefix(file_list)

    for file_name in file_list:
        # 去掉公共前缀（如有）
        target_path = file_name
        if common_prefix and file_name.startswith(common_prefix):
            target_path = file_name[len(common_prefix):]

        if not target_path:
            continue

        # 跳过目录条目
        if target_path.endswith("/"):
            os.makedirs(os.path.join(extract_dir, target_path), exist_ok=True)
            continue

        # 安全检查：防路径遍历
        if not is_path_safe(extract_dir, target_path):
            logger.warning(f"⚠️ 检测到路径遍历攻击: {file_name}")
            continue

        full_target = os.path.join(extract_dir, target_path)
        os.makedirs(os.path.dirname(full_target), exist_ok=True)
        with zip_ref.open(file_name) as src, open(full_target, "wb") as dst:
            dst.write(src.read())
