"""safe_extract_zip 的单元测试。

验证修复：zip 没有外层目录时（文件直接在根），不应跳过文件。
"""

import zipfile
import os
import tempfile
import pytest

from app.services.zip_extractor import safe_extract_zip


class TestSafeExtractZip:
    """安全解压的各种情况。"""

    def test_flat_zip_no_common_dir(self, tmp_path):
        """zip 里文件直接在根（无外层目录），应正常解压。

        这是 bug 的场景：原代码把第一个文件名当目录前缀，导致全部跳过。
        """
        zip_path = tmp_path / "flat.zip"
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("app.py", "print('hello')")
            z.writestr("utils.py", "def helper(): pass")

        extract_dir = str(tmp_path / "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as z:
            safe_extract_zip(z, extract_dir)

        # 应解压出 2 个文件
        files = os.listdir(extract_dir)
        assert "app.py" in files
        assert "utils.py" in files

    def test_single_file_zip(self, tmp_path):
        """只有一个文件的 zip。"""
        zip_path = tmp_path / "single.zip"
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("main.py", "print(1)")

        extract_dir = str(tmp_path / "out")
        os.makedirs(extract_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as z:
            safe_extract_zip(z, extract_dir)

        assert "main.py" in os.listdir(extract_dir)

    def test_zip_with_common_dir(self, tmp_path):
        """zip 有外层目录（常见 GitHub 下载格式），应去掉前缀。"""
        zip_path = tmp_path / "nested.zip"
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("myproject/app.py", "print('hello')")
            z.writestr("myproject/lib/util.py", "x = 1")
            z.writestr("myproject/", "")  # 目录条目

        extract_dir = str(tmp_path / "out")
        os.makedirs(extract_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as z:
            safe_extract_zip(z, extract_dir)

        # 应去掉 myproject/ 前缀
        files = os.listdir(extract_dir)
        assert "app.py" in files
        assert os.path.exists(os.path.join(extract_dir, "lib", "util.py"))

    def test_empty_zip(self, tmp_path):
        """空 zip 不应报错。"""
        zip_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(zip_path, "w") as z:
            pass  # 空

        extract_dir = str(tmp_path / "out")
        os.makedirs(extract_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as z:
            safe_extract_zip(z, extract_dir)

        assert os.listdir(extract_dir) == []

    def test_subdirectory_files_no_prefix(self, tmp_path):
        """zip 里有子目录但无公共外层前缀。"""
        zip_path = tmp_path / "subdir.zip"
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("app.py", "print(1)")
            z.writestr("src/utils.py", "def f(): pass")

        extract_dir = str(tmp_path / "out")
        os.makedirs(extract_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as z:
            safe_extract_zip(z, extract_dir)

        assert "app.py" in os.listdir(extract_dir)
        assert os.path.exists(os.path.join(extract_dir, "src", "utils.py"))
