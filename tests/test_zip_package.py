import subprocess
import sys
import unittest
import zipfile
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]


class ZipPackageTests(unittest.TestCase):
    def test_build_zip_has_aapanel_root_and_excludes_prototype_and_cache(self):
        subprocess.run([sys.executable, "scripts/build_zip.py"], cwd=str(ROOT), check=True)
        manifest = json.loads((ROOT / "nginx_guard" / "info.json").read_text(encoding="utf-8"))
        archive = ROOT / "dist" / ("nginx_guard-%s.zip" % manifest["version"])
        self.assertTrue(archive.is_file())
        with zipfile.ZipFile(archive) as bundle:
            names = set(bundle.namelist())
        self.assertIn("nginx_guard/info.json", names)
        self.assertIn("nginx_guard/index.html", names)
        self.assertIn("nginx_guard/install.sh", names)
        self.assertIn("nginx_guard/icon.png", names)
        self.assertFalse(any("nginx_guard_ui_prototype.html" in name for name in names))
        self.assertFalse(any("systemd" in name or "reconcile" in name for name in names))
        self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in names))


if __name__ == "__main__":
    unittest.main()
